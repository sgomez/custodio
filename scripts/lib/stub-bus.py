"""A stub system bus for the tests of the install-time ProcessFD check (run as `python3 -I`).

usage: stub-bus.py SOCKET MODE READY_FILE
MODE: without  GetConnectionCredentials answers uid and pid but no ProcessFD (an old dbus-daemon)
      with     the same reply plus ProcessFD (a file descriptor passed with the message)
      error    GetConnectionCredentials answers an error whose text names ProcessFD
Speaks just enough of the D-Bus wire protocol (EXTERNAL auth, Hello, GetConnectionCredentials) for busctl and dbus-send. READY_FILE is
created once the socket listens. Stops on SIGTERM.
"""
import os
import socket
import struct
import sys
import threading

sock_path, mode, ready = sys.argv[1:4]
BUS = "org.freedesktop.DBus"


def pad(buf, n):
    buf.extend(b"\0" * (-len(buf) % n))


def put_str(buf, text):
    pad(buf, 4)
    raw = text.encode()
    buf.extend(struct.pack("<I", len(raw)) + raw + b"\0")


def field(buf, code, sig, value):
    pad(buf, 8)
    buf.append(code)
    buf.extend(bytes([len(sig)]) + sig.encode() + b"\0")
    if sig in ("s", "o"):
        put_str(buf, value)
    elif sig == "u":
        pad(buf, 4)
        buf.extend(struct.pack("<I", value))
    else:  # "g"
        buf.extend(bytes([len(value)]) + value.encode() + b"\0")


def message(kind, serial, reply_to, dest, sig, body, error=None, fds=0):
    fields = bytearray()
    if error:
        field(fields, 4, "s", error)
    field(fields, 5, "u", reply_to)
    field(fields, 6, "s", dest)
    field(fields, 7, "s", BUS)
    field(fields, 8, "g", sig)
    if fds:
        field(fields, 9, "u", fds)
    head = struct.pack("<BBBBII", ord("l"), kind, 1, 1, len(body), serial) + struct.pack("<I", len(fields)) + fields
    out = bytearray(head)
    pad(out, 8)
    return bytes(out) + bytes(body)


def credentials_body():
    body = bytearray()
    entries = [("UnixUserID", "u", os.getuid()), ("ProcessID", "u", os.getpid())]
    if mode == "with":
        entries.append(("ProcessFD", "h", 0))
    pad(body, 4)
    body.extend(b"\0\0\0\0")  # array length, patched below
    pad(body, 8)
    start = len(body)
    for key, sig, value in entries:
        pad(body, 8)
        put_str(body, key)
        body.extend(bytes([len(sig)]) + sig.encode() + b"\0")
        pad(body, 4)
        body.extend(struct.pack("<I", value))
    body[0:4] = struct.pack("<I", len(body) - start)
    return body


def member_of(header):
    pos, end = 16, 16 + struct.unpack_from("<I", header, 12)[0]
    found = {}
    while pos < end:
        pos += -pos % 8
        code, siglen = header[pos], header[pos + 1]
        sig = header[pos + 2 : pos + 2 + siglen].decode()
        pos += 3 + siglen
        if sig in ("s", "o"):
            pos += -pos % 4
            (size,) = struct.unpack_from("<I", header, pos)
            found[code] = header[pos + 4 : pos + 4 + size].decode()
            pos += 5 + size
        elif sig == "u":
            pos += -pos % 4 + 4
        else:  # "g"
            pos += 2 + header[pos]
    return found.get(3)


def read_more(conn, buf):
    chunk = conn.recv(4096)
    if not chunk:
        raise EOFError
    buf.extend(chunk)


def read_exact(conn, size, buf):
    while len(buf) < size:
        read_more(conn, buf)


def serve(conn):
    buf = bytearray()
    try:
        while True:
            while b"\r\n" not in buf:
                read_more(conn, buf)
            line, _, rest = bytes(buf).partition(b"\r\n")
            buf = bytearray(rest)
            line = line.lstrip(b"\0")
            if line == b"BEGIN":
                break
            if line == b"AUTH EXTERNAL":  # sd-bus sends the credentials in a second step
                conn.sendall(b"DATA\r\n")
            elif line.startswith((b"AUTH EXTERNAL", b"DATA")):
                conn.sendall(b"OK " + b"0" * 32 + b"\r\n")
            elif line == b"NEGOTIATE_UNIX_FD":
                conn.sendall(b"AGREE_UNIX_FD\r\n")
            else:
                conn.sendall(b"REJECTED EXTERNAL\r\n")
        serial = 0
        while True:
            read_exact(conn, 16, buf)
            fields_len = struct.unpack_from("<I", buf, 12)[0]
            body_len = struct.unpack_from("<I", buf, 4)[0]
            head = 16 + fields_len + (-(16 + fields_len) % 8)
            read_exact(conn, head + body_len, buf)
            their_serial = struct.unpack_from("<I", buf, 8)[0]
            member = member_of(bytes(buf[:head]))
            del buf[: head + body_len]
            serial += 1
            if member == "Hello":
                body = bytearray()
                put_str(body, ":1.1")
                conn.sendall(message(2, serial, their_serial, ":1.1", "s", body))
            elif member == "GetConnectionCredentials" and mode == "error":
                body = bytearray()
                put_str(body, "cannot read ProcessFD of the connection")
                conn.sendall(message(3, serial, their_serial, ":1.1", "s", body, error="org.freedesktop.DBus.Error.Failed"))
            elif member == "GetConnectionCredentials":
                msg = message(2, serial, their_serial, ":1.1", "a{sv}", credentials_body(), fds=1 if mode == "with" else 0)
                if mode == "with":
                    socket.send_fds(conn, [msg], [os.pidfd_open(os.getpid())])
                else:
                    conn.sendall(msg)
            else:
                body = bytearray()
                put_str(body, "unknown method")
                conn.sendall(message(3, serial, their_serial, ":1.1", "s", body, error="org.freedesktop.DBus.Error.UnknownMethod"))
    except (EOFError, OSError):
        pass
    finally:
        conn.close()


server = socket.socket(socket.AF_UNIX)
server.bind(sock_path)
server.listen(8)
open(ready, "w").close()
while True:
    client, _ = server.accept()
    threading.Thread(target=serve, args=(client,), daemon=True).start()
