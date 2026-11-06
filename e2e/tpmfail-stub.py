#!/usr/bin/python3 -I
"""A TPM that is not quite one (F139). Listens on the swtpm-style data socket PATH and on PATH.ctrl (world-writable, test only) in front of the real swtpm at UPSTREAM (and
UPSTREAM.ctrl). Every TPM command goes through untouched except, by MODE:
  fail-capability   TPM2_GetCapability (the capability query of the import) gets a response with TPM_RC_FAILURE (0x101) in swtpm's framing: a TPM that answers the connection and
                    then fails (tpmfail-tpm-error)
  lack-rsa          the TPM lacks RSA, as the filter of custodio-it does with alg=0x1 (tpm-lib.sh, mode lacking): TPM2_TestParms of an RSA key fails with TPM_RC_TYPE on parameter 1
                    and the algorithm list leaves RSA out (the credential-service cases need the choice encrypted-tpm; the filter program is mounted only in mode lacking)
Prints "ready" once both sockets listen. Usage: tpmfail-stub.py PATH UPSTREAM MODE"""
import os
import socket
import struct
import sys
import threading

RC_FAILURE = 0x101
CC_GET_CAPABILITY = 0x17A
CC_TEST_PARMS = 0x18A
ALG_RSA = 0x0001
RC_TYPE_PARAM1 = 0x08A | 0x40 | (1 << 8)


def listen(path):
    if os.path.exists(path):
        os.unlink(path)
    s = socket.socket(socket.AF_UNIX)
    s.bind(path)
    os.chmod(path, 0o666)
    s.listen(8)
    return s


def exactly(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def hang_up(sock):
    """shutdown first: close alone leaves the connection open while another thread of ours is blocked in recv on it (swtpm would keep serving a client that is gone)."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


def message(conn):
    header = exactly(conn, 10)
    size = struct.unpack(">I", header[2:6])[0]
    return header + (exactly(conn, size - 10) if size > 10 else b"")


def without_rsa(command, response):
    """The answer to GetCapability(TPM_CAP_ALGS) without the RSA entry (6 bytes each, after the 19-byte header, flag and count)."""
    if struct.unpack(">I", command[10:14])[0] != 0 or response[6:10] != b"\0\0\0\0" or len(response) < 19:
        return response
    kept = b"".join(e for e in (response[19:][i:i + 6] for i in range(0, len(response) - 19, 6)) if struct.unpack(">H", e[:2])[0] != ALG_RSA)
    out = response[:15] + struct.pack(">I", len(kept) // 6) + kept
    return out[:2] + struct.pack(">I", len(out)) + out[6:]


def make_serve(upstream, mode):
    def serve(conn):
        up = None
        try:
            while True:
                command = message(conn)
                code = struct.unpack(">I", command[6:10])[0]
                if mode == "fail-capability" and code == CC_GET_CAPABILITY:
                    conn.sendall(struct.pack(">HII", 0x8001, 10, RC_FAILURE))
                    continue
                if mode == "lack-rsa" and code == CC_TEST_PARMS and struct.unpack(">H", command[10:12])[0] == ALG_RSA:
                    conn.sendall(struct.pack(">HII", 0x8001, 10, RC_TYPE_PARAM1))
                    continue
                if up is None:
                    up = socket.socket(socket.AF_UNIX)
                    up.connect(upstream)
                up.sendall(command)
                response = message(up)
                conn.sendall(without_rsa(command, response) if mode == "lack-rsa" and code == CC_GET_CAPABILITY else response)
        except (EOFError, OSError):
            pass
        finally:
            hang_up(conn)
            if up is not None:
                hang_up(up)

    return serve


def accept_loop(sock, handler):
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def make_pump(upstream):
    """The control channel goes through untouched; the upstream is connected on the first bytes (swtpm serves one control client at a time)."""

    def pump(conn):
        up = None
        try:
            first = conn.recv(4096)
            if not first:
                return
            up = socket.socket(socket.AF_UNIX)
            up.connect(upstream + ".ctrl")
            up.sendall(first)
            threading.Thread(target=copy, args=(up, conn), daemon=True).start()
            copy(conn, up)
        except OSError:
            pass
        finally:
            hang_up(conn)
            if up is not None:
                hang_up(up)

    return pump


def copy(src, dst):
    try:
        while True:
            chunk = src.recv(4096)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass


def main():
    path, upstream, mode = sys.argv[1:4]
    if mode not in ("fail-capability", "lack-rsa"):
        sys.exit(f"tpmfail-stub: unknown mode {mode!r}")
    data, ctrl = listen(path), listen(path + ".ctrl")
    threading.Thread(target=accept_loop, args=(ctrl, make_pump(upstream)), daemon=True).start()
    print("ready", flush=True)
    accept_loop(data, make_serve(upstream, mode))


main()
