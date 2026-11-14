#!/usr/bin/python3 -I
"""The client of the snap-* cases (F179). It runs under `snap run --shell firefox` with the interpreter of the snap's own content (python3 in
gnome-platform; nothing else is installed there: no socat, no pkcs11-tool) and outside it as alice and as root, so it uses only the standard library.
  snap-client.py list MODULE                       prints `pid<TAB>N` then `token<TAB>LABEL` for each token (C_GetSlotList, C_GetTokenInfo)
  snap-client.py cert MODULE LABEL OUTFILE         writes the DER certificate of the token's key (C_GetAttributeValue CKA_VALUE)
  snap-client.py sign MODULE LABEL KIND IN OUT     one C_Sign over the digest file IN: KIND rsa (RSA-PKCS-PSS, SHA-256, MGF1 SHA-256, salt 32) or ec (ECDSA, r||s)
  snap-client.py call bus|p2p METHOD [UID]         one D-Bus method call without arguments to com.rfirma.Custodio1, from a hand-made client
                                                   (bus: the system bus, EXTERNAL as UID; p2p: /run/snap.firefox/custodio.sock, ANONYMOUS, as the module does).
                                                   Prints `ok` or `error NAME [text]`; the member is looked up before any argument, so an absent method is UnknownMethod.
Every command prints `pid<TAB>N` first (os.getpid()): /proc/self/attr/current cannot be read in the snap, and the pid is how the harness compares the
polkit subject and CUSTODIO_PID with the process it started. Exit 0 on success, 1 with the reason on stderr otherwise."""
import ctypes as C
import os
import socket
import struct
import sys

NAME = "com.rfirma.Custodio1"
PATH = "/com/rfirma/Custodio1"
SOCK = "/run/snap.firefox/custodio.sock"
BUS = "/run/dbus/system_bus_socket"
UL = C.c_ulong
P = C.c_void_p


# ---- D-Bus by hand
def _align(n, k):
    return (n + k - 1) // k * k


def _field(buf, code, sig, val):
    buf += b"\0" * (_align(len(buf), 8) - len(buf))
    buf += bytes([code, 1, ord(sig), 0])
    if sig == "g":
        v = val.encode()
        buf += bytes([len(v)]) + v + b"\0"
    elif sig == "u":
        buf += struct.pack("<I", val)
    else:
        v = val.encode()
        buf += struct.pack("<I", len(v)) + v + b"\0"
    return buf


def message(kind, serial, fields):
    """kind 1 call, 2 return, 3 error; fields: [(code, sig, value)]."""
    buf = b""
    for code, sig, val in fields:
        buf = _field(buf, code, sig, val)
    head = b"l" + bytes([kind, 0, 1]) + struct.pack("<III", 0, serial, len(buf)) + buf
    return head + b"\0" * (_align(len(head), 8) - len(head))


def parse_fields(buf):
    out, pos = {}, 0
    while pos < len(buf):
        pos = _align(pos, 8)
        if pos >= len(buf):
            break
        code, slen = buf[pos], buf[pos + 1]
        sig = buf[pos + 2:pos + 2 + slen]
        pos += slen + 3
        if sig in (b"s", b"o"):
            pos = _align(pos, 4)
            n = struct.unpack_from("<I", buf, pos)[0]
            out[code] = buf[pos + 4:pos + 4 + n].decode(errors="replace")
            pos += n + 5
        elif sig == b"u":
            pos = _align(pos, 4)
            out[code] = struct.unpack_from("<I", buf, pos)[0]
            pos += 4
        elif sig == b"g":
            out[code] = buf[pos + 1:pos + 1 + buf[pos]].decode(errors="replace")
            pos += buf[pos] + 2
        else:
            break
    return out


def _recv(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise ConnectionError("the peer closed the connection")
        data += chunk
    return data


def read_message(s):
    h = _recv(s, 16)
    body, _serial, flen = struct.unpack("<III", h[4:16])
    rest = _recv(s, _align(flen, 8) + body)
    return h[1], parse_fields(rest[:flen]), rest[_align(flen, 8):]


def _auth(s, line):
    s.sendall(b"\0" + line + b"\r\n")
    got = b""
    while not got.endswith(b"\r\n"):
        got += _recv(s, 1)
    if not got.startswith(b"OK"):
        raise ConnectionError("authentication refused: " + got.decode(errors="replace").strip())
    s.sendall(b"BEGIN\r\n")


def _roundtrip(s, serial, fields):
    s.sendall(message(1, serial, fields))
    while True:
        kind, f, _ = read_message(s)
        if kind in (2, 3) and f.get(5) == serial:
            return "ok" if kind == 2 else "error " + f.get(4, "unknown") + (" " + f[2] if 2 in f else "")


def dbus_call(mode, method, uid=None, sock_path=None):
    """The answer of one call: `ok`, `error NAME ...`, or `error ExceptionClass text` when the connection itself fails."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    try:
        s.connect(sock_path or (BUS if mode == "bus" else SOCK))
        dest = [(6, "s", NAME)] if mode == "bus" else []
        call = [(1, "o", PATH), (2, "s", NAME), (3, "s", method)] + dest
        if mode == "bus":
            _auth(s, b"AUTH EXTERNAL " + str(uid if uid is not None else os.getuid()).encode().hex().encode())
            hello = _roundtrip(s, 1, [(1, "o", "/org/freedesktop/DBus"), (2, "s", "org.freedesktop.DBus"), (3, "s", "Hello"), (6, "s", "org.freedesktop.DBus")])
            if hello != "ok":
                return hello
            return _roundtrip(s, 2, call)
        _auth(s, b"AUTH ANONYMOUS " + b"e2e".hex().encode())
        return _roundtrip(s, 1, call)
    except OSError as err:
        return f"error {type(err).__name__} {err}"
    finally:
        s.close()


# ---- PKCS#11 by ctypes (the style of e2e/p11-pss.py)
class Attr(C.Structure):
    _fields_ = [("type", UL), ("value", P), ("len", UL)]


class Mech(C.Structure):
    _fields_ = [("mechanism", UL), ("param", P), ("param_len", UL)]


class Pss(C.Structure):
    _fields_ = [("hash", UL), ("mgf", UL), ("salt", UL)]


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


class Module:
    def __init__(self, path):
        lib = C.CDLL(path)
        lib.C_GetFunctionList.argtypes = [C.POINTER(P)]
        fl = P()
        if lib.C_GetFunctionList(C.byref(fl)):
            die("no function list")
        ptrs = (P * 70).from_address(fl.value + 8)
        self.lib = lib

        def fn(i, *argtypes):
            return C.CFUNCTYPE(UL, *argtypes)(ptrs[i])
        self.initialize, self.get_slots, self.get_token = fn(0, P), fn(4, C.c_ubyte, P, C.POINTER(UL)), fn(6, UL, P)
        self.open_session = fn(12, UL, UL, P, P, C.POINTER(UL))
        self.get_attr = fn(24, UL, UL, C.POINTER(Attr), UL)
        self.find_init, self.find, self.find_final = fn(26, UL, P, UL), fn(27, UL, C.POINTER(UL), UL, C.POINTER(UL)), fn(28, UL)
        self.sign_init, self.sign = fn(42, UL, C.POINTER(Mech), UL), fn(43, UL, C.c_char_p, UL, P, C.POINTER(UL))
        if rv := self.initialize(None):
            die(f"C_Initialize failed: rv = 0x{rv:x}")

    def tokens(self):
        n = UL(0)
        if rv := self.get_slots(1, None, C.byref(n)):
            die(f"C_GetSlotList failed: rv = 0x{rv:x}")
        slots = (UL * max(n.value, 1))()
        if rv := self.get_slots(1, slots, C.byref(n)):
            die(f"C_GetSlotList failed: rv = 0x{rv:x}")
        out = []
        for s in slots[: n.value]:
            info = C.create_string_buffer(1024)
            if self.get_token(s, info) == 0:
                out.append((s, info.raw[:32].rstrip(b" \0").decode()))
        return out

    def session(self, label):
        slot = next((s for s, t in self.tokens() if t == label), None)
        if slot is None:
            die(f"no token {label}")
        sess = UL(0)
        if rv := self.open_session(slot, 4, None, None, C.byref(sess)):
            die(f"C_OpenSession failed: rv = 0x{rv:x}")
        return sess

    def find_one(self, sess, cls):
        c = UL(cls)
        tmpl = (Attr * 1)(Attr(0, C.cast(C.byref(c), P), C.sizeof(UL)))
        if rv := self.find_init(sess, tmpl, 1):
            die(f"C_FindObjectsInit failed: rv = 0x{rv:x}")
        obj, found = UL(0), UL(0)
        self.find(sess, C.byref(obj), 1, C.byref(found))
        self.find_final(sess)
        if found.value != 1:
            die(f"no object of class {cls}")
        return obj


def main(argv):
    print(f"pid\t{os.getpid()}", flush=True)
    cmd = argv[0] if argv else ""
    if cmd == "call" and len(argv) in (3, 4):
        print(dbus_call(argv[1], argv[2], int(argv[3]) if len(argv) == 4 else None))
        return 0
    if cmd == "list" and len(argv) == 2:
        for _, label in Module(argv[1]).tokens():
            print(f"token\t{label}")
        return 0
    if cmd == "cert" and len(argv) == 4:
        m = Module(argv[1])
        sess = m.session(argv[2])
        obj = m.find_one(sess, 1)
        a = (Attr * 1)(Attr(0x11, None, 0))
        if rv := m.get_attr(sess, obj, a, 1):
            die(f"C_GetAttributeValue failed: rv = 0x{rv:x}")
        buf = C.create_string_buffer(a[0].len)
        a[0].value = C.cast(buf, P)
        if rv := m.get_attr(sess, obj, a, 1):
            die(f"C_GetAttributeValue failed: rv = 0x{rv:x}")
        with open(argv[3], "wb") as f:
            f.write(buf.raw[: a[0].len])
        return 0
    if cmd == "sign" and len(argv) == 6 and argv[3] in ("rsa", "ec"):
        m = Module(argv[1])
        sess = m.session(argv[2])
        key = m.find_one(sess, 3)
        if argv[3] == "rsa":
            params = Pss(0x250, 0x2, 32)
            mech = Mech(0xD, C.cast(C.byref(params), P), C.sizeof(Pss))
        else:
            mech = Mech(0x1041, None, 0)
        if rv := m.sign_init(sess, C.byref(mech), key):
            die(f"C_SignInit failed: rv = 0x{rv:x}")
        with open(argv[4], "rb") as f:
            data = f.read()
        buf = C.create_string_buffer(512)
        ln = UL(512)
        if rv := m.sign(sess, data, len(data), buf, C.byref(ln)):
            die(f"C_Sign failed: rv = 0x{rv:x}")
        with open(argv[5], "wb") as f:
            f.write(buf.raw[: ln.value])
        return 0
    die(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
