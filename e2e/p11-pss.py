#!/usr/bin/python3 -I
"""One RSA signature through the PKCS#11 module with one C_Sign call (F134). RSA-PKCS-PSS with the salt length the caller chooses: pkcs11-tool cannot do it with this
module, it looks for a public key object to learn the key size and the module serves only the private key and the certificate. RSA-PKCS (HASH `pkcs`): the
first error of C_Sign, which pkcs11-tool hides behind a retry with C_SignUpdate (docs/findings/F134.md).
Usage: p11-pss.py MODULE TOKEN-LABEL HASH SALT-LEN INPUT-FILE OUTPUT-FILE        HASH is sha256, sha384 or sha512 (MGF1 of the same hash) or pkcs (SALT-LEN ignored)
Exit 0 and the signature in OUTPUT-FILE, or exit 1 with "rv = CKR_NAME (0xHEX)" on stderr and no output file."""
import ctypes as C
import sys

CKR = {0x5: "CKR_GENERAL_ERROR", 0x6: "CKR_FUNCTION_FAILED", 0x7: "CKR_ARGUMENTS_BAD", 0x30: "CKR_DEVICE_ERROR", 0x20: "CKR_DATA_INVALID", 0x21: "CKR_DATA_LEN_RANGE",
       0x54: "CKR_FUNCTION_NOT_SUPPORTED", 0x70: "CKR_MECHANISM_INVALID", 0x71: "CKR_MECHANISM_PARAM_INVALID", 0x91: "CKR_OPERATION_NOT_INITIALIZED",
       0x150: "CKR_BUFFER_TOO_SMALL", 0x190: "CKR_USER_NOT_LOGGED_IN"}
HASH = {"sha256": (0x250, 0x2), "sha384": (0x260, 0x3), "sha512": (0x270, 0x4)}
UL = C.c_ulong
P = C.c_void_p


class Attr(C.Structure):
    _fields_ = [("type", UL), ("value", P), ("len", UL)]


class Mech(C.Structure):
    _fields_ = [("mechanism", UL), ("param", P), ("param_len", UL)]


class Pss(C.Structure):
    _fields_ = [("hash", UL), ("mgf", UL), ("salt", UL)]


def die(rv, where):
    print(f"error: PKCS11 function {where} failed: rv = {CKR.get(rv, 'CKR_UNKNOWN')} (0x{rv:x})", file=sys.stderr)
    sys.exit(1)


def main(argv):
    module, label, h, salt, inp, out = argv
    lib = C.CDLL(module)
    lib.C_GetFunctionList.argtypes = [C.POINTER(P)]
    fl = P()
    if lib.C_GetFunctionList(C.byref(fl)):
        sys.exit("no function list")
    ptrs = (P * 70).from_address(fl.value + 8)

    def fn(i, *argtypes):
        return C.CFUNCTYPE(UL, *argtypes)(ptrs[i])

    initialize, get_slots, get_token, open_session = fn(0, P), fn(4, C.c_ubyte, P, C.POINTER(UL)), fn(6, UL, P), fn(12, UL, UL, P, P, C.POINTER(UL))
    find_init, find, find_final = fn(26, UL, P, UL), fn(27, UL, C.POINTER(UL), UL, C.POINTER(UL)), fn(28, UL)
    sign_init, sign = fn(42, UL, C.POINTER(Mech), UL), fn(43, UL, C.c_char_p, UL, P, C.POINTER(UL))
    if rv := initialize(None):
        die(rv, "C_Initialize")
    n = UL(0)
    get_slots(1, None, C.byref(n))
    slots = (UL * n.value)()
    if rv := get_slots(1, slots, C.byref(n)):
        die(rv, "C_GetSlotList")
    slot = None
    for s in slots[: n.value]:
        info = C.create_string_buffer(1024)
        if get_token(s, info) == 0 and info.raw[:32].rstrip(b" \0").decode() == label:  # CK_TOKEN_INFO starts with the 32-byte label
            slot = s
    if slot is None:
        sys.exit(f"no token {label}")
    sess = UL(0)
    if rv := open_session(slot, 4, None, None, C.byref(sess)):
        die(rv, "C_OpenSession")
    cls = UL(3)  # CKO_PRIVATE_KEY
    tmpl = (Attr * 1)(Attr(0, C.cast(C.byref(cls), P), C.sizeof(UL)))
    if rv := find_init(sess, tmpl, 1):
        die(rv, "C_FindObjectsInit")
    key, found = UL(0), UL(0)
    find(sess, C.byref(key), 1, C.byref(found))
    find_final(sess)
    if found.value != 1:
        sys.exit("no private key")
    if h == "pkcs":
        mech = Mech(0x1, None, 0)
    else:
        hash_ckm, mgf = HASH[h]
        params = Pss(hash_ckm, mgf, int(salt))
        mech = Mech(0xD, C.cast(C.byref(params), P), C.sizeof(Pss))
    if rv := sign_init(sess, C.byref(mech), key):
        die(rv, "C_SignInit")
    data = open(inp, "rb").read()
    buf = C.create_string_buffer(512)
    ln = UL(512)
    if rv := sign(sess, data, len(data), buf, C.byref(ln)):
        die(rv, "C_Sign")
    with open(out, "wb") as f:
        f.write(buf.raw[: ln.value])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
