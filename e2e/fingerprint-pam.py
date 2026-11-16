#!/usr/bin/env python3
"""PAM client of the fingerprint-* cases (F199). Usage: fingerprint-pam.py SERVICE USER PASSWORD.

Runs pam_start/pam_authenticate for SERVICE with PASSWORD as the answer to every prompt, then reads its own /proc/self/maps and prints
`rc=<pam_authenticate result> fprintd=<1 if pam_fprintd.so is mapped, else 0>`. The mapping shows that the service's stack loaded pam_fprintd.
"""
import ctypes
import sys

PROMPT_ECHO_OFF, PROMPT_ECHO_ON = 1, 2


class Msg(ctypes.Structure):
    _fields_ = [("style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class Resp(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("retcode", ctypes.c_int)]


CONV = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(Msg)), ctypes.POINTER(ctypes.POINTER(Resp)), ctypes.c_void_p)


class Conv(ctypes.Structure):
    _fields_ = [("conv", CONV), ("data", ctypes.c_void_p)]


def main(service, user, password):
    pam = ctypes.CDLL("libpam.so.0")
    libc = ctypes.CDLL(None)
    libc.calloc.restype = ctypes.c_void_p
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]
    pw = password.encode()

    def conv(n, msgs, resp, _data):
        arr = ctypes.cast(libc.calloc(n, ctypes.sizeof(Resp)), ctypes.POINTER(Resp))
        for i in range(n):
            if msgs[i].contents.style in (PROMPT_ECHO_OFF, PROMPT_ECHO_ON):
                arr[i].resp = libc.strdup(pw)
        resp[0] = arr
        return 0

    cb = CONV(conv)
    c = Conv(cb, None)
    handle = ctypes.c_void_p()
    pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(Conv), ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
    rc = pam.pam_start(service.encode(), user.encode(), ctypes.byref(c), ctypes.byref(handle))
    if rc == 0:
        rc = pam.pam_authenticate(handle, 0)
        pam.pam_end(handle, rc)
    with open("/proc/self/maps", encoding="utf-8") as f:
        mapped = any("pam_fprintd.so" in line for line in f)
    print(f"rc={rc} fprintd={int(mapped)}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
