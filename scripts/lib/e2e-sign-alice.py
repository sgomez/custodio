#!/usr/bin/python3 -I
"""Stand-in for alice's session of sign-run.sh on fixtures (F162): usage e2e-sign-alice.py E2E_DIR WORK. It takes the keys out of the .p12 files sign-run.sh made, signs every job with
REAL openssl (PKCS#1 v1.5, PSS with the exact salt length, ECDSA) and writes what sign-user.sh writes. Environment: STUB_KIND (kind of both keys, default tpm), STUB_BADSIG=NAME (that
signature is made with the other key's hash), STUB_NOIMPORTED=1 (no `imported` file), STUB_WAIT (wait for read-done when SG_READ is set, as sign-user.sh does)."""
import importlib.util
import os
import subprocess
import sys
import time

e2e, work = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("sign", os.path.join(e2e, "sign.py"))
sign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sign)
sg = os.path.join(work, "sign")
env = os.environ


def ssl(*args):
    return subprocess.run(["openssl", *args], capture_output=True, check=True).stdout


def put(path, data):
    with open(path, "wb") as f:
        f.write(data)


def der_to_raw(der):
    i = 2 if der[1] < 0x80 else 3
    out = b""
    for _ in range(2):
        n = der[i + 1]
        out += der[i + 2:i + 2 + n].lstrip(b"\0").rjust(32, b"\0")
        i += 2 + n
    return out


os.makedirs(os.path.join(sg, "out"), exist_ok=True)
for k in ("rsa", "ec"):
    key = os.path.join(sg, f"{k}.fixture.key")
    put(key, ssl("pkcs12", "-in", os.path.join(sg, f"{k}.p12"), "-passin", "pass:e2e-password", "-nocerts", "-noenc"))
    put(os.path.join(sg, "in", f"{k}.pub.pem"), ssl("pkey", "-in", key, "-pubout"))
kind = env.get("STUB_KIND", "tpm")
rows = f"sg-rsa\trsa2048\t{kind}\nsg-ec\tecdsa-p256\t{kind}\n"
put(os.path.join(sg, "api.out"), rows.encode())
if env.get("SG_READ") and not env.get("STUB_NOIMPORTED"):
    put(os.path.join(sg, "imported"), b"")
    for _ in range(300):
        if os.path.exists(os.path.join(sg, "read-done")):
            break
        time.sleep(0.1)
    else:
        sys.exit("read-done never came")
inp = lambda n: os.path.join(sg, "in", n)  # noqa: E731
for _g, name, key, infile, _args, expect in sign.jobs():
    kd, _, arg = expect.partition(":")
    k = os.path.join(sg, f"{key}.fixture.key")
    i = inp(infile)
    o = os.path.join(sg, "out", name)
    if kd == "refused":
        put(o + ".rc", b"1\n")
        put(o + ".log", b"error: PKCS11 function C_Sign failed: rv = CKR_DATA_INVALID (0x20)\n")
        continue
    if kd == "digest":
        sig = ssl("pkeyutl", "-sign", "-inkey", k, "-in", inp(f"dgst-{arg}.bin"), "-pkeyopt", f"digest:{arg}")
    elif kd == "recover":
        sig = ssl("rsautl", "-sign", "-inkey", k, "-in", i)
    elif kd == "pss":
        h, _, salt = arg.partition(":")
        if env.get("STUB_BADSIG") == name:
            salt = "0" if salt != "0" else "20"
        sig = ssl("pkeyutl", "-sign", "-inkey", k, "-in", i, *sign.pss_opts(h, salt))
    elif kd == "dgst":
        sig = ssl("dgst", f"-{arg}", "-sign", k, inp("msg.bin"))
    elif kd == "ec":
        sig = der_to_raw(ssl("pkeyutl", "-sign", "-inkey", k, "-in", i))
    else:
        sig = ssl("dgst", f"-{arg}", "-sign", k, inp("msg.bin"))
    put(o + ".sig", sig)
    put(o + ".rc", b"0\n")
    put(o + ".log", b"")
put(os.path.join(sg, "groups"), ("\n".join(sign.groups()) + "\n").encode())
put(os.path.join(sg, "jobs"), ("\n".join(f"{j[1]} {j[2]} {j[3]}" for j in sign.jobs()) + "\n").encode())
for g in sign.groups():
    put(os.path.join(sg, f"count-{g}"), f"{sum(1 for j in sign.jobs() if j[0] == g)}\n".encode())
put(os.path.join(sg, "api-mid.out"), rows.encode())
put(os.path.join(sg, "api-after.out"), b"")
