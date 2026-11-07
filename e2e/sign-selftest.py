#!/usr/bin/python3 -I
"""Self-test of the judgements of sign.py (F134), without a container: signatures are made with openssl and the private keys, written where the guest puts what
the module gave, and every case must pass on them; then each kind of bad evidence must make its case fail. Usage: sign-selftest.py DIR (an empty directory)"""
import importlib.util
import os
import shutil
import subprocess
import sys

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("sign", os.path.join(here, "sign.py"))
sign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sign)

d = sys.argv[1]
fails = []


def ssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def inp(name):
    return os.path.join(d, "in", name)


def put(name, data):
    with open(os.path.join(d, "out", name), "wb") as f:
        f.write(data)


def der_to_raw(der):
    assert der[0] == 0x30
    i = 2 if der[1] < 0x80 else 3
    out = b""
    for _ in range(2):
        n = der[i + 1]
        out += der[i + 2:i + 2 + n].lstrip(b"\0").rjust(32, b"\0")
        i += 2 + n
    return out


def make_good():
    sign.prepare(d)
    os.makedirs(os.path.join(d, "out"), exist_ok=True)
    for k, args in (("rsa", ["rsa", "-pkeyopt", "rsa_keygen_bits:2048"]), ("ec", ["EC", "-pkeyopt", "ec_paramgen_curve:P-256"])):
        ssl("genpkey", "-algorithm", args[0], *args[1:], "-out", os.path.join(d, f"{k}.key"))
        with open(inp(f"{k}.pub.pem"), "wb") as f:
            f.write(ssl("pkey", "-in", os.path.join(d, f"{k}.key"), "-pubout"))
    for _g, name, key, infile, _args, expect in sign.jobs():
        kind, _, arg = expect.partition(":")
        k = os.path.join(d, f"{key}.key")
        i = inp(infile)
        if kind == "refused":
            put(f"{name}.rc", b"1\n")
            put(f"{name}.log", b"error: PKCS11 function C_Sign failed: rv = CKR_DATA_INVALID (0x20)\n")
            continue
        if kind == "digest":
            sig = ssl("pkeyutl", "-sign", "-inkey", k, "-in", inp(f"dgst-{arg}.bin"), "-pkeyopt", f"digest:{arg}")
        elif kind == "recover":
            sig = ssl("rsautl", "-sign", "-inkey", k, "-in", i)  # PKCS#1 v1.5 type 1 over the payload as it is
        elif kind == "pss":
            h, _, salt = arg.partition(":")
            sig = ssl("pkeyutl", "-sign", "-inkey", k, "-in", i, *sign.pss_opts(h, salt))
        elif kind == "dgst":
            sig = ssl("dgst", f"-{arg}", "-sign", k, inp("msg.bin"))
        elif kind == "ec":
            sig = der_to_raw(ssl("pkeyutl", "-sign", "-inkey", k, "-in", i))
        elif kind == "ecdgst":
            sig = ssl("dgst", f"-{arg}", "-sign", k, inp("msg.bin"))
        put(f"{name}.sig", sig)
        put(f"{name}.rc", b"0\n")
        put(f"{name}.log", b"")
    for g in sign.groups():
        n = sum(1 for j in sign.jobs() if j[0] == g)
        with open(os.path.join(d, f"count-{g}"), "w") as f:
            f.write(f"{n}\n")


def expect_ok(label):
    for g in sign.groups():
        p = sign.case_problems(g, d)
        if p:
            fails.append(f"{label}: {g} fails on good evidence: {p}")


def expect_bad(label, case, mutate):
    """mutate(): changes the files; the case must then report a problem; the files are restored afterwards."""
    snap = os.path.join(d, "snap")
    shutil.rmtree(snap, ignore_errors=True)
    shutil.copytree(os.path.join(d, "out"), snap)
    shutil.copy(os.path.join(d, f"count-{case}"), os.path.join(d, "count.keep"))
    mutate()
    if not sign.case_problems(case, d):
        fails.append(f"{label}: {case} accepts bad evidence")
    shutil.rmtree(os.path.join(d, "out"))
    shutil.copytree(snap, os.path.join(d, "out"))
    shutil.copy(os.path.join(d, "count.keep"), os.path.join(d, f"count-{case}"))


def out(name):
    return os.path.join(d, "out", name)


def kinds():
    rows = {
        "swtpm": ("tpm", "tpm"),
        "none": ("encrypted-host", "encrypted-host"),
        "lacking": ("tpm", "tpm"),
    }
    p = os.path.join(d, "api.out")

    def write(rsa, ec):
        with open(p, "w") as f:
            f.write(f"sg-rsa\trsa2048\t{rsa}\nsg-ec\tecdsa-p256\t{ec}\n")

    specs = ["sg-rsa:rsa2048", "sg-ec:ecdsa-p256"]
    for mode, (rsa, ec) in rows.items():
        write(rsa, ec)
        if sign.kind_problems(p, mode, specs):
            fails.append(f"kind: the right kinds are refused in {mode}")
    for label, mode, rsa, ec in (("a swtpm list under none", "none", "tpm", "tpm"), ("encrypted-tpm RSA under swtpm", "swtpm", "encrypted-tpm", "tpm"),
                                 ("encrypted-tpm EC under lacking", "lacking", "tpm", "encrypted-tpm"),
                                 ("a substring of the kind", "swtpm", "tpm-ish", "tpm"), ("encrypted-host RSA under lacking", "lacking", "encrypted-host", "tpm")):
        write(rsa, ec)
        if not sign.kind_problems(p, mode, specs):
            fails.append(f"kind: {label} is accepted")
    with open(p, "w") as f:
        f.write("sg-rsa\trsa2048\ttpm\n")
    if not sign.kind_problems(p, "swtpm", specs):
        fails.append("kind: a missing key is accepted")


make_good()
expect_ok("good evidence")


def swap(a, b):
    def f():
        shutil.copy(out(b), out(a))
    return f


def write_bytes(name, fn):
    def f():
        put(name, fn(open(out(name), "rb").read()))
    return f


expect_bad("recovered payload differs", "sign-rsa-pkcs", swap("rsa-pkcs-md5sha1.sig", "rsa-pkcs-arbitrary.sig"))
expect_bad("another hash", "sign-rsa-pkcs", swap("rsa-pkcs-sha256.sig", "rsa-pkcs-sha384.sig"))
expect_bad("another salt length", "sign-rsa-pss-sha256", swap("pss-sha256-hash.sig", "pss-sha256-0.sig"))
expect_bad("another salt length (max)", "sign-rsa-pss-sha512", swap("pss-sha512-max.sig", "pss-sha512-hash.sig"))
expect_bad("another hash (PSS)", "sign-rsa-pss-sha384", swap("pss-sha384-0.sig", "pss-sha512-0.sig"))
expect_bad("truncated", "sign-rsa-pss-sha256", write_bytes("pss-sha256-max.sig", lambda b: b[:-1]))
expect_bad("empty output", "sign-rsa-composed", write_bytes("rsa-sha256.sig", lambda b: b""))
expect_bad("a signature of another hash", "sign-rsa-composed", swap("rsa-sha384.sig", "rsa-sha512.sig"))
expect_bad("an EC signature of another hash", "sign-ec-ecdsa", swap("ecdsa-sha256.sig", "ecdsa-sha384.sig"))
expect_bad("an EC signature of 63 bytes", "sign-ec-ecdsa", write_bytes("ecdsa-sha512.sig", lambda b: b[:-1]))
expect_bad("a composed EC signature of another hash", "sign-ec-composed", swap("ecdsa-sha384-composed.sig", "ecdsa-sha512-composed.sig"))
expect_bad("a failing exit code", "sign-ec-composed", lambda: put("ecdsa-sha256-composed.rc", b"1\n"))
expect_bad("a refusal that left output", "sign-rsa-pss-sha256", lambda: put("pss-sha256-over.sig", b"x" * 256))
expect_bad("a refusal that exited 0", "sign-rsa-pss-sha384", lambda: put("pss-sha384-over.rc", b"0\n"))
expect_bad("a refusal with another error", "sign-rsa-pkcs", lambda: put("rsa-pkcs-too-long.log", b"rv = CKR_DEVICE_ERROR (0x30)\n"))
expect_bad("a refusal with no error", "sign-rsa-pss-sha512", lambda: put("pss-sha512-over.log", b""))
expect_bad("one request too few", "sign-ec-ecdsa", lambda: open(os.path.join(d, "count-sign-ec-ecdsa"), "w").write("2\n"))
expect_bad("one request too many", "sign-rsa-pss-sha256", lambda: open(os.path.join(d, "count-sign-rsa-pss-sha256"), "w").write("5\n"))
expect_bad("no request count", "sign-rsa-composed", lambda: os.remove(os.path.join(d, "count-sign-rsa-composed")))
kinds()

if fails:
    print("\n".join(fails), file=sys.stderr)
    sys.exit(1)
print("sign-selftest: passed")
