#!/usr/bin/python3 -I
"""The jobs and the judgements of the sign-* cases (F134, acceptances 2 and 6 of SPEC.md), as functions of files, so that sign-selftest.sh can show each
judgement fails on bad evidence without a container. Each subcommand prints one problem per line and nothing when the evidence is right (exit 0 either way;
exit 2 on a bad call).
  sign.py prepare DIR                  writes DIR/in/*: the message, its digests, DigestInfos and the payloads that are not a DigestInfo
  sign.py jobs [CASE]                  one line per signature: NAME KEY INPUT then the pkcs11-tool arguments, or `p11-pss HASH SALT` (e2e/p11-pss.py); the guest runs each (DIR/out/NAME.sig, .rc, .log)
  sign.py groups                       the case ids, one per line (a case is judged on its own jobs)
  sign.py case ID DIR                  the problems of one case (needs DIR/in/{rsa,ec}.pub.pem, the out files and DIR/count-ID, the agent requests it caused)
  sign.py kind FILE MODE ID:KEYTYPE... owner-call.py list output: the kind of each key is the one MODE gives its type (swtpm tpm/tpm, none encrypted-host, lacking RSA encrypted-tpm, EC tpm)
Every verification is `openssl` with the public key of the certificate the module served; PSS names its hash, its MGF1 hash and its salt length.
"""
import os
import re
import subprocess
import sys

HASHES = {"sha256": 32, "sha384": 48, "sha512": 64}
DIGESTINFO = {
    "sha256": "3031300d060960864801650304020105000420",
    "sha384": "3041300d060960864801650304020205000430",
    "sha512": "3051300d060960864801650304020305000440",
}
KEY_BYTES = 256  # RSA 2048
EC_BYTES = 64  # raw r||s on P-256
# 2048-bit key: the largest salt is 256 - 2 - hash length (F107)
MAX_SALT = {h: KEY_BYTES - 2 - n for h, n in HASHES.items()}
# The error pkcs11-tool reports when the service refuses (a salt too long, a payload too long): the same in every mode (SPEC section 4).
REFUSED_CKR = "CKR_DATA_INVALID"  # replaced by what the finding proves
# Whether a refused signature reaches the agent (polkit) before it is refused; fixed by docs/findings/F134.md.
REFUSED_ASKS_POLKIT = True
PAYLOAD_36, PAYLOAD_ARB, PAYLOAD_LONG = 36, 100, 246

KINDS = {  # mode -> (RSA kind, EC kind)
    "swtpm": ("tpm", "tpm"),
    "none": ("encrypted-host", "encrypted-host"),
    "lacking": ("tpm", "tpm"),  # the filter removes RSAPSS, which no key needs (docs/findings/F134.md); encrypted-tpm is out of reach in the container
}
KEYTYPES = {"rsa": "rsa2048", "ec": "ecdsa-p256"}
OTHER = {"sha256": "sha384", "sha384": "sha512", "sha512": "sha256"}


def jobs():
    """[(group, name, key, input file, extra pkcs11-tool args, expectation)]; the expectation is parsed by judge_job."""
    out = []
    for h in HASHES:
        out.append(("sign-rsa-pkcs", f"rsa-pkcs-{h}", "rsa", f"di-{h}.bin", ["--mechanism", "RSA-PKCS"], f"digest:{h}"))
    out.append(("sign-rsa-pkcs", "rsa-pkcs-md5sha1", "rsa", "md5sha1.bin", ["--mechanism", "RSA-PKCS"], "recover:md5sha1.bin"))
    out.append(("sign-rsa-pkcs", "rsa-pkcs-arbitrary", "rsa", "arbitrary.bin", ["--mechanism", "RSA-PKCS"], "recover:arbitrary.bin"))
    out.append(("sign-rsa-pkcs", "rsa-pkcs-too-long", "rsa", "too-long.bin", ["p11-pss", "pkcs", "0"], "refused"))
    for h, n in HASHES.items():
        g = f"sign-rsa-pss-{h}"
        for label, salt in (("0", 0), ("hash", n), ("max", MAX_SALT[h])):
            out.append((g, f"pss-{h}-{label}", "rsa", f"dgst-{h}.bin", pss_args(h, salt), f"pss:{h}:{salt}"))
        out.append((g, f"pss-{h}-over", "rsa", f"dgst-{h}.bin", pss_args(h, MAX_SALT[h] + 1), "refused"))
    for h in HASHES:
        out.append(("sign-rsa-composed", f"rsa-{h}", "rsa", "msg.bin", ["--mechanism", f"{h.upper()}-RSA-PKCS"], f"dgst:{h}"))
    for h in HASHES:
        out.append(("sign-ec-ecdsa", f"ecdsa-{h}", "ec", f"dgst-{h}.bin", ["--mechanism", "ECDSA"], f"ec:{h}"))
    for h in HASHES:
        out.append(("sign-ec-composed", f"ecdsa-{h}-composed", "ec", "msg.bin",
                    ["--mechanism", f"ECDSA-{h.upper()}", "--signature-format", "openssl"], f"ecdgst:{h}"))
    return out


def pss_args(h, salt):
    # p11-pss.py, not pkcs11-tool: see the docstring of that script
    return ["p11-pss", h, str(salt)]


def groups():
    seen = []
    for g, *_ in jobs():
        if g not in seen:
            seen.append(g)
    return seen


def prepare(d):
    os.makedirs(os.path.join(d, "in"), exist_ok=True)

    def w(name, data):
        with open(os.path.join(d, "in", name), "wb") as f:
            f.write(data)

    msg = os.urandom(1000)
    w("msg.bin", msg)
    for h in HASHES:
        dg = subprocess.run(["openssl", "dgst", f"-{h}", "-binary"], input=msg, capture_output=True, check=True).stdout
        w(f"dgst-{h}.bin", dg)
        w(f"di-{h}.bin", bytes.fromhex(DIGESTINFO[h]) + dg)
    w("md5sha1.bin", os.urandom(PAYLOAD_36))
    w("arbitrary.bin", os.urandom(PAYLOAD_ARB))
    w("too-long.bin", os.urandom(PAYLOAD_LONG))


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def ssl(args, data=None):
    """(exit code, stdout bytes, stderr text) of openssl."""
    p = subprocess.run(["openssl", *args], input=data, capture_output=True, check=False)
    return p.returncode, p.stdout, p.stderr.decode(errors="replace") + p.stdout.decode(errors="replace")[:200]


def raw_to_der(raw):
    """ECDSA r||s (two 32-byte integers) as the DER SEQUENCE OpenSSL reads."""
    def integer(b):
        b = b.lstrip(b"\0") or b"\0"
        if b[0] & 0x80:
            b = b"\0" + b
        return b"\x02" + bytes([len(b)]) + b
    body = integer(raw[:32]) + integer(raw[32:])
    return b"\x30" + bytes([len(body)]) + body


def verify_pkeyutl(d, key, digest_file, sig_path, opts):
    code, out, text = ssl(["pkeyutl", "-verify", "-pubin", "-inkey", os.path.join(d, "in", f"{key}.pub.pem"),
                           "-in", os.path.join(d, "in", digest_file), "-sigfile", sig_path, *opts])
    return code == 0 and "Signature Verified Successfully" in text


def verify_dgst(d, key, h, sig_path):
    code, out, text = ssl(["dgst", f"-{h}", "-verify", os.path.join(d, "in", f"{key}.pub.pem"), "-signature", sig_path,
                           os.path.join(d, "in", "msg.bin")])
    return code == 0 and "Verified OK" in text


def pss_opts(h, salt):
    return ["-pkeyopt", f"digest:{h}", "-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt", f"rsa_mgf1_md:{h}", "-pkeyopt", f"rsa_pss_saltlen:{salt}"]


def ckr(d, name):
    log = read(os.path.join(d, "out", f"{name}.log")) or b""
    m = re.findall(rb"CKR_[A-Z_0-9]+", log)
    return m[-1].decode() if m else ""


def judge_job(d, key, name, inp, expect):
    out = []
    sig_path = os.path.join(d, "out", f"{name}.sig")
    rc = (read(os.path.join(d, "out", f"{name}.rc")) or b"?").decode().strip()
    sig = read(sig_path)
    kind, _, arg = expect.partition(":")
    if kind == "refused":
        if rc in ("0", "?"):
            out.append(f"{name}: expected a refusal, exit code {rc}")
        if sig:
            out.append(f"{name}: a refused signature left {len(sig)} bytes of output")
        if ckr(d, name) != REFUSED_CKR:
            out.append(f"{name}: the error is {ckr(d, name)!r}, expected {REFUSED_CKR}")
        return out
    if rc != "0":
        return [f"{name}: pkcs11-tool exit code {rc}"]
    want = EC_BYTES if key == "ec" and kind == "ec" else KEY_BYTES
    if kind == "ecdgst":
        want = None
    if not sig:
        return [f"{name}: no signature"]
    if want is not None and len(sig) != want:
        return [f"{name}: signature of {len(sig)} bytes, expected {want}"]
    if kind == "digest":
        if not verify_pkeyutl(d, key, f"dgst-{arg}.bin", sig_path, ["-pkeyopt", f"digest:{arg}"]):
            out.append(f"{name}: openssl does not verify with {arg}")
        if verify_pkeyutl(d, key, f"dgst-{OTHER[arg]}.bin", sig_path, ["-pkeyopt", f"digest:{OTHER[arg]}"]):
            out.append(f"{name}: openssl verifies with {OTHER[arg]} too")
    elif kind == "recover":
        code, rec, _ = ssl(["pkeyutl", "-verifyrecover", "-pubin", "-inkey", os.path.join(d, "in", "rsa.pub.pem"), "-in", sig_path])
        if code != 0 or rec != read(os.path.join(d, "in", arg)):
            out.append(f"{name}: the recovered bytes are not the payload")
        other = "arbitrary.bin" if arg == "md5sha1.bin" else "md5sha1.bin"
        if rec == read(os.path.join(d, "in", other)):
            out.append(f"{name}: the recovered bytes are also {other}")
    elif kind == "pss":
        h, _, salt = arg.partition(":")
        salt = int(salt)
        if not verify_pkeyutl(d, key, f"dgst-{h}.bin", sig_path, pss_opts(h, salt)):
            out.append(f"{name}: openssl does not verify with {h}, MGF1 {h}, salt {salt}")
        other_salt = HASHES[h] if salt != HASHES[h] else 0
        if verify_pkeyutl(d, key, f"dgst-{h}.bin", sig_path, pss_opts(h, other_salt)):
            out.append(f"{name}: openssl verifies with salt {other_salt} too")
        o = OTHER[h]
        if verify_pkeyutl(d, key, f"dgst-{o}.bin", sig_path, pss_opts(o, salt)):
            out.append(f"{name}: openssl verifies with {o} too")
    elif kind == "dgst":
        if not verify_dgst(d, key, arg, sig_path):
            out.append(f"{name}: openssl does not verify with {arg}")
        if verify_dgst(d, key, OTHER[arg], sig_path):
            out.append(f"{name}: openssl verifies with {OTHER[arg]} too")
    elif kind == "ec":
        der = os.path.join(d, "out", f"{name}.der")
        with open(der, "wb") as f:
            f.write(raw_to_der(sig))
        if not verify_pkeyutl(d, key, f"dgst-{arg}.bin", der, []):
            out.append(f"{name}: openssl does not verify the {arg} digest")
        if verify_pkeyutl(d, key, f"dgst-{OTHER[arg]}.bin", der, []):
            out.append(f"{name}: openssl verifies the {OTHER[arg]} digest too")
    elif kind == "ecdgst":
        if not verify_dgst(d, key, arg, sig_path):
            out.append(f"{name}: openssl does not verify with {arg}")
        if verify_dgst(d, key, OTHER[arg], sig_path):
            out.append(f"{name}: openssl verifies with {OTHER[arg]} too")
    else:
        out.append(f"{name}: unknown expectation {expect}")
    return out


def case_problems(case, d):
    out = []
    mine = [j for j in jobs() if j[0] == case]
    if not mine:
        sys.exit(f"sign: unknown case {case}")
    for _, name, key, inp, _args, expect in mine:
        out += judge_job(d, key, name, inp, expect)
    asking = sum(1 for j in mine if j[5] != "refused" or REFUSED_ASKS_POLKIT)
    got = (read(os.path.join(d, f"count-{case}")) or b"").decode().strip()
    if got != str(asking):
        out.append(f"{case}: the agent was asked {got or '?'} times, expected exactly {asking}")
    return out


def kind_problems(path, mode, specs):
    if mode not in KINDS:
        sys.exit(f"sign: unknown mode {mode}")
    rows = [ln.split("\t") for ln in open(path, encoding="utf-8").read().split("\n") if ln]
    if any(len(r) != 3 for r in rows):
        return [f"{path}: a line is not ID<TAB>TYPE<TAB>KIND"]
    out = []
    for spec in specs:
        key_id, _, kt = spec.rpartition(":")
        want = KINDS[mode][0 if kt == KEYTYPES["rsa"] else 1]
        mine = [r for r in rows if r[0] == key_id]
        if len(mine) != 1:
            out.append(f"{path}: {len(mine)} rows for {key_id}, expected 1")
            continue
        if mine[0][1] != kt:
            out.append(f"{key_id}: key type {mine[0][1]!r}, expected {kt!r}")
        if mine[0][2] != want:
            out.append(f"{key_id}: kind {mine[0][2]!r}, expected {want!r} in mode {mode}")
    return out


def main(argv):
    if argv[:1] == ["prepare"] and len(argv) == 2:
        prepare(argv[1])
    elif argv[:1] == ["jobs"] and len(argv) <= 2:
        for g, name, key, inp, args, _e in jobs():
            if len(argv) == 1 or g == argv[1]:
                print(name, key, inp, *args)
    elif argv == ["groups"]:
        print("\n".join(groups()))
    elif argv[:1] == ["case"] and len(argv) == 3:
        print("\n".join(case_problems(argv[1], argv[2])))
    elif argv[:1] == ["kind"] and len(argv) >= 4:
        print("\n".join(kind_problems(argv[1], argv[2], argv[3:])))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
