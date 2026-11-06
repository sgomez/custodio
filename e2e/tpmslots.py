#!/usr/bin/python3 -I
"""The judgements of the tpm-slots-* cases (F143, acceptance 10 of SPEC.md), as functions of files, so that scripts/test-e2e-tpmslots.sh can show each one fails on bad
evidence without a container. Each subcommand prints one problem per line and nothing when the evidence is right (exit 0 either way; exit 2 on a bad call).
  tpmslots.py cases
  tpmslots.py slotcount FILE            prints the transient-object count of `tpm2_getcap properties-fixed` (TPM2_PT_HR_TRANSIENT_MIN); exit 1 and a message on stderr when it
                                        cannot be read or is not in 1..64
  tpmslots.py calls DIR RECORDS PUB TYPE MIN
                                        the signing calls of a run, from the records the guest logged ("IDX<TAB>MECH<TAB>RC<TAB>SIG<TAB>INPUT", paths relative to DIR): at
                                        least MIN records (counted here, from the records), numbered 1..n with no gap, each with exit status 0, a mechanism fit for TYPE
                                        (rsa2048: pkcs and pss, both present when n > 1; ecdsa-p256: ecdsa) and a signature that `openssl` verifies against PUB
  tpmslots.py imports RECORDS MIN       the imports of a run ("IDX<TAB>ID<TAB>RC"): at least MIN records, numbered 1..n, distinct ids, exit status 0
  tpmslots.py listed LIST ID:TYPE...    owner-call.py list output ("ID<TAB>TYPE<TAB>KIND"): each ID once, with that type and kind tpm
  tpmslots.py gone LIST ID...           none of the IDs is listed
  tpmslots.py handles BEFORE AFTER      two `tpm2_getcap handles-transient` (or handles-loaded-session) outputs: no handle in AFTER that is not in BEFORE
  tpmslots.py leaked BEFORE LEAKED      the same judgement must report a handle: a problem when LEAKED holds none that BEFORE lacks (the control)
Signing: RSA with SHA256-RSA-PKCS and RSA-PKCS-PSS (SHA-256, salt 32), P-256 with ECDSA-SHA256 in the openssl (DER) format; the mechanisms are F134's, not repeated.
"""
import os
import re
import subprocess
import sys

CASES = ["tpm-slots-sign-rsa", "tpm-slots-sign-ec", "tpm-slots-import", "tpm-slots-no-leak"]
MECHS = {"rsa2048": ("pkcs", "pss"), "ecdsa-p256": ("ecdsa",)}
MAX_SLOTS = 64


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def text(path):
    b = read(path)
    return None if b is None else b.decode("utf-8", errors="replace")


def rows(path):
    t = text(path)
    if t is None:
        return None
    return [ln.split("\t") for ln in t.split("\n") if ln]


def slotcount(path):
    t = text(path)
    if t is None:
        return None, f"{path}: cannot be read"
    m = re.search(r"^\s*TPM2_PT_HR_TRANSIENT_MIN:\s*\n\s*raw:\s*0x([0-9a-fA-F]+)\s*$", t, re.M)
    if not m:
        return None, f"{path}: no TPM2_PT_HR_TRANSIENT_MIN with a raw value (not a properties-fixed reading)"
    n = int(m.group(1), 16)
    if not 1 <= n <= MAX_SLOTS:
        return None, f"{path}: the TPM reports {n} transient object slots, expected 1..{MAX_SLOTS}"
    return n, None


def ssl(args):
    p = subprocess.run(["openssl", *args], capture_output=True, check=False)
    return p.returncode, p.stderr.decode(errors="replace") + p.stdout.decode(errors="replace")


def verifies(mech, pub, sig, inp):
    if mech in ("pkcs", "ecdsa"):
        code, t = ssl(["dgst", "-sha256", "-verify", pub, "-signature", sig, inp])
        return code == 0 and "Verified OK" in t
    code, t = ssl(["pkeyutl", "-verify", "-pubin", "-inkey", pub, "-in", inp, "-sigfile", sig, "-pkeyopt", "digest:sha256",
                   "-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt", "rsa_mgf1_md:sha256", "-pkeyopt", "rsa_pss_saltlen:32"])
    return code == 0 and "Signature Verified Successfully" in t


def sequence(idxs):
    return idxs == list(range(1, len(idxs) + 1))


def calls(d, records, pub, kt, minimum):
    if kt not in MECHS:
        return [f"key type {kt!r} has no signing job"]
    if minimum < 1:
        return [f"the required number of calls is {minimum}: nothing would be proven"]
    r = rows(os.path.join(d, records))
    if r is None:
        return [f"{records}: the call records cannot be read"]
    out = []
    if len(r) < minimum:
        out.append(f"only {len(r)} calls were made, at least {minimum} (slots + 3) are needed")
    if any(len(x) != 5 for x in r):
        return out + [f"{records}: a record is not IDX<TAB>MECH<TAB>RC<TAB>SIG<TAB>INPUT"]
    if not all(x[0].isdigit() for x in r) or not sequence([int(x[0]) for x in r]):
        out.append(f"{records}: the calls are not numbered 1..{len(r)} in a row")
    seen = set()
    for idx, mech, rc, sig, inp in r:
        seen.add(mech)
        if mech not in MECHS[kt]:
            out.append(f"call {idx}: mechanism {mech!r} is not one of {MECHS[kt]} for {kt}")
            continue
        if rc != "0":
            out.append(f"call {idx} ({mech}): signing exited {rc}")
            continue
        if not read(os.path.join(d, sig)):
            out.append(f"call {idx} ({mech}): no signature")
            continue
        if not verifies(mech, pub, os.path.join(d, sig), os.path.join(d, inp)):
            out.append(f"call {idx} ({mech}): the signature does not verify against the served certificate")
    if len(r) > 1:
        for m in MECHS[kt]:
            if m not in seen:
                out.append(f"no call used the mechanism {m}")
    return out


def imports(records, minimum):
    if minimum < 1:
        return [f"the required number of imports is {minimum}: nothing would be proven"]
    r = rows(records)
    if r is None:
        return [f"{records}: the import records cannot be read"]
    out = []
    if len(r) < minimum:
        out.append(f"only {len(r)} imports were made, at least {minimum} (slots + 3) are needed")
    if any(len(x) != 3 for x in r):
        return out + [f"{records}: a record is not IDX<TAB>ID<TAB>RC"]
    if not all(x[0].isdigit() for x in r) or not sequence([int(x[0]) for x in r]):
        out.append(f"{records}: the imports are not numbered 1..{len(r)} in a row")
    if len({x[1] for x in r}) != len(r):
        out.append(f"{records}: an id was imported twice")
    out += [f"import {x[0]} ({x[1]}) exited {x[2]}" for x in r if x[2] != "0"]
    return out


def listed(path, specs):
    r = rows(path)
    if r is None:
        return [f"{path}: cannot be read"]
    if any(len(x) != 3 for x in r):
        return [f"{path}: a line is not ID<TAB>TYPE<TAB>KIND"]
    out = []
    for spec in specs:
        kid, _, kt = spec.rpartition(":")
        mine = [x for x in r if x[0] == kid]
        if len(mine) != 1:
            out.append(f"{kid}: {len(mine)} rows in the list, expected 1")
            continue
        if mine[0][1] != kt:
            out.append(f"{kid}: key type {mine[0][1]!r}, expected {kt!r}")
        if mine[0][2] != "tpm":
            out.append(f"{kid}: kind {mine[0][2]!r}, expected 'tpm'")
    return out


def gone(path, ids):
    r = rows(path)
    if r is None:
        return [f"{path}: cannot be read"]
    return [f"{kid}: still listed" for kid in ids if any(x[0] == kid for x in r)]


def handle_set(path):
    t = text(path)
    if t is None:
        return None, f"{path}: the handle list cannot be read"
    hs = set()
    for ln in t.split("\n"):
        if not ln.strip():
            continue
        m = re.fullmatch(r"\s*-\s*(0x[0-9a-fA-F]+)\s*", ln)
        if not m:
            return None, f"{path}: not a handle list: {ln.strip()[:80]}"
        hs.add(m.group(1).lower())
    return hs, None


def handles(before, after):
    b, e1 = handle_set(before)
    a, e2 = handle_set(after)
    if e1 or e2:
        return [e for e in (e1, e2) if e]
    return [f"handle {h} is loaded and was not before" for h in sorted(a - b)]


def leaked(before, leak):
    if handle_set(before)[0] is None or handle_set(leak)[0] is None:
        return handles(before, leak) or ["the control has no evidence"]
    return [] if handles(before, leak) else ["the control loaded an object and the judgement did not report a new handle"]


def main(argv):
    n = len(argv)
    if argv == ["cases"]:
        print("\n".join(CASES))
    elif argv[:1] == ["slotcount"] and n == 2:
        v, err = slotcount(argv[1])
        if err:
            print(err, file=sys.stderr)
            return 1
        print(v)
    elif argv[:1] == ["calls"] and n == 6 and argv[5].isdigit():
        print("\n".join(calls(argv[1], argv[2], argv[3], argv[4], int(argv[5]))))
    elif argv[:1] == ["imports"] and n == 3 and argv[2].isdigit():
        print("\n".join(imports(argv[1], int(argv[2]))))
    elif argv[:1] == ["listed"] and n >= 3:
        print("\n".join(listed(argv[1], argv[2:])))
    elif argv[:1] == ["gone"] and n >= 3:
        print("\n".join(gone(argv[1], argv[2:])))
    elif argv[:1] == ["handles"] and n == 3:
        print("\n".join(handles(argv[1], argv[2])))
    elif argv[:1] == ["leaked"] and n == 3:
        print("\n".join(leaked(argv[1], argv[2])))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
