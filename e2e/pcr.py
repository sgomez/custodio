#!/usr/bin/python3 -I
"""The judgements of the pcr-* cases (F137, acceptance 5 first part of SPEC.md), as functions of files, so that scripts/test-e2e-pcr.sh can show each one fails on bad
evidence without a container. Each subcommand prints one problem per line and nothing when the evidence is right (exit 0 either way; exit 2 on a bad call).
  pcr.py cases                          the case ids, one per line
  pcr.py enumerate LIST                 "ID<TAB>TYPE" of every key of kind tpm in an owner-call.py list output (what the guest signs with)
  pcr.py extended FIRST EXTENDED        PCRs 0, 7 and 11 (sha256, tpm2_pcrread output) are all there and each differs after the extension
  pcr.py restarted FIRST EXTENDED AFTER the PCRs read after the TPM restart equal the first reading (reset values) and differ from the extended ones
  pcr.py pid OLD NEW                    the service's main pid is a number, not 0, and not the old one
  pcr.py keys LIST_BEFORE LIST_AFTER MODE ID:KEYTYPE...
                                        the keys are listed with kind tpm (modes swtpm and lacking) before and after, with the same set of (id, type, kind) rows,
                                        at least the named ones, and at least two keys of kind tpm
  pcr.py sigs DIR TAG LIST              the signatures of round TAG: for every tpm key of LIST, DIR/out/TAG-ID.{rc,sig,log} exist, the exit code is 0 and `openssl`
                                        verifies the signature against DIR/in/ID.pub.pem (the certificate the module served) over DIR/in/msg.bin
  pcr.py control BEFORE_RC BEFORE_OUT AFTER_RC AFTER_OUT SECRET
                                        the object whose policy is PolicyPCR on PCR 7 unseals before the extension (the secret comes back) and fails with a policy
                                        failure after it
Signing: RSA with SHA256-RSA-PKCS, P-256 with ECDSA-SHA256 in the openssl (DER) format; the mechanisms and their parameters are F134's, not repeated.
"""
import os
import re
import subprocess
import sys

CASES = ["pcr-extended-signs", "pcr-restarted-signs", "pcr-signs-every-key"]
PCRS = (0, 7, 11)
TPM_MODES = ("swtpm", "lacking")


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


def pcr_values(path):
    """{index: hex} from tpm2_pcrread output; None when the file cannot be read."""
    t = text(path)
    if t is None:
        return None
    return {int(m.group(1)): m.group(2).lower() for m in re.finditer(r"^\s+(\d+)\s*:\s*0x([0-9a-fA-F]+)\s*$", t, re.M)}


def both(first, other, name_a, name_b):
    out = []
    a, b = pcr_values(first), pcr_values(other)
    for name, v in ((name_a, a), (name_b, b)):
        if v is None:
            out.append(f"{name}: the PCR reading cannot be read")
    if out:
        return out, None, None
    for name, v in ((name_a, a), (name_b, b)):
        for i in PCRS:
            if i not in v:
                out.append(f"{name}: PCR {i} is not in the reading")
            elif len(v[i]) != 64:
                out.append(f"{name}: PCR {i} is not a sha256 value ({len(v[i])} hex digits)")
    return out, a, b


def extended(first, ext):
    out, a, b = both(first, ext, "first reading", "extended reading")
    if out:
        return out
    return [f"PCR {i} did not change with the extension ({a[i]})" for i in PCRS if a[i] == b[i]]


def restarted(first, ext, after):
    out, a, c = both(first, after, "first reading", "reading after the restart")
    out2, _, b = both(first, ext, "first reading", "extended reading")
    if out or out2:
        return out + [p for p in out2 if p not in out]
    for i in PCRS:
        if c[i] == b[i]:
            out.append(f"PCR {i} after the TPM restart is still the extended value ({c[i]})")
        if c[i] != a[i]:
            out.append(f"PCR {i} after the TPM restart ({c[i]}) is not the value of the first reading ({a[i]}): the TPM was not reset")
    return out


def pid(old, new):
    o, n = (text(old) or "").strip(), (text(new) or "").strip()
    if not o.isdigit() or int(o) == 0:
        return [f"the old main pid {o!r} is not a running service's"]
    if not n.isdigit() or int(n) == 0:
        return [f"the new main pid {n!r} is not a running service's"]
    if o == n:
        return [f"the main pid did not change ({n}): the service was not restarted"]
    return []


def enumerate_keys(path):
    r = rows(path)
    if r is None:
        return None
    return [(x[0], x[1]) for x in r if len(x) == 3 and x[2] == "tpm"]


def keys(before, after, mode, specs):
    if mode not in TPM_MODES:
        return [f"mode {mode!r} has no TPM keys to judge"]
    out = []
    sets = []
    for name, path in (("before", before), ("after", after)):
        r = rows(path)
        if r is None:
            out.append(f"the list {name} the restarts cannot be read")
            continue
        if any(len(x) != 3 for x in r):
            out.append(f"the list {name} the restarts has a line that is not ID<TAB>TYPE<TAB>KIND")
            continue
        sets.append(sorted(tuple(x) for x in r))
        for spec in specs:
            kid, _, kt = spec.rpartition(":")
            mine = [x for x in r if x[0] == kid]
            if len(mine) != 1:
                out.append(f"{kid}: {len(mine)} rows in the list {name} the restarts, expected 1")
                continue
            if mine[0][1] != kt:
                out.append(f"{kid}: key type {mine[0][1]!r} {name} the restarts, expected {kt!r}")
            if mine[0][2] != "tpm":
                out.append(f"{kid}: kind {mine[0][2]!r} {name} the restarts, expected 'tpm' in mode {mode}")
        if len([x for x in r if x[2] == "tpm"]) < 2:
            out.append(f"fewer than two keys of kind tpm are listed {name} the restarts")
    if len(sets) == 2 and sets[0] != sets[1]:
        gone = [x for x in sets[0] if x not in sets[1]]
        new = [x for x in sets[1] if x not in sets[0]]
        out.append(f"the keys listed changed over the restarts: gone {gone}, new {new}")
    return out


def ssl(args, data=None):
    p = subprocess.run(["openssl", *args], input=data, capture_output=True, check=False)
    return p.returncode, p.stderr.decode(errors="replace") + p.stdout.decode(errors="replace")[:200]


def sigs(d, tag, listfile):
    ks = enumerate_keys(listfile)
    if ks is None:
        return [f"{listfile}: cannot be read"]
    if len(ks) < 2:
        return [f"{listfile}: fewer than two keys of kind tpm ({len(ks)}) to sign with"]
    out = []
    msg = os.path.join(d, "in", "msg.bin")
    for kid, kt in ks:
        base = os.path.join(d, "out", f"{tag}-{kid}")
        rc = (text(base + ".rc") or "").strip()
        sig = read(base + ".sig")
        if rc != "0":
            log = (text(base + ".log") or "")
            ckr = re.findall(r"CKR_[A-Z_0-9]+", log)
            out.append(f"{tag}: {kid}: signing exited {rc or 'with no status'}{' ' + ckr[-1] if ckr else ''}")
            continue
        if not sig:
            out.append(f"{tag}: {kid}: no signature")
            continue
        pub = os.path.join(d, "in", f"{kid}.pub.pem")
        if kt == "rsa2048":
            args = ["dgst", "-sha256", "-verify", pub, "-signature", base + ".sig", msg]
        elif kt == "ecdsa-p256":
            args = ["dgst", "-sha256", "-verify", pub, "-signature", base + ".sig", msg]
        else:
            out.append(f"{tag}: {kid}: key type {kt!r} has no signing job")
            continue
        code, t = ssl(args)
        if code != 0 or "Verified OK" not in t:
            out.append(f"{tag}: {kid}: the signature does not verify against the served certificate")
    return out


def control(brc, bout, arc, aout, secret):
    out = []
    b, a = text(bout), text(aout)
    if b is None or a is None or not (brc and arc):
        return ["the control has no evidence (a file is missing)"]
    if brc.strip() != "0" or secret not in b:
        out.append("the PCR-7-policy object did not unseal before the extension, so it proves nothing")
    if arc.strip() == "0":
        out.append("the PCR-7-policy object still unseals after the extension: the extension had no effect on it")
    elif not re.search(r"policy", a, re.I):
        out.append("the PCR-7-policy object failed after the extension, but not with a policy failure: " + " ".join(a.split())[:160])
    if secret in a:
        out.append("the secret came out after the extension")
    return out


def main(argv):
    n = len(argv)
    if argv == ["cases"]:
        print("\n".join(CASES))
    elif argv[:1] == ["enumerate"] and n == 2:
        ks = enumerate_keys(argv[1])
        if ks is None:
            print(f"{argv[1]}: cannot be read", file=sys.stderr)
            return 1
        for k in ks:
            print(*k, sep="\t")
    elif argv[:1] == ["extended"] and n == 3:
        print("\n".join(extended(argv[1], argv[2])))
    elif argv[:1] == ["restarted"] and n == 4:
        print("\n".join(restarted(argv[1], argv[2], argv[3])))
    elif argv[:1] == ["pid"] and n == 3:
        print("\n".join(pid(argv[1], argv[2])))
    elif argv[:1] == ["keys"] and n >= 5:
        print("\n".join(keys(argv[1], argv[2], argv[3], argv[4:])))
    elif argv[:1] == ["sigs"] and n == 4:
        print("\n".join(sigs(argv[1], argv[2], argv[3])))
    elif argv[:1] == ["control"] and n == 6:
        print("\n".join(control(argv[1], argv[2], argv[3], argv[4], argv[5])))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
