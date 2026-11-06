#!/usr/bin/python3 -I
"""Judgements of the noplain-* cases (F135), files in, problems out (one per line; no output is a pass). Nothing here reads a key into the output.

usage:
  noplain.py kind LIST MODE ID:TYPE...   LIST (ListKeys rows ID<TAB>TYPE<TAB>KIND) has each ID once, with its type and the kind MODE gives
  noplain.py files DIR                   no file under DIR is an unencrypted private key (PEM header, or read by openssl without a password)
  noplain.py list DIR                    the files under DIR with their sizes (a log for the reader)
"""
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

KINDS = {"swtpm": ("tpm", "tpm"), "none": ("encrypted-host",) * 2, "lacking": ("tpm", "tpm")}  # mode -> (RSA kind, EC kind), as sign.py
KEYTYPES = {"rsa": "rsa2048", "ec": "ecdsa-p256"}
# a PEM private key that is not encrypted: PKCS#8, PKCS#1, SEC1, DSA...
PLAIN_HEADER = re.compile(rb"-----BEGIN (?!ENCRYPTED )[A-Z0-9 ]*PRIVATE KEY-----")
# the reads that must fail on a protected file: an explicit wrong password, no stdin, so an encrypted PEM can never prompt
READS = [("pkey", f) for f in ("PEM", "DER")] + [("rsa", f) for f in ("PEM", "DER")] + [("ec", f) for f in ("PEM", "DER")]


def run(args):
    try:
        r = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False)
    except subprocess.TimeoutExpired:
        return None
    return r


def files(root):
    out = []
    for d, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        for n in sorted(names):
            p = os.path.join(d, n)
            if os.path.isfile(p) and not os.path.islink(p):
                out.append(p)
    return out


def probe(p, cmd, form):
    if cmd == "pkcs12":
        r = run(["openssl", "pkcs12", *form, "-in", p, "-passin", "pass:", "-nocerts", "-noenc"])
        if r is not None and r.returncode == 0 and b"PRIVATE KEY" in r.stdout:
            return f"{p}: openssl pkcs12 reads a private key from it with an empty password"
        return None
    r = run(["openssl", cmd, "-in", p, "-inform", form, "-passin", "pass:wrong-password", "-noout"])
    if r is None:
        return f"{p}: openssl {cmd} {form} did not finish (a prompt?)"
    if r.returncode == 0:
        return f"{p}: openssl {cmd} {form} reads it as a {form} private key without a password"
    return None


def file_problems(root):
    paths = files(root)
    problems = []
    for p in paths:
        with open(p, "rb") as f:
            if PLAIN_HEADER.search(f.read()):
                problems.append(f"{p}: a PEM private key that is not encrypted")
    # every (file, read) pair is independent: run them all at once
    jobs = [(p, c, f) for p in paths for c, f in READS] + [(p, "pkcs12", leg) for p in paths for leg in ([], ["-legacy"])]
    with ThreadPoolExecutor(max_workers=16) as ex:
        problems += [r for r in ex.map(lambda j: probe(*j), jobs) if r]
    return problems


def kind_problems(path, mode, specs):
    if mode not in KINDS:
        sys.exit(f"noplain: unknown mode {mode}")
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
    if argv[:1] == ["kind"] and len(argv) >= 4:
        print("\n".join(kind_problems(argv[1], argv[2], argv[3:])))
    elif argv[:1] == ["files"] and len(argv) == 2:
        print("\n".join(file_problems(argv[1])))
    elif argv[:1] == ["list"] and len(argv) == 2:
        for p in files(argv[1]):
            print(f"{os.path.getsize(p):8d} {p}")
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
