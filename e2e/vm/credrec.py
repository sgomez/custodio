#!/usr/bin/env python3
"""Takes the stored credential of an encrypted-tpm key out of the service's state directory (F161).

  credrec.py STATE ID OUT   finds the record of key ID under STATE/<uid>/, requires kind encrypted-tpm, writes its raw credential to OUT.

Exit 0 on success; 1 with one line on stderr when the key has no record, two records, another kind, or an unreadable record.
The record layout is the one of crates/custodiod/src/store/record.rs: "CUSTODIO" version(1) kind(1) owner(4) id(1+n) certificate(4+n) protected(4+n);
for an encrypted key the protected part is the credential itself.
"""
import os
import sys

MAGIC = b"CUSTODIO"
KINDS = {1: "tpm", 2: "encrypted-tpm", 3: "encrypted-host"}


def parse(data):
    pos = 0

    def take(n):
        nonlocal pos
        if n < 0 or pos + n > len(data):
            raise ValueError("record is truncated")
        pos += n
        return data[pos - n:pos]

    if take(8) != MAGIC:
        raise ValueError("bad magic")
    if take(1) != b"\x01":
        raise ValueError("unknown record version")
    kind = KINDS.get(take(1)[0])
    take(4)
    key_id = take(take(1)[0]).decode("ascii", "replace")
    take(int.from_bytes(take(4), "big"))
    cred = take(int.from_bytes(take(4), "big"))
    if pos != len(data):
        raise ValueError("trailing bytes")
    return key_id, kind, cred


def main(argv):
    if len(argv) != 3:
        print("usage: credrec.py STATE ID OUT", file=sys.stderr)
        return 1
    state, want, out = argv
    found = []
    for uid in sorted(os.listdir(state)):
        d = os.path.join(state, uid)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if not os.path.isfile(p) or os.path.islink(p):
                continue
            with open(p, "rb") as f:
                data = f.read()
            if not data.startswith(MAGIC):
                continue
            try:
                key_id, kind, cred = parse(data)
            except ValueError as e:
                print(f"credrec: {p}: {e}", file=sys.stderr)
                return 1
            if key_id == want:
                found.append((p, kind, cred))
    if len(found) != 1:
        print(f"credrec: {len(found)} records for key {want} under {state}, expected 1", file=sys.stderr)
        return 1
    p, kind, cred = found[0]
    if kind != "encrypted-tpm":
        print(f"credrec: key {want} has kind {kind}, not encrypted-tpm ({p})", file=sys.stderr)
        return 1
    with open(out, "wb") as f:
        f.write(cred)
    return 0


sys.exit(main(sys.argv[1:]))
