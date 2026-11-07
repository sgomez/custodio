#!/usr/bin/python3 -I
"""Reading of the service's records and judgements of the tpm-dup-* cases (F136), files in, problems out (one per line; no output is a pass).

usage:
  tpmdup.py scan STATE OUT               every record under STATE/<uid>/<id>: prints `uid<TAB>id<TAB>kind<TAB>parent-name-hex`; for a TPM key writes
                                         OUT/<uid>-<id>/k.pub and k.priv (the TPM2B_PUBLIC / TPM2B_PRIVATE `tpm2_load -u / -r` read)
  tpmdup.py inventory TSV MODE ID...     the scan has each ID once, as a `tpm` key when MODE is swtpm or lacking, and at least len(IDs) `tpm` records
  tpmdup.py parent STORED_HEX NAMEFILE   the name of the parent the guest made (a binary file) is the one in the record
  tpmdup.py samepub OUT1 OUT2            two `tpm2_readpublic` outputs of parents are one template (same but for the name and the unique field)
  tpmdup.py authpolicy OUT               a `tpm2_readpublic` output of a key has no authorization policy
  tpmdup.py duplicate RC OUT             `tpm2_duplicate` failed with TPM_RC_POLICY_FAIL (0x99D: session 1)
  tpmdup.py other-tpm RC OUT             `tpm2_load` under another TPM's parent failed with an integrity error
  tpmdup.py succeeded WHAT RC OUT        the control command WHAT exited 0
"""
import os
import re
import sys

MAGIC = b"CUSTODIO"
VERSION = 1
KIND_TPM = 1
KIND_NAMES = {1: "tpm", 2: "encrypted-tpm", 3: "encrypted-host"}  # the tags of crates/custodiod/src/store/kind.rs
TPM_MODES = ("swtpm", "lacking")
POLICY_FAIL = re.compile(r"0x99d", re.I)


class Bad(Exception):
    pass


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise Bad("record is truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def num(self, n):
        return int.from_bytes(self.take(n), "big")

    def sized(self, width):
        """A length-prefixed field, with its size field when width is negative (a TPM2B)."""
        n = self.num(abs(width))
        body = self.take(n)
        return (n.to_bytes(abs(width), "big") + body) if width < 0 else body


def parse(data):
    """A record as crates/custodiod/src/store/record.rs writes it; a dict, with the TPM parts for a TPM key."""
    r = Reader(data)
    if r.take(8) != MAGIC:
        raise Bad("not a record (bad magic)")
    if r.num(1) != VERSION:
        raise Bad("unknown record version")
    tag = r.num(1)
    if tag not in KIND_NAMES:
        raise Bad(f"unknown kind tag {tag}")
    rec = {"kind": KIND_NAMES[tag], "owner": r.num(4)}
    rec["id"] = r.sized(1).decode("ascii", "replace")
    rec["certificate"] = r.sized(4)
    protected = Reader(r.sized(4))
    if r.pos != len(data):
        raise Bad("record has trailing bytes")
    if tag == KIND_TPM:
        rec["parent_name"] = protected.sized(2)
        rec["pub"] = protected.sized(-2)
        rec["priv"] = protected.sized(-2)
        if protected.pos != len(protected.data):
            raise Bad("stored TPM key has trailing bytes")
    return rec


def scan(state, out):
    rows = []
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
                continue  # not a record (the cases of noplain-* judge the files)
            rec = parse(data)
            rows.append((uid, rec["id"], rec["kind"], rec.get("parent_name", b"").hex()))
            if rec["kind"] == "tpm":
                kd = os.path.join(out, f"{uid}-{rec['id']}")
                os.makedirs(kd, exist_ok=True)
                with open(os.path.join(kd, "k.pub"), "wb") as f:
                    f.write(rec["pub"])
                with open(os.path.join(kd, "k.priv"), "wb") as f:
                    f.write(rec["priv"])
    return rows


def inventory(tsv, mode, ids):
    rows = [line.rstrip("\n").split("\t") for line in open(tsv) if line.strip()]
    if any(len(r) != 4 for r in rows):
        return ["the scan has a malformed row"]
    problems = []
    tpm = [r for r in rows if r[2] == "tpm"]
    for i in ids:
        mine = [r for r in rows if r[1] == i]
        if len(mine) != 1:
            problems.append(f"{len(mine)} records with the id {i}, expected 1")
        elif mode in TPM_MODES and mine[0][2] != "tpm":
            problems.append(f"{i} has the kind {mine[0][2]} in mode {mode}, expected tpm")
    if mode in TPM_MODES and len(tpm) < len(ids):
        problems.append(f"{len(tpm)} records of kind tpm, expected at least {len(ids)}")
    return problems


def parent(stored_hex, namefile):
    got = open(namefile, "rb").read().hex()
    if not stored_hex:
        return ["the record holds no parent name"]
    return [] if got == stored_hex else [f"the parent made here has the name {got}, the record holds {stored_hex}"]


def fields(text):
    """`key: value` lines of tpm2_readpublic: key -> value of the first such line."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z][A-Za-z0-9 ]*?):\s*(.*)$", line)
        if m and m.group(1) not in out:
            out[m.group(1)] = m.group(2).strip()
    return out


def is_public_area(text):
    f = fields(text)
    return bool(f.get("name")) and "attributes" in f and "type" in f


def samepub(a, b):
    ta, tb = open(a).read(), open(b).read()
    if not (is_public_area(ta) and is_public_area(tb)):
        return ["an output is not a public area"]
    drop = ("name", "qualified name", "x", "y", "rsa")  # the name follows from the unique field, which is the TPM's

    def keep(t):
        return [ln.strip() for ln in t.splitlines() if ln.strip() and re.sub(r":.*", "", ln.strip()) not in drop]

    return [] if keep(ta) == keep(tb) else ["the parents of the two TPMs are not made from one template"]


def authpolicy(path):
    text = open(path).read()
    if not is_public_area(text):
        return [f"not the public area of a key: {text.strip()[:200]}"]
    pol = fields(text).get("authorization policy")
    return [f"authorization policy: {pol}"] if pol else []


def duplicate(rc, path):
    text = open(path).read()
    if rc == 0:
        return ["tpm2_duplicate succeeded"]
    return [] if POLICY_FAIL.search(text) else [f"tpm2_duplicate failed, but not with TPM_RC_POLICY_FAIL (0x99D): {text.strip()[-300:]}"]


def other_tpm(rc, path):
    text = open(path).read()
    if rc == 0:
        return ["tpm2_load under another TPM's parent succeeded"]
    return [] if "integrity" in text.lower() else [f"the load failed, but not with an integrity error: {text.strip()[-300:]}"]


def succeeded(what, rc, path):
    return [] if rc == 0 else [f"{what} exited {rc}: {open(path).read().strip()[-300:]}"]


def main(argv):
    try:
        cmd, args = argv[1], argv[2:]
        if cmd == "scan":
            for r in scan(args[0], args[1]):
                print("\t".join(r))
            return 0
        problems = {
            "inventory": lambda: inventory(args[0], args[1], args[2:]),
            "parent": lambda: parent(args[0], args[1]),
            "samepub": lambda: samepub(args[0], args[1]),
            "authpolicy": lambda: authpolicy(args[0]),
            "duplicate": lambda: duplicate(int(args[0]), args[1]),
            "other-tpm": lambda: other_tpm(int(args[0]), args[1]),
            "succeeded": lambda: succeeded(args[0], int(args[1]), args[2]),
        }[cmd]()
    except (IndexError, KeyError):
        print(__doc__, file=sys.stderr)
        return 2
    except (Bad, OSError, ValueError) as e:
        print(f"tpmdup: {e}")
        return 1
    for p in problems:
        print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
