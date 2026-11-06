#!/usr/bin/python3 -I
"""The judgements of the fallback-* cases (F138, acceptance 6 of SPEC.md, mode none: kind encrypted-host), as functions of files. Each subcommand prints one
problem per line and nothing when the evidence is right (exit 0 either way; exit 2 on a bad call), so scripts/test-e2e-fallback.sh can show each one fails on bad evidence.
The kind is compared by exact value, never by a substring: "tpm" and "encrypted-tpm" are other kinds.
  fallback.py import FILE ID KEYTYPE   the CLI output of `custodio import --id ID`: says it imported ID as KEYTYPE and has exactly one Storage line, of kind encrypted-host
  fallback.py why FILE...              the Storage line of each import output says the key is weaker than a TPM key and the reason: this machine has no TPM
  fallback.py api FILE ID:KEYTYPE...   owner-call.py list output ("ID<TAB>TYPE<TAB>KIND"): each ID once, with KEYTYPE and kind encrypted-host
  fallback.py cli FILE ID:KEYTYPE...   `custodio list` output: the block of each ID once, with `type: KEYTYPE` and `kind: encrypted-host`
"""
import re
import sys

KIND = "encrypted-host"


def read(path):
    return open(path, encoding="utf-8", errors="replace").read().replace("\r", "")


def storage_lines(path):
    # the Storage text may continue on the lines that follow it, up to an empty line or the reminder to delete the original
    lines = read(path).split("\n")
    found = []
    for i, ln in enumerate(lines):
        if ln.startswith("Storage:"):
            text = ln
            for nxt in lines[i + 1:]:
                if not nxt or nxt.startswith(("Now delete", "Storage:")):
                    break
                text += " " + nxt.strip()
            found.append(text)
    return found


def import_problems(path, key_id, key_type):
    out = []
    if f"Imported key '{key_id}' ({key_type})." not in read(path).split("\n"):
        out.append(f"{path}: no line \"Imported key '{key_id}' ({key_type}).\"")
    storage = storage_lines(path)
    if len(storage) != 1:
        out.append(f"{path}: {len(storage)} Storage lines, expected 1")
    elif not storage[0].startswith(f"Storage: {KIND}. "):
        out.append(f"{path}: the Storage line is {storage[0]!r}, expected kind {KIND}")
    return out


def why_problems(paths):
    out = []
    for path in paths:
        storage = storage_lines(path)
        if len(storage) != 1:
            out.append(f"{path}: {len(storage)} Storage lines, expected 1")
            continue
        if not re.search(r"\bweaker than a TPM key\b", storage[0]):
            out.append(f"{path}: the Storage text does not say the key is weaker than a TPM key")
        if "no TPM" not in storage[0]:
            out.append(f"{path}: the Storage text does not give the reason (no TPM)")
    return out


def expected(specs):
    pairs = []
    for spec in specs:
        key_id, _, key_type = spec.rpartition(":")
        if not key_id or not key_type:
            sys.exit(f"fallback: bad ID:KEYTYPE '{spec}'")
        pairs.append((key_id, key_type))
    return pairs


def api_problems(path, specs):
    rows = [ln.split("\t") for ln in read(path).split("\n") if ln]
    if any(len(r) != 3 for r in rows):
        return [f"{path}: a line is not ID<TAB>TYPE<TAB>KIND"]
    out = []
    for key_id, key_type in expected(specs):
        mine = [r for r in rows if r[0] == key_id]
        if len(mine) != 1:
            out.append(f"{path}: {len(mine)} rows for {key_id}, expected 1")
            continue
        if mine[0][1] != key_type:
            out.append(f"{key_id}: key type {mine[0][1]!r}, expected {key_type!r}")
        if mine[0][2] != KIND:
            out.append(f"{key_id}: kind {mine[0][2]!r}, expected {KIND!r}")
    return out


def cli_problems(path, specs):
    blocks, cur = {}, None
    for ln in read(path).split("\n"):
        m = re.fullmatch(r"id: (.*)", ln)
        if m:
            cur = m.group(1)
            blocks.setdefault(cur, []).append({})
        elif cur is not None:
            m = re.fullmatch(r"  (type|kind): (.*)", ln)
            if m:
                blocks[cur][-1][m.group(1)] = m.group(2)
    out = []
    for key_id, key_type in expected(specs):
        mine = blocks.get(key_id, [])
        if len(mine) != 1:
            out.append(f"{path}: {len(mine)} blocks for {key_id}, expected 1")
            continue
        if mine[0].get("type") != key_type:
            out.append(f"{key_id}: type {mine[0].get('type')!r}, expected {key_type!r}")
        if mine[0].get("kind") != KIND:
            out.append(f"{key_id}: kind {mine[0].get('kind')!r}, expected {KIND!r}")
    return out


def main(argv):
    if len(argv) == 4 and argv[0] == "import":
        problems = import_problems(*argv[1:])
    elif len(argv) >= 2 and argv[0] == "why":
        problems = why_problems(argv[1:])
    elif len(argv) >= 3 and argv[0] == "api":
        problems = api_problems(argv[1], argv[2:])
    elif len(argv) >= 3 and argv[0] == "cli":
        problems = cli_problems(argv[1], argv[2:])
    else:
        sys.exit(__doc__)
    for p in problems:
        print(p)
    return 0


sys.exit(main(sys.argv[1:]))
