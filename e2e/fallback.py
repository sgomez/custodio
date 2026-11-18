#!/usr/bin/python3 -I
"""The judgements of the fallback-* cases (F138, acceptance 6 of SPEC.md, mode none: kind encrypted-host), as functions of files. Each subcommand prints one
problem per line and nothing when the evidence is right (exit 0 either way; exit 2 on a bad call), so scripts/test-e2e-fallback.sh can show each one fails on bad evidence.
The kind is compared by exact value, never by a substring: "tpm" and "encrypted-tpm" are other kinds.
  fallback.py import FILE ID KEYTYPE   the CLI output of `custodio import --id ID`: exactly one key line, of ID as KEYTYPE with kind encrypted-host
  fallback.py why FILE...              the key line of each import output is a warning (warn) with one note under it
  fallback.py api FILE ID:KEYTYPE...   owner-call.py list output ("ID<TAB>TYPE<TAB>KIND"): each ID once, with KEYTYPE and kind encrypted-host
  fallback.py cli FILE ID:KEYTYPE...   `custodio list` output: the row of each ID once, with the type KEYTYPE and the kind encrypted-host
F161: `fallback.py --mode lacking|full SUBCOMMAND ...` judges a VM run. lacking: kind encrypted-tpm, and `why` wants the warning and its note.
full: kind tpm for every key and `why` wants ok with no note. No --mode (or --mode none) is the container run above.
"""
import re
import sys

KIND = "encrypted-host"
MODE = "none"


def read(path):
    return open(path, encoding="utf-8", errors="replace").read().replace("\r", "")


# The key lines of `custodio import` output, read by layout (crates/custodio-cli/src/lib.rs, write_imported): "WORD  ID  TYPE  KIND" with WORD ok or warn,
# then the notes under it (indented 6 spaces). The words of a note are not judged, only that it is there.
KEY_LINE = re.compile(r"(ok|warn) +(\S+)  +(\S+)  +(\S+)")


def key_lines(text):
    lines = text.replace("\r", "").split("\n")
    found = []
    for i, ln in enumerate(lines):
        m = KEY_LINE.fullmatch(ln)
        if not m:
            continue
        notes = []
        for nxt in lines[i + 1:]:
            if not nxt.startswith("      ") or not nxt.strip():
                break
            notes.append(nxt.strip())
        found.append({"word": m[1], "id": m[2], "type": m[3], "kind": m[4], "notes": notes})
    return found


def one_key(path):
    keys = key_lines(read(path))
    if len(keys) != 1:
        return None, [f"{path}: {len(keys)} key lines, expected 1"]
    return keys[0], []


def import_problems(path, key_id, key_type):
    key, out = one_key(path)
    if key is None:
        return out
    if (key["id"], key["type"]) != (key_id, key_type):
        out.append(f"{path}: the key line is of {key['id']!r} as {key['type']!r}, expected {key_id!r} as {key_type!r}")
    if key["kind"] != KIND:
        out.append(f"{path}: the kind is {key['kind']!r}, expected {KIND}")
    return out


def why_problems(paths):
    out = []
    for path in paths:
        key, problems = one_key(path)
        out += problems
        if key is None:
            continue
        if MODE == "full":
            if key["word"] != "ok" or key["notes"]:
                out.append(f"{path}: the key line is {key['word']!r} with {len(key['notes'])} notes, but the key is in the TPM")
            continue
        if key["word"] != "warn":
            out.append(f"{path}: the key line says {key['word']!r}, not warn: it does not say the key is weaker")
        if len(key["notes"]) != 1:
            out.append(f"{path}: {len(key['notes'])} notes under the key line, expected 1 saying who can use the key")
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
    blocks = {}
    for ln in read(path).split("\n"):
        if not ln or ln.startswith("You have no keys"):
            break  # the rows end at the blank line before the note
        f = re.split(r"  +", ln)
        if len(f) >= 3:
            blocks.setdefault(f[0], []).append({"type": f[1], "kind": f[2]})
    out = []
    for key_id, key_type in expected(specs):
        mine = blocks.get(key_id, [])
        if len(mine) != 1:
            out.append(f"{path}: {len(mine)} rows for {key_id}, expected 1")
            continue
        if mine[0].get("type") != key_type:
            out.append(f"{key_id}: type {mine[0].get('type')!r}, expected {key_type!r}")
        if mine[0].get("kind") != KIND:
            out.append(f"{key_id}: kind {mine[0].get('kind')!r}, expected {KIND!r}")
    return out


def main(argv):
    global KIND, MODE
    if argv[:1] == ["--mode"] and len(argv) >= 2:
        if argv[1] not in ("none", "full", "lacking"):
            sys.exit(f"fallback: unknown mode {argv[1]!r}")
        MODE = argv[1]
        KIND = {"none": KIND, "full": "tpm", "lacking": "encrypted-tpm"}[MODE]
        argv = argv[2:]
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
