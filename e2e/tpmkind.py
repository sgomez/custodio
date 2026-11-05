#!/usr/bin/python3 -I
"""The judgements of the tpm-kind-* cases (F133, acceptance 1 of SPEC.md), as functions of files. Each subcommand prints one problem per line and
nothing when the evidence is right (exit 0 either way; exit 2 on a bad call), so tpmkind-selftest.sh can show each one fails on bad evidence.
The kind is compared by exact value "tpm" (the wire name), never by a substring: "encrypted-tpm" and "encrypted-host" are other kinds.
  tpmkind.py import FILE ID KEYTYPE      the CLI output of `custodio import --id ID`: says it imported ID as KEYTYPE and "Storage: tpm." exactly once
  tpmkind.py api FILE ID:KEYTYPE...      owner-call.py list output ("ID<TAB>TYPE<TAB>KIND"): each ID once, with KEYTYPE and kind tpm
  tpmkind.py cli FILE ID:KEYTYPE...      `custodio list` output: the block of each ID once, with `type: KEYTYPE` and `kind: tpm`
  tpmkind.py journal FILE ID...          `journalctl -o json` rows: per ID exactly one import entry of custodio.service, outcome stored, kind tpm
"""
import json
import re
import sys

TPM = "tpm"
UNIT = "custodio.service"


def import_problems(path, key_id, key_type):
    lines = open(path, encoding="utf-8", errors="replace").read().replace("\r", "").split("\n")
    out = []
    if f"Imported key '{key_id}' ({key_type})." not in lines:
        out.append(f"{path}: no line \"Imported key '{key_id}' ({key_type}).\"")
    storage = [ln for ln in lines if ln.startswith("Storage:")]
    if len(storage) != 1:
        out.append(f"{path}: {len(storage)} Storage lines, expected 1")
    elif not re.fullmatch(r"Storage: tpm\. The key is in the TPM and cannot be copied out of it\.", storage[0]):
        out.append(f"{path}: the Storage line is {storage[0]!r}, expected kind tpm")
    if any("weaker" in ln for ln in lines):
        out.append(f"{path}: the output speaks of a weaker kind")
    return out


def expected(specs):
    pairs = []
    for spec in specs:
        key_id, _, key_type = spec.rpartition(":")
        if not key_id or not key_type:
            sys.exit(f"tpmkind: bad ID:KEYTYPE '{spec}'")
        pairs.append((key_id, key_type))
    return pairs


def api_problems(path, specs):
    rows = [ln.split("\t") for ln in open(path, encoding="utf-8").read().split("\n") if ln]
    out = []
    if any(len(r) != 3 for r in rows):
        return [f"{path}: a line is not ID<TAB>TYPE<TAB>KIND"]
    for key_id, key_type in expected(specs):
        mine = [r for r in rows if r[0] == key_id]
        if len(mine) != 1:
            out.append(f"{path}: {len(mine)} rows for {key_id}, expected 1")
            continue
        if mine[0][1] != key_type:
            out.append(f"{key_id}: key type {mine[0][1]!r}, expected {key_type!r}")
        if mine[0][2] != TPM:
            out.append(f"{key_id}: kind {mine[0][2]!r}, expected {TPM!r}")
    return out


def cli_problems(path, specs):
    blocks, cur = {}, None
    for ln in open(path, encoding="utf-8").read().split("\n"):
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
        if mine[0].get("kind") != TPM:
            out.append(f"{key_id}: kind {mine[0].get('kind')!r}, expected {TPM!r}")
    return out


def journal_problems(path, ids):
    with open(path, encoding="utf-8") as f:
        rows = [json.loads(ln) for ln in f if ln.strip()]
    out = []
    for key_id in ids:
        mine = [r for r in rows if r.get("_SYSTEMD_UNIT") == UNIT and r.get("CUSTODIO_OPERATION") == "import" and r.get("CUSTODIO_KEY_ID") == key_id]
        if len(mine) != 1:
            out.append(f"{key_id}: {len(mine)} import entries of {UNIT}, expected 1")
            continue
        e = mine[0]
        if e.get("CUSTODIO_OUTCOME") != "stored":
            out.append(f"{key_id}: outcome {e.get('CUSTODIO_OUTCOME')!r}, expected 'stored'")
        if e.get("CUSTODIO_STORAGE_KIND") != TPM:
            out.append(f"{key_id}: CUSTODIO_STORAGE_KIND {e.get('CUSTODIO_STORAGE_KIND')!r}, expected {TPM!r}")
    return out


def main(argv):
    if len(argv) >= 4 and argv[0] == "import" and len(argv) == 4:
        problems = import_problems(*argv[1:])
    elif len(argv) >= 3 and argv[0] == "api":
        problems = api_problems(argv[1], argv[2:])
    elif len(argv) >= 3 and argv[0] == "cli":
        problems = cli_problems(argv[1], argv[2:])
    elif len(argv) >= 3 and argv[0] == "journal":
        problems = journal_problems(argv[1], argv[2:])
    else:
        sys.exit(__doc__)
    for p in problems:
        print(p)
    return 0


sys.exit(main(sys.argv[1:]))
