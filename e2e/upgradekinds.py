#!/usr/bin/python3 -I
"""The judgements of the upgrade-kinds-* cases (F141, acceptance 5 of SPEC.md, second part), as functions of files, so that scripts/test-e2e-upgradekinds.sh can show each
one fails on bad evidence without a container. Each subcommand prints one problem per line and nothing when the evidence is right (exit 0 either way; exit 2 on a bad call).
The kind of every key is fixed by the mode of the run and judged by exact value: swtpm and lacking give "tpm" (lacking: SPEC_DEVIATIONS.md F134), none gives "encrypted-host".
A run in which every key got the same wrong kind therefore fails, as does one in which the kinds only stayed equal.
The keys are the ones upgrade-accts.sh seeds: alice holds ec1 and rsa1, bob holds bobonly and rsa1 (another key under the same id).
A listing directory holds, for each user, USER.api (owner-call.py list: "ID<TAB>TYPE<TAB>KIND") and USER.cli (`custodio list`).
  upgradekinds.py cases
  upgradekinds.py kind MODE                     the kind of the mode
  upgradekinds.py listing MODE DIR              each user's API list and CLI list hold exactly that user's keys, once each, with the type of the key and the kind of the mode
  upgradekinds.py kept MODE BEFORE AFTER        both directories are as `listing` wants, and the (user, id, type, kind) rows of the API and of the CLI are the same in both
  upgradekinds.py journal MODE JSON ALICE_UID BOB_UID REQUESTS
                                                JSON (journalctl -o json after the cursor of the round): exactly REQUESTS entries (the Sign calls the agents answered), every one a
                                                sign entry of the mode's kind for a key of the user whose uid it names, and each of the four keys has at least one
The certificates are not compared here: acct_after_problems (upgrade-accts-lib.sh) compares them byte for byte before and after the upgrade.
"""
import json
import re
import sys

CASES = ["upgrade-kinds-before", "upgrade-kinds-kept", "upgrade-kinds-signs", "upgrade-kinds-tpmbound"]
KINDS = {"swtpm": "tpm", "lacking": "tpm", "none": "encrypted-host", "vm-full": "tpm", "vm-lacking": "encrypted-tpm"}  # vm-*: a VM run (F163)
KEYS = {"alice": {"ec1": "ecdsa-p256", "rsa1": "rsa2048"}, "bob": {"bobonly": "rsa2048", "rsa1": "rsa2048"}}


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().replace("\r", "")
    except OSError:
        return None


def kind_of(mode):
    if mode not in KINDS:
        sys.exit(f"upgradekinds: unknown mode {mode!r} (swtpm, none or lacking)")
    return KINDS[mode]


def api_rows(path):
    """(rows, problems): the (id, type, kind) rows of an owner-call.py list file."""
    t = read(path)
    if t is None or not t.strip():
        return None, [f"{path}: missing or empty"]
    rows = []
    for ln in t.split("\n"):
        if not ln:
            continue
        f = ln.split("\t")
        if len(f) != 3:
            return None, [f"{path}: a line is not ID<TAB>TYPE<TAB>KIND: {ln!r}"]
        rows.append(tuple(f))
    return rows, []


def cli_rows(path):
    """(rows, problems): the (id, type, kind) of each block of a `custodio list` file; a block lacking type or kind has None there."""
    t = read(path)
    if t is None or not t.strip():
        return None, [f"{path}: missing or empty"]
    blocks = []
    for ln in t.split("\n"):
        m = re.fullmatch(r"id: (.*)", ln)
        if m:
            blocks.append({"id": m.group(1)})
            continue
        m = re.fullmatch(r"  (type|kind): (.*)", ln)
        if m and blocks:
            blocks[-1].setdefault(m.group(1), m.group(2))
    return [(b["id"], b.get("type"), b.get("kind")) for b in blocks], []


def rows_problems(label, rows, user, kind):
    out = []
    want = KEYS[user]
    for key_id, key_type in sorted(want.items()):
        mine = [r for r in rows if r[0] == key_id]
        if len(mine) != 1:
            out.append(f"{label}: {len(mine)} rows for {user}'s {key_id}, expected 1")
            continue
        if mine[0][1] != key_type:
            out.append(f"{label}: {user}'s {key_id} has type {mine[0][1]!r}, expected {key_type!r}")
        if mine[0][2] != kind:
            out.append(f"{label}: {user}'s {key_id} has kind {mine[0][2]!r}, expected {kind!r}")
    for r in rows:
        if r[0] not in want:
            out.append(f"{label}: {user} is shown {r[0]!r}, which is not one of his or her keys")
    return out


def listing(mode, d):
    kind = kind_of(mode)
    out = []
    for user in KEYS:
        for ext, reader in (("api", api_rows), ("cli", cli_rows)):
            path = f"{d}/{user}.{ext}"
            rows, bad = reader(path)
            out += bad
            if rows is not None:
                out += rows_problems(path, rows, user, kind)
    return out


def kept(mode, before, after):
    out = [f"before: {p}" for p in listing(mode, before)] + [f"after: {p}" for p in listing(mode, after)]
    for user in KEYS:
        for ext, reader in (("api", api_rows), ("cli", cli_rows)):
            b, _ = reader(f"{before}/{user}.{ext}")
            a, _ = reader(f"{after}/{user}.{ext}")
            if b is None or a is None:
                continue
            if sorted(b, key=str) != sorted(a, key=str):
                out.append(f"{user}.{ext}: the rows changed in the upgrade: {sorted(b, key=str)} -> {sorted(a, key=str)}")
    return out


def journal(mode, path, alice_uid, bob_uid, requests):
    kind = kind_of(mode)
    t = read(path)
    if t is None:
        return [f"{path}: cannot be read"]
    if not re.fullmatch(r"[0-9]+", requests):
        return [f"requests {requests!r} is not a number"]
    es = [e for e in (json.loads(ln) for ln in t.split("\n") if ln.strip()) if "CUSTODIO_OPERATION" in e]
    uids = {alice_uid: "alice", bob_uid: "bob"}
    out = []
    if len(es) != int(requests):
        out.append(f"{path}: {len(es)} entries, expected {requests} (one per Sign call the agents answered)")
    seen = set()
    for e in es:
        key, uid = e.get("CUSTODIO_KEY_ID"), e.get("CUSTODIO_UID")
        if e.get("CUSTODIO_OPERATION") != "sign":
            out.append(f"{path}: an entry for {key!r} has operation {e.get('CUSTODIO_OPERATION')!r}, expected 'sign'")
        if e.get("CUSTODIO_STORAGE_KIND") != kind:
            out.append(f"{path}: the entry for {key!r} (uid {uid}) has kind {e.get('CUSTODIO_STORAGE_KIND')!r}, expected {kind!r}")
        user = uids.get(uid)
        if user is None or key not in KEYS[user]:
            out.append(f"{path}: an entry for {key!r} of uid {uid!r}, which is none of the seeded keys")
        else:
            seen.add((user, key))
    for user, keys in KEYS.items():
        for key in keys:
            if (user, key) not in seen:
                out.append(f"{path}: no entry for {user}'s {key}")
    return out


def main(argv):
    n = len(argv)
    if argv[:1] == ["cases"] and n == 1:
        print("\n".join(CASES))
        return 0
    if argv[:1] == ["kind"] and n == 2:
        print(kind_of(argv[1]))
        return 0
    if argv[:1] == ["keys"] and n == 2 and argv[1] in KEYS:
        print("\n".join(KEYS[argv[1]]))
        return 0
    if argv[:1] == ["listing"] and n == 3:
        problems = listing(argv[1], argv[2])
    elif argv[:1] == ["kept"] and n == 4:
        problems = kept(argv[1], argv[2], argv[3])
    elif argv[:1] == ["journal"] and n == 6:
        problems = journal(argv[1], argv[2], argv[3], argv[4], argv[5])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    for p in problems:
        print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
