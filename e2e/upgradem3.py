#!/usr/bin/python3 -I
"""The judgements of the upgrade-m3-* cases (F142, acceptance 9 of SPEC.md), as functions of files, so that scripts/test-e2e-m3.sh can show each one fails on bad evidence
without a container. Each subcommand prints one problem per line and nothing when the evidence is right (exit 0 either way; exit 2 on a bad call).
The keys are the four the M3 build is given: alice holds rsa1 and ec1, bob holds rsa1 (the same id under another owner) and bobonly.
A state snapshot is "RELATIVE-PATH<TAB>SHA256" per regular file under the state directory (the path is UID/FILE). A listing directory holds, for each user, USER.api
(owner-call.py list: "ID<TAB>TYPE<TAB>KIND" per key), USER.cli (`custodio list`) and the exit status of each in USER.api.rc and USER.cli.rc.
  upgradem3.py cases
  upgradem3.py seeded ALICE_UID BOB_UID BEFORE        before the upgrade every seeded key has its pair of old files (UID/ID and UID/ID-cert)
  upgradem3.py purged ALICE_UID BOB_UID BEFORE AFTER  after the upgrade none of the old paths and none of the old files' sha256 is left, and no file is named like a seeded id
                                                      or like its -cert file under any uid
  upgradem3.py empty DIR                              both accounts' API and CLI listings succeeded and show none of the seeded ids
  upgradem3.py journal ALICE_UID BOB_UID JSON         JSON (journalctl -o json after the cursor taken before the install): the purge entries are exactly the seeded (owner uid, id)
                                                      pairs, once each, with no caller
  upgradem3.py reimport ALICE_UID BOB_UID DIR         every import ended with status 0 (DIR/import/USER-ID.rc) and both accounts list exactly their own ids (DIR as for `empty`)
"""
import json
import re
import sys

CASES = ["upgrade-m3-state-purged", "upgrade-m3-list-empty", "upgrade-m3-journal-purge", "upgrade-m3-reimport"]
KEYS = {"alice": ["ec1", "rsa1"], "bob": ["bobonly", "rsa1"]}


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().replace("\r", "")
    except OSError:
        return None


def snapshot(path):
    """({relative path: sha256}, problems)"""
    t = read(path)
    if t is None:
        return None, [f"{path}: cannot be read"]
    files, out = {}, []
    for ln in t.split("\n"):
        if not ln:
            continue
        f = ln.split("\t")
        if len(f) != 2 or not re.fullmatch(r"[0-9a-f]{64}", f[1]):
            out.append(f"{path}: a line is not PATH<TAB>SHA256: {ln!r}")
        else:
            files[f[0]] = f[1]
    return files, out


def seeded_set(alice, bob):
    return sorted((u, k) for u, name in ((alice, "alice"), (bob, "bob")) for k in KEYS[name])


def uids(alice, bob):
    if not (re.fullmatch(r"[0-9]+", alice) and re.fullmatch(r"[0-9]+", bob)) or alice == bob:
        sys.exit(f"upgradem3: bad uids {alice!r} {bob!r}")
    return alice, bob


def seeded(alice, bob, before):
    files, out = snapshot(before)
    if files is None:
        return out
    want = set()
    for uid, key in seeded_set(alice, bob):
        for name in (key, key + "-cert"):
            want.add(f"{uid}/{name}")
            if f"{uid}/{name}" not in files:
                out.append(f"{before}: the old file {uid}/{name} is not there before the upgrade")
    return out


def purged(alice, bob, before, after):
    b, out = snapshot(before)
    a, bad = snapshot(after)
    if b is None or a is None:
        return out + bad
    out += bad
    if not b:
        out.append(f"{before}: no old file before the upgrade, so there is nothing to purge")
    old_hashes = set(b.values())
    for p in sorted(b):
        if p in a:
            out.append(f"{after}: the old file {p} is still there")
    for p, h in sorted(a.items()):
        if h in old_hashes:
            out.append(f"{after}: {p} holds the content of an old file")
    names = {k for ks in KEYS.values() for k in ks}
    names |= {k + "-cert" for k in names}
    for p in sorted(a):
        if p.split("/")[-1] in names:
            out.append(f"{after}: {p} is named like a file of the old format")
    return out


def rc_of(path):
    t = read(path)
    if t is None or not re.fullmatch(r"\s*[0-9]+\s*", t):
        return None
    return int(t)


def api_ids(path):
    t = read(path)
    if t is None:
        return None, [f"{path}: missing"]
    ids = []
    for ln in t.split("\n"):
        if ln.strip():
            f = ln.split("\t")
            if len(f) != 3:
                return None, [f"{path}: a line is not ID<TAB>TYPE<TAB>KIND: {ln!r}"]
            ids.append(f[0])
    return ids, []


def cli_ids(path):
    t = read(path)
    if t is None:
        return None, [f"{path}: missing"]
    return [m.group(1) for m in (re.fullmatch(r"id: (.*)", ln) for ln in t.split("\n")) if m], []


def listing_ids(d):
    """{user: {"api": ids, "cli": ids}} and the problems of reading it"""
    got, out = {}, []
    for user in KEYS:
        got[user] = {}
        for ext, reader in (("api", api_ids), ("cli", cli_ids)):
            rc = rc_of(f"{d}/{user}.{ext}.rc")
            if rc != 0:
                out.append(f"{d}/{user}.{ext}.rc: the listing did not succeed (status {rc!r})")
            ids, bad = reader(f"{d}/{user}.{ext}")
            out += bad
            got[user][ext] = ids
    return got, out


def empty(d):
    got, out = listing_ids(d)
    seeded_ids = {k for ks in KEYS.values() for k in ks}
    for user, by in got.items():
        for ext, ids in by.items():
            for i in ids or []:
                out.append(f"{d}/{user}.{ext}: {user} is shown {i!r}" + (" (a purged key)" if i in seeded_ids else ""))
    return out


def journal(alice, bob, path):
    t = read(path)
    if t is None:
        return [f"{path}: cannot be read"]
    out, entries = [], []
    for ln in t.split("\n"):
        if not ln.strip():
            continue
        try:
            e = json.loads(ln)
        except ValueError:
            out.append(f"{path}: a line is not JSON: {ln[:60]!r}")
            continue
        if e.get("CUSTODIO_OPERATION") == "purge":
            entries.append(e)
    got = sorted((e.get("CUSTODIO_OWNER_UID"), e.get("CUSTODIO_KEY_ID")) for e in entries)
    want = seeded_set(alice, bob)
    for pair in sorted(set(got) | set(want), key=str):
        n, w = got.count(pair), want.count(pair)
        if n != w:
            out.append(f"{path}: owner {pair[0]} key {pair[1]}: {n} purge entries, expected {w}")
    for e in entries:
        if "CUSTODIO_UID" in e or "CUSTODIO_PID" in e:
            out.append(f"{path}: a purge entry for {e.get('CUSTODIO_KEY_ID')} carries a caller")
        if e.get("CUSTODIO_OUTCOME") != "purged":
            out.append(f"{path}: a purge entry for {e.get('CUSTODIO_KEY_ID')} has outcome {e.get('CUSTODIO_OUTCOME')!r}, expected 'purged'")
    return out


def reimport(d):
    out = []
    for user in KEYS:
        for key in KEYS[user]:
            rc = rc_of(f"{d}/import/{user}-{key}.rc")
            if rc != 0:
                out.append(f"{d}/import/{user}-{key}.rc: the import of {user}'s {key} did not succeed (status {rc!r})")
    got, bad = listing_ids(d)
    out += bad
    for user, by in got.items():
        for ext, ids in by.items():
            if ids is not None and sorted(ids) != KEYS[user]:
                out.append(f"{d}/{user}.{ext}: {user} lists {sorted(ids)}, expected {KEYS[user]}")
    return out


def main(argv):
    cmd, args = (argv[0], argv[1:]) if argv else ("", [])
    table = {"cases": 0, "seeded": 3, "purged": 4, "empty": 1, "journal": 3, "reimport": 3}
    if cmd not in table or len(args) != table[cmd]:
        sys.exit(__doc__)
    if cmd == "cases":
        res = CASES
    elif cmd == "empty":
        res = empty(args[0])
    else:
        a, b = uids(args[0], args[1])
        res = {"seeded": lambda: seeded(a, b, args[2]), "purged": lambda: purged(a, b, args[2], args[3]),
               "journal": lambda: journal(a, b, args[2]), "reimport": lambda: reimport(args[2])}[cmd]()
    for ln in res:
        print(ln)


if __name__ == "__main__":
    main(sys.argv[1:])
