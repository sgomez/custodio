#!/usr/bin/python3 -I
"""The judgements of the tpm-clear-* cases (F140, acceptance 8 of SPEC.md), as functions of files, so that scripts/test-e2e-tpmclear.sh can show each one fails on bad evidence
without a container. Each subcommand prints one problem per line and nothing when the evidence is right (exit 0 either way; exit 2 on a bad call).
  tpmclear.py cases
  tpmclear.py dbus FILE ok|KeyLost       tpmclear-sign.py's output: "ok", or "error com.rfirma.Custodio1.Error.KeyLost: the stored key can no longer be used" (docs/api.md)
  tpmclear.py p11fail RC LOG             pkcs11-tool exited non-zero and its last CKR_ is CKR_DEVICE_ERROR (the module maps KeyLost to it)
  tpmclear.py p11ok RC LOG PUB MSG SIG   pkcs11-tool exited 0 and `openssl dgst -sha256 -verify` accepts SIG over MSG against PUB
  tpmclear.py journal JSON UID KIND REQUESTS ID,ID... [SECRET...]
                                         JSON (journalctl -o json, the custodiod entries with an operation after the clear): every one is a sign / signing_failed / key_lost entry of
                                         kind KIND for uid UID and one of the IDs, there are exactly REQUESTS of them (the Sign calls the agent approved, not the tool runs: a
                                         consumer may call twice), each ID has at least 2 (the D-Bus call and the tool), and no SECRET is in any entry
  tpmclear.py deljournal JSON UID ID...
                                         exactly one delete / deleted entry per ID (uid UID; a delete entry carries no storage kind, docs/audit.md), no other entry, none for another key
  tpmclear.py listed LIST KIND ID...     owner-call.py list output ("ID<TAB>TYPE<TAB>KIND"): each ID once with kind KIND
  tpmclear.py samelist LIST_A LIST_B ID...
                                         the rows of the IDs are the same in both lists
  tpmclear.py gone LIST ID...            none of the IDs is listed
  tpmclear.py clilist FILE KIND ID...    `custodio list`: the block of each ID once, with `kind: KIND`
  tpmclear.py state BEFORE AFTER         two listings of the state directory (find + sha256) are identical and not empty
  tpmclear.py records SCAN present|absent KIND ID...
                                         tpmdup.py scan output (uid, id, kind, parent name): each ID has a record of kind KIND (present) or none (absent)
  tpmclear.py owner BEFORE AFTER         two names (hex) of the primary made under the owner hierarchy with one fixed template differ (the seed changed)
  tpmclear.py rc FILE LABEL [WANT]       an exit status file holds WANT (default 0)
"""
import json
import os
import re
import subprocess
import sys

CASES = ["tpm-clear-sign-fails", "tpm-clear-keys-listed", "tpm-clear-delete"]
ERR = "com.rfirma.Custodio1.Error."
KEYLOST_TEXT = "the stored key can no longer be used"


def text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().replace("\r", "")
    except OSError:
        return None


def rows(path):
    t = text(path)
    return None if t is None else [ln.split("\t") for ln in t.split("\n") if ln.strip()]


def dbus(path, want):
    t = text(path)
    if t is None:
        return [f"{path}: cannot be read"]
    t = t.strip()
    if want == "ok":
        return [] if t == "ok" else [f"{path}: the signature gave {t!r}, expected ok"]
    expected = f"error {ERR}{want}: {KEYLOST_TEXT}" if want == "KeyLost" else f"error {ERR}{want}"
    return [] if t == expected else [f"{path}: the signature gave {t!r}, expected {expected!r}"]


def p11fail(rc, log):
    out = []
    status = (text(rc) or "").strip()
    if not re.fullmatch(r"[0-9]+", status):
        return [f"{rc}: not an exit status: {status!r}"]
    if int(status) == 0:
        out.append(f"{rc}: pkcs11-tool signed (exit 0) after the clear")
    ckr = re.findall(r"CKR_[A-Z_0-9]+", text(log) or "")
    if not ckr or ckr[-1] != "CKR_DEVICE_ERROR":
        out.append(f"{log}: the last CKR is {ckr[-1] if ckr else 'none'}, expected CKR_DEVICE_ERROR")
    return out


def p11ok(rc, log, pub, msg, sig):
    status = (text(rc) or "").strip()
    if status != "0":
        ckr = re.findall(r"CKR_[A-Z_0-9]+", text(log) or "")
        return [f"{rc}: pkcs11-tool exited {status or 'with no status'}{' ' + ckr[-1] if ckr else ''}, expected a signature"]
    if not os.path.exists(sig) or os.path.getsize(sig) == 0:
        return [f"{sig}: no signature"]
    r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pub, "-signature", sig, msg], capture_output=True, text=True, check=False)
    return [] if r.returncode == 0 and "Verified OK" in r.stdout else [f"{sig}: does not verify against {pub}"]


def entries(path):
    t = text(path)
    if t is None:
        return None
    return [e for e in (json.loads(ln) for ln in t.split("\n") if ln.strip()) if "CUSTODIO_OPERATION" in e]


def journal(path, uid, kind, requests, ids, secrets):
    es = entries(path)
    if es is None:
        return [f"{path}: cannot be read"]
    out = []
    if not re.fullmatch(r"[0-9]+", requests):
        return [f"requests {requests!r} is not a number"]
    if len(es) != int(requests):
        out.append(f"{path}: {len(es)} entries, expected {requests} (one per Sign call)")
    per = {i: 0 for i in ids}
    for e in es:
        key = e.get("CUSTODIO_KEY_ID")
        for field, want in (("CUSTODIO_OPERATION", "sign"), ("CUSTODIO_OUTCOME", "signing_failed"), ("CUSTODIO_CAUSE", "key_lost"), ("CUSTODIO_STORAGE_KIND", kind), ("CUSTODIO_UID", uid)):
            if e.get(field) != want:
                out.append(f"{path}: an entry for {key!r} has {field} {e.get(field)!r}, expected {want!r}")
        if key not in per:
            out.append(f"{path}: an entry for the key {key!r}, which is none of {sorted(per)}")
        else:
            per[key] += 1
        body = json.dumps(e)
        for s in secrets:
            if s and s in body:
                out.append(f"{path}: an entry holds a secret")
    for k, n in per.items():
        if n < 2:
            out.append(f"{path}: {n} entries for {k}, expected at least 2 (the D-Bus call and pkcs11-tool)")
    return out


def deljournal(path, uid, ids):
    es = entries(path)
    if es is None:
        return [f"{path}: cannot be read"]
    out = []
    if len(es) != len(ids):
        out.append(f"{path}: {len(es)} entries, expected {len(ids)}")
    for i in ids:
        mine = [e for e in es if e.get("CUSTODIO_KEY_ID") == i]
        if len(mine) != 1:
            out.append(f"{path}: {len(mine)} entries for {i}, expected 1")
            continue
        e = mine[0]
        for field, want in (("CUSTODIO_OPERATION", "delete"), ("CUSTODIO_OUTCOME", "deleted"), ("CUSTODIO_UID", uid)):
            if e.get(field) != want:
                out.append(f"{path}: the entry for {i} has {field} {e.get(field)!r}, expected {want!r}")
    return out


def listed(path, kind, ids):
    rs = rows(path)
    if rs is None:
        return [f"{path}: cannot be read"]
    out = []
    for i in ids:
        mine = [r for r in rs if r and r[0] == i]
        if len(mine) != 1:
            out.append(f"{path}: {i} is listed {len(mine)} times, expected once")
        elif len(mine[0]) < 3 or mine[0][2] != kind:
            out.append(f"{path}: {i} has kind {mine[0][2] if len(mine[0]) > 2 else None!r}, expected {kind!r}")
    return out


def samelist(a, b, ids):
    ra, rb = rows(a), rows(b)
    if ra is None or rb is None:
        return ["a list cannot be read"]
    out = []
    for i in ids:
        x = [r for r in ra if r and r[0] == i]
        y = [r for r in rb if r and r[0] == i]
        if not x or x != y:
            out.append(f"{i}: listed as {x} before and {y} after")
    return out


def gone(path, ids):
    rs = rows(path)
    if rs is None:
        return [f"{path}: cannot be read"]
    return [f"{path}: {i} is still listed" for i in ids if any(r and r[0] == i for r in rs)]


def clilist(path, kind, ids):
    t = text(path)
    if t is None:
        return [f"{path}: cannot be read"]
    blocks, cur = {}, None
    for ln in t.split("\n"):
        m = re.fullmatch(r"id: (.*)", ln)
        if m:
            cur = m.group(1)
            blocks.setdefault(cur, []).append({})
        elif cur is not None:
            m = re.fullmatch(r"  (type|kind): (.*)", ln)
            if m:
                blocks[cur][-1][m.group(1)] = m.group(2)
    out = []
    for i in ids:
        mine = blocks.get(i, [])
        if len(mine) != 1:
            out.append(f"{path}: {len(mine)} blocks for {i}, expected 1")
        elif mine[0].get("kind") != kind:
            out.append(f"{path}: {i} has kind {mine[0].get('kind')!r}, expected {kind!r}")
    return out


def state(a, b):
    ta, tb = text(a), text(b)
    if ta is None or tb is None:
        return ["a listing cannot be read"]
    out = []
    if not ta.strip():
        out.append(f"{a}: empty listing of the state directory")
    if ta != tb:
        out.append(f"the state directory changed: {a} differs from {b}")
    return out


def records(scan, want, kind, ids):
    rs = rows(scan)
    if rs is None:
        return [f"{scan}: cannot be read"]
    out = []
    for i in ids:
        mine = [r for r in rs if len(r) >= 3 and r[1] == i]
        if want == "present" and (len(mine) != 1 or mine[0][2] != kind):
            out.append(f"{scan}: {len(mine)} records for {i} ({[m[2] for m in mine]}), expected one of kind {kind}")
        if want == "absent" and mine:
            out.append(f"{scan}: a record for {i} is still there")
    return out


def owner(a, b):
    na, nb = (text(a) or "").strip(), (text(b) or "").strip()
    out = []
    for label, n in (("before", na), ("after", nb)):
        if not re.fullmatch(r"[0-9a-f]{68}", n):
            out.append(f"the name {label} the clear is not a 34-byte hex name: {n!r}")
    if not out and na == nb:
        out.append("the owner-hierarchy primary has the same name after the clear: the seed did not change")
    return out


def rc(path, label, want="0"):
    t = (text(path) or "").strip()
    return [] if t == want else [f"{label}: exit status {t or 'missing'}, expected {want}"]


def main(argv):
    n = len(argv) - 1
    cmd, a = (argv[0] if argv else ""), argv[1:]
    if cmd == "cases" and n == 0:
        problems = CASES
    elif cmd == "dbus" and n == 2:
        problems = dbus(*a)
    elif cmd == "p11fail" and n == 2:
        problems = p11fail(*a)
    elif cmd == "p11ok" and n == 5:
        problems = p11ok(*a)
    elif cmd == "journal" and n >= 5:
        problems = journal(a[0], a[1], a[2], a[3], a[4].split(","), a[5:])
    elif cmd == "deljournal" and n >= 3:
        problems = deljournal(a[0], a[1], a[2:])
    elif cmd == "listed" and n >= 3:
        problems = listed(a[0], a[1], a[2:])
    elif cmd == "samelist" and n >= 3:
        problems = samelist(a[0], a[1], a[2:])
    elif cmd == "gone" and n >= 2:
        problems = gone(a[0], a[1:])
    elif cmd == "clilist" and n >= 3:
        problems = clilist(a[0], a[1], a[2:])
    elif cmd == "state" and n == 2:
        problems = state(*a)
    elif cmd == "records" and n >= 4:
        problems = records(a[0], a[1], a[2], a[3:])
    elif cmd == "owner" and n == 2:
        problems = owner(*a)
    elif cmd == "rc" and n in (2, 3):
        problems = rc(*a)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    print("\n".join(problems))
    return 0


sys.exit(main(sys.argv[1:]))
