#!/usr/bin/python3 -I
"""The judgements of the journal-kind-* cases (F144, acceptance 11 of SPEC.md), as functions of files, so that scripts/test-e2e-journalkind.sh can show each one fails on bad
evidence without a container. Each subcommand prints one problem per line and nothing when the evidence is right (exit 0 either way; exit 2 on a bad call).
  journalkind.py cases
  journalkind.py extract DOC SERVICE_UID UID1 UID2 KIND...
        the queries of docs/audit.md this feature runs, taken from the fenced journalctl lines of the document, one per line: "NAME<TAB>ARGS<TAB>DOCUMENT-LINE", NAME being
        kind:KIND (for each KIND), purge, owner:UID1, owner:UID2, key-lost, temporarily-unavailable. Only the placeholders are replaced: $(id -u custodio) by SERVICE_UID, the
        kind by KIND, CUSTODIO_OWNER_UID=1000 by the uid; every other token is the document's. A heading whose query is not found is a problem (exit 1, message on stderr).
  journalkind.py check RESULT PRE WINDOW SERVICE_UID EXPECT [--forged KEY]... [--present KEY:OUTCOME]... [--secret TEXT]...
        RESULT: `journalctl -o json` of one documented query run after the case's cursor; PRE: the entries of the unit that were in the journal before the cursor; WINDOW: every
        entry after the cursor, whatever its unit. EXPECT: the entries the case caused, "KEY_ID OPERATION OUTCOME KIND CAUSE OWNER" (tab separated, `-` for a field the entry must
        not have), possibly none (an empty file). The result must be exactly those, each from custodio.service and the service user, none from before the cursor; every --forged KEY
        must be in WINDOW as an entry of another sender (the control that the forged entry was written and not returned); every --present KEY:OUTCOME must be in WINDOW as a
        service entry (a successful or denied call that no cause query may return); no WINDOW entry holds a --secret.
"""
import json
import re
import sys

CASES = ["journal-kind-import", "journal-kind-purge", "journal-kind-owner", "journal-kind-key-lost", "journal-kind-temporarily-unavailable"]
UNIT = "_SYSTEMD_UNIT=custodio.service"
SERVICE_UID_TEXT = "$(id -u custodio)"
KINDS = ("tpm", "encrypted-tpm", "encrypted-host")
FIELDS = ("KEY_ID", "OPERATION", "OUTCOME", "KIND", "CAUSE", "OWNER")
FIELD_NAME = {"KEY_ID": "CUSTODIO_KEY_ID", "OPERATION": "CUSTODIO_OPERATION", "OUTCOME": "CUSTODIO_OUTCOME", "KIND": "CUSTODIO_STORAGE_KIND",
              "CAUSE": "CUSTODIO_CAUSE", "OWNER": "CUSTODIO_OWNER_UID"}


def field(entry, name):
    value = entry.get(name)
    return value if isinstance(value, str) else None


def rows(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [json.loads(line) for line in f if line.strip()]


def fenced_queries(doc):
    """The journalctl lines inside fenced blocks, as token lists (without 'journalctl')."""
    found, fenced = [], False
    for raw in doc.splitlines():
        if raw.startswith("```"):
            fenced = not fenced
        elif fenced and raw.startswith("journalctl "):
            found.append((raw, raw.replace(SERVICE_UID_TEXT, "SERVICE_UID").split()[1:]))
    return found


def extract(doc, service_uid, uids, kinds):
    """[(name, args, line)] and the problems."""
    queries, problems = [], []
    found = fenced_queries(doc)

    def lookup(want, replace):
        # want: the tokens (after the unit and user) the line must hold, as a set of exact tokens; replace: {document token: value}
        for raw, toks in found:
            toks = [t.replace("SERVICE_UID", str(service_uid)) for t in toks]
            if [UNIT, f"_UID={service_uid}"] != toks[:2]:
                continue
            rest = toks[2:]
            if rest == want:
                return [replace.get(t, t) for t in toks], raw
        return None

    def add(name, want, replace):
        hit = lookup(want, replace)
        if hit is None:
            problems.append(f"{name}: docs/audit.md has no query 'journalctl {UNIT} _UID=<service> {' '.join(want)}'")
        else:
            queries.append((name, hit[0], hit[1]))

    for kind in kinds:
        add(f"kind:{kind}", ["CUSTODIO_OPERATION=import", "CUSTODIO_STORAGE_KIND=encrypted-host"], {"CUSTODIO_STORAGE_KIND=encrypted-host": f"CUSTODIO_STORAGE_KIND={kind}"})
    add("purge", ["CUSTODIO_OPERATION=purge"], {})
    for uid in uids:
        add(f"owner:{uid}", ["CUSTODIO_OPERATION=purge", "CUSTODIO_OWNER_UID=1000"], {"CUSTODIO_OWNER_UID=1000": f"CUSTODIO_OWNER_UID={uid}"})
    add("key-lost", ["CUSTODIO_OPERATION=sign", "CUSTODIO_CAUSE=key_lost"], {})
    add("temporarily-unavailable", ["CUSTODIO_OPERATION=sign", "CUSTODIO_CAUSE=temporarily_unavailable"], {})
    return queries, problems


def read_expect(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) != len(FIELDS):
                raise ValueError(f"{path}: expected {len(FIELDS)} tab separated fields, got '{line}'")
            out.append(tuple(None if p == "-" else p for p in parts))
    return out


def tuple_of(entry):
    return tuple(field(entry, FIELD_NAME[f]) for f in FIELDS)


def is_service(entry, service_uid):
    return field(entry, "_SYSTEMD_UNIT") == "custodio.service" and field(entry, "_UID") == str(service_uid)


def show(t):
    return ", ".join(f"{f}={v}" for f, v in zip(FIELDS, t) if v is not None)


def check(result, pre, window, service_uid, expect, forged, present, secrets):
    problems = []
    got = rows(result)
    pre_cursors = {field(e, "__CURSOR") for e in rows(pre)} - {None}
    win = rows(window)
    for e in got:
        who = f"{field(e, 'CUSTODIO_KEY_ID')} from {field(e, '_SYSTEMD_UNIT')} uid {field(e, '_UID')}"
        if not is_service(e, service_uid):
            problems.append(f"the query returned an entry that is not the service's: {who}")
        if field(e, "__CURSOR") in pre_cursors:
            problems.append(f"the query returned an entry from before the case's cursor: {who}")
        if field(e, "CUSTODIO_OPERATION") == "purge" and (field(e, "CUSTODIO_UID") is not None or field(e, "CUSTODIO_PID") is not None):
            problems.append(f"a purge entry carries a caller: {who}")
    want = list(expect)
    for e in got:
        t = tuple_of(e)
        if t in want:
            want.remove(t)
        else:
            problems.append(f"stray entry returned: {show(t)}")
    for t in want:
        problems.append(f"missing entry: {show(t)}")
    for key in forged:
        if not any(field(e, "CUSTODIO_KEY_ID") == key and not is_service(e, service_uid) for e in win):
            problems.append(f"the control is vacuous: no forged entry for {key} in the window")
        if any(field(e, "CUSTODIO_KEY_ID") == key for e in got):
            problems.append(f"a forged entry for {key} was returned")
    for spec in present:
        key, _, outcome = spec.partition(":")
        if not any(field(e, "CUSTODIO_KEY_ID") == key and field(e, "CUSTODIO_OUTCOME") == outcome and is_service(e, service_uid) for e in win):
            problems.append(f"the control is vacuous: no service entry {key}:{outcome} in the window")
    blob = json.dumps(win)
    for s in secrets:
        if s and s in blob:
            problems.append("a secret is in an entry of the window")
    return problems


def main(argv):
    n = len(argv)
    if argv[:1] == ["cases"]:
        print("\n".join(CASES))
    elif argv[:1] == ["extract"] and n >= 6:
        with open(argv[1], encoding="utf-8") as f:
            doc = f.read()
        if not re.fullmatch(r"[0-9]+", argv[2]) or not all(re.fullmatch(r"[0-9]+", u) for u in argv[3:5]) or not all(k in KINDS for k in argv[5:]):
            print("journalkind: bad uid or kind", file=sys.stderr)
            return 2
        queries, problems = extract(doc, argv[2], argv[3:5], argv[5:])
        for p in problems:
            print(f"journalkind: {p}", file=sys.stderr)
        if problems:
            return 1
        for name, args, line in queries:
            print(f"{name}\t{' '.join(args)}\t{line}")
    elif argv[:1] == ["check"] and n >= 6:
        forged, present, secrets, i = [], [], [], 6
        while i < n:
            if argv[i] in ("--forged", "--present", "--secret") and i + 1 < n:
                {"--forged": forged, "--present": present, "--secret": secrets}[argv[i]].append(argv[i + 1])
                i += 2
            else:
                print(__doc__, file=sys.stderr)
                return 2
        try:
            problems = check(argv[1], argv[2], argv[3], argv[4], read_expect(argv[5]), forged, present, secrets)
        except (OSError, ValueError) as err:
            problems = [str(err)]
        if problems:
            print("\n".join(problems))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
