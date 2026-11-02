#!/usr/bin/python3 -I
"""The judgements of the journal-ops-* cases (F94, acceptance 7 of SPEC.md), as functions of files, so that jo-selftest.sh can feed them bad evidence.

  jo.py merge --plan P --observed O --uid N --out L
      P: e2e/jo-ledger.txt ("LABEL OPERATION OUTCOME KEY KEYTYPE RESULT", the calls and what each must give), O: what alice's session saw
      ("LABEL<TAB>PID<TAB>UID<TAB>RESULT"). Writes the ledger L ("LABEL OPERATION OUTCOME KEY PID UID KEYTYPE") when they agree.
  jo.py window --json ALL --start TAG --end TAG --window-out F --cursors-out F
      ALL is `journalctl -o json`; the window is what lies between the entry with MESSAGE TAG (start) and the one with MESSAGE END.
      Prints the cursor of the start marker (for --after-cursor).
  jo.py entries --window F --ledger L --unit U --service-uid N [--op OP]...
      Exactly one entry of the service per ledger line (of OP, when given), with the fields of the line; no audit entry without a line.
  jo.py extract --doc D --uid N --service-uid N --key K --out F
      The journalctl queries of the fenced blocks of docs/audit.md, with the documented placeholders replaced: "INDEX<TAB>ARGUMENTS<TAB>LINE".
      DIR/q-INDEX.json holds the output of each query (-o json, after the start cursor); the entries of the window it returns must be
      exactly the ones the ledger predicts for its filter.
  jo.py count --json F --cursors C      prints how many entries of F lie in the window

A problem names the field and the label, never a secret."""
import argparse
import json
import re
import sys

OPERATIONS = {  # operation -> (MESSAGE_ID, {outcome: (PRIORITY, start of MESSAGE)}); docs/audit.md "Identifier" and "Outcomes"
    "sign": ("29c3d30e6c4242406c6db3f120d36401", {
        "signed": ("6", "signature made"), "denied": ("5", "signature denied"),
        "authorization_unavailable": ("4", "authorization unavailable, no signature"),
        "signing_failed": ("3", "signing failed after approval")}),
    "import": ("4c7163ce45d0b9faf8e7c38d098bdb22", {
        "stored": ("6", "key imported"), "denied": ("5", "import denied"),
        "authorization_unavailable": ("4", "import authorization unavailable, nothing stored"),
        "wrong_password": ("4", "import failed, wrong password"), "unsupported_key": ("4", "import failed, unsupported key"),
        "storage_failure": ("3", "import failed after approval, key not stored")}),
    "delete": ("13d1a981ea8f64fc1a6f390bee7fd66c", {
        "deleted": ("6", "key deleted"), "denied": ("5", "delete denied"),
        "authorization_unavailable": ("4", "delete authorization unavailable, nothing deleted"),
        "storage_failure": ("3", "delete failed after approval, key not removed")}),
    "replace_certificate": ("336e0b53720a735afb179ebc7f779ed6", {
        "replaced": ("6", "certificate replaced"), "denied": ("5", "certificate replacement denied"),
        "authorization_unavailable": ("4", "certificate replacement authorization unavailable, nothing changed"),
        "certificate_mismatch": ("4", "certificate replacement refused, certificate does not match the key"),
        "storage_failure": ("3", "certificate replacement failed after approval, nothing changed")}),
}
APP_ID_STATES = ("read", "none", "undetermined")
FIELD_OF_QUERY = ("MESSAGE_ID", "CUSTODIO_OPERATION", "CUSTODIO_UID", "CUSTODIO_KEY_ID", "CUSTODIO_APP_ID", "CUSTODIO_APP_ID_STATE", "CUSTODIO_OUTCOME")
SERVICE_UID_TEXT = "$(id -u custodio)"  # the documented placeholder of every query: the uid of the service account
NO_SUCH_APP = "org.invalid.NoEntryHasThis"
TAG_FIELDS = ("label", "op", "outcome", "key", "pid", "uid", "keytype")


def field(entry, name):
    value = entry.get(name)
    return value if isinstance(value, str) else None


def read_rows(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [json.loads(line) for line in f if line.strip()]


def read_ledger(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                out.append(dict(zip(TAG_FIELDS, line.split())))
    return out


def read_set(path):
    with open(path, encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def merge_problems(plan_text, observed_text, uid):
    """(problems, ledger lines): the plan and the observation agree on the labels, the results and the uid, and every pid is a number used once."""
    problems, ledger, seen = [], [], {}
    plan = {}
    for line in plan_text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            parts = line.split()
            if len(parts) != 6:
                problems.append(f"plan line '{line}' has {len(parts)} words, expected 6")
            else:
                plan[parts[0]] = parts[1:]
    for line in observed_text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            problems.append(f"observed line '{line}' has {len(parts)} fields, expected 4")
        elif parts[0] in seen:
            problems.append(f"{parts[0]}: observed twice")
        else:
            seen[parts[0]] = parts[1:]
    for label in seen:
        if label not in plan:
            problems.append(f"{label}: a call the plan does not know")
    for label, (op, outcome, key, keytype, result) in plan.items():
        if label not in seen:
            problems.append(f"{label}: the call was not made")
            continue
        pid, who, got = seen[label]
        if got != result:
            problems.append(f"{label}: result '{got}', expected '{result}'")
        if not pid.isdigit():
            problems.append(f"{label}: pid '{pid}' is not a number")
        if who != str(uid):
            problems.append(f"{label}: made by uid '{who}', expected '{uid}'")
        if op not in OPERATIONS or outcome not in OPERATIONS[op][1]:
            problems.append(f"{label}: '{op} {outcome}' is no documented operation and outcome")
        ledger.append(dict(zip(TAG_FIELDS, [label, op, outcome, key, pid, who, keytype])))
    pids = [line["pid"] for line in ledger]
    for pid in sorted(set(p for p in pids if pids.count(p) > 1)):
        problems.append(f"pid {pid} is on more than one ledger line")
    return problems, ledger


def window_of(rows, start, end):
    """(start entry, window entries): the entries between the two markers, which must each be in the journal once and in this order."""
    first = [i for i, e in enumerate(rows) if e.get("MESSAGE") == start]
    last = [i for i, e in enumerate(rows) if e.get("MESSAGE") == end]
    if len(first) != 1 or len(last) != 1:
        raise ValueError(f"marker '{start}' is in the journal {len(first)} times and '{end}' {len(last)} times, expected once each")
    if last[0] < first[0]:
        raise ValueError(f"marker '{end}' comes before '{start}'")
    return rows[first[0]], rows[first[0] + 1:last[0]]


def service_audit(rows, unit, uid):
    """The audit entries of the service: its unit, its account (both trusted fields) and an audit MESSAGE_ID or an operation field."""
    ids = {v[0] for v in OPERATIONS.values()}
    return [e for e in rows if field(e, "_SYSTEMD_UNIT") == unit and field(e, "_UID") == str(uid)
            and (field(e, "MESSAGE_ID") in ids or "CUSTODIO_OPERATION" in e)]


def line_problems(entry, line):
    """What the entry of one ledger line must hold."""
    message_id, outcomes = OPERATIONS[line["op"]]
    priority, text = outcomes[line["outcome"]]
    want = {
        "MESSAGE_ID": message_id,
        "CUSTODIO_OPERATION": line["op"],
        "CUSTODIO_OUTCOME": line["outcome"],
        "CUSTODIO_KEY_ID": line["key"],
        "CUSTODIO_UID": line["uid"],
        "PRIORITY": priority,
        "SYSLOG_IDENTIFIER": "custodiod",
        "MESSAGE": f"{text}: uid {line['uid']} pid {line['pid']} key {line['key']}",
        "CUSTODIO_KEY_TYPE": None if line["keytype"] == "-" else line["keytype"],
    }
    problems = [f"{line['label']}: {name} is {entry.get(name)!r}, expected {value!r}"
                for name, value in want.items() if field(entry, name) != value]
    state, app = field(entry, "CUSTODIO_APP_ID_STATE"), field(entry, "CUSTODIO_APP_ID")
    if state not in APP_ID_STATES:
        problems.append(f"{line['label']}: CUSTODIO_APP_ID_STATE is {state!r}, expected one of {APP_ID_STATES}")
    elif (app is not None) != (state == "read"):
        problems.append(f"{line['label']}: CUSTODIO_APP_ID is {app!r} with the state {state!r}")
    return problems


def entry_problems(window, ledger, unit, uid, ops=None):
    """Exactly one entry per ledger line (the lines of OPS, when given), and no audit entry that no line explains (of OPS, when given)."""
    audits = service_audit(window, unit, uid)
    problems, matched = [], []
    for line in ledger:
        if ops is not None and line["op"] not in ops:
            continue
        mine = [e for e in audits if field(e, "CUSTODIO_PID") == line["pid"]]
        if len(mine) != 1:
            problems.append(f"{line['label']}: {len(mine)} journal entries for pid {line['pid']}, expected exactly 1")
            continue
        matched.append(id(mine[0]))
        problems += line_problems(mine[0], line)
    for entry in audits:
        if id(entry) in matched or (ops is not None and field(entry, "CUSTODIO_OPERATION") not in ops):
            continue
        problems.append("an entry no ledger line explains: operation {} outcome {} key {} pid {}".format(
            *(field(entry, n) for n in ("CUSTODIO_OPERATION", "CUSTODIO_OUTCOME", "CUSTODIO_KEY_ID", "CUSTODIO_PID"))))
    return problems


def extract_queries(doc_text, uid, service_uid, key):
    """[(arguments, line)] of the journalctl lines of the fenced blocks of the document, with the placeholders replaced. A query that is not of the
    form 'journalctl FIELD=VALUE...' over the fields judged here, or that lacks the unit and the service account, is an error."""
    queries, fenced = [], False
    for raw in doc_text.splitlines():
        if raw.startswith("```"):
            fenced = not fenced
            continue
        if not fenced or not raw.startswith("journalctl"):
            continue
        text = raw.replace(SERVICE_UID_TEXT, str(service_uid))
        tokens = text.split()[1:]
        args = []
        for token in tokens:
            m = re.fullmatch(r"([A-Z_][A-Z_]*)=([A-Za-z0-9._-]+)", token)
            if not m or m.group(1) not in FIELD_OF_QUERY + ("_SYSTEMD_UNIT", "_UID"):
                raise ValueError(f"the documented query '{raw}' has '{token}', which this step does not know how to judge")
            name, value = m.groups()
            if (name, value) == ("CUSTODIO_UID", "1000"):
                value = str(uid)
            elif (name, value) == ("CUSTODIO_KEY_ID", "my-key"):
                value = key
            elif (name, value) == ("CUSTODIO_APP_ID", "org.example.App"):
                value = NO_SUCH_APP
            args.append(f"{name}={value}")
        names = [a.split("=")[0] for a in args]
        if "_SYSTEMD_UNIT=custodio.service" not in args or f"_UID={service_uid}" not in args or names.count("_UID") != 1:
            raise ValueError(f"the documented query '{raw}' lacks _SYSTEMD_UNIT=custodio.service or _UID of the service account")
        queries.append((args, raw))
    if not queries:
        raise ValueError("the document holds no journalctl query")
    return queries


def predicted_value(line, name, entry):
    if name == "MESSAGE_ID":
        return OPERATIONS[line["op"]][0]
    if name in ("CUSTODIO_APP_ID", "CUSTODIO_APP_ID_STATE"):
        return field(entry, name) if entry else None  # not in the ledger: what the entry of that call says (F95 owns the real cases)
    return line[{"CUSTODIO_OPERATION": "op", "CUSTODIO_UID": "uid", "CUSTODIO_KEY_ID": "key", "CUSTODIO_OUTCOME": "outcome"}[name]]


def tuple_of(source):
    if "op" in source:
        return (source["op"], source["outcome"], source["key"], source["pid"])
    return tuple(field(source, n) for n in ("CUSTODIO_OPERATION", "CUSTODIO_OUTCOME", "CUSTODIO_KEY_ID", "CUSTODIO_PID"))


def query_problems(index, args, result_rows, cursors, ledger, window, unit, uid):
    """The entries of the window that the query returned are exactly the ledger lines whose fields the query names."""
    audits = service_audit(window, unit, uid)
    filters = [tuple(a.split("=", 1)) for a in args if a.split("=")[0] not in ("_SYSTEMD_UNIT", "_UID")]
    predicted = []
    for line in ledger:
        entry = next((e for e in audits if field(e, "CUSTODIO_PID") == line["pid"]), None)
        if all(predicted_value(line, n, entry) == v for n, v in filters):
            predicted.append(tuple_of(line))
    got = []
    for row in result_rows:
        if field(row, "__CURSOR") in cursors:
            got.append(tuple_of(row))
    label = f"query {index} ({' '.join(args)})"
    problems = []
    for t in sorted(set(predicted + got)):
        if predicted.count(t) != got.count(t):
            problems.append(f"{label}: {got.count(t)} entries for {t}, the ledger predicts {predicted.count(t)}")
    return problems, len(predicted)


def queries_problems(queries, results, cursors, ledger, window, unit, uid):
    """The problems of all queries: QUERIES is [(index, arguments)], RESULTS(index) the rows the query returned (OSError: it has no result)."""
    problems, predicted_total = [], 0
    for index, arguments in queries:
        try:
            result = results(index)
        except OSError as err:
            problems.append(f"query {index}: no result ({err})")
            continue
        p, n = query_problems(index, arguments, result, cursors, ledger, window, unit, uid)
        problems, predicted_total = problems + p, predicted_total + n
    if ledger and predicted_total == 0:
        problems.append("no query predicts any entry: the queries cannot see the entries")
    return problems


def cmd_queries(args):
    with open(args.queries, encoding="utf-8") as f:
        queries = [(i, a.split()) for i, a, _line in (line.rstrip("\n").split("\t") for line in f if line.strip())]
    return queries_problems(queries, lambda i: read_rows(f"{args.results}/q-{i}.json"), read_set(args.cursors), read_ledger(args.ledger),
                            read_rows(args.window), args.unit, args.service_uid)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, opts in {
        "merge": ["plan", "observed", "uid", "out"], "window": ["json", "start", "end", "window-out", "cursors-out"],
        "entries": ["window", "ledger", "unit", "service-uid"], "extract": ["doc", "uid", "service-uid", "key", "out"],
        "queries": ["queries", "results", "cursors", "ledger", "window", "unit", "service-uid"], "count": ["json", "cursors"],
    }.items():
        p = sub.add_parser(name)
        for o in opts:
            p.add_argument("--" + o, required=True)
        if name == "entries":
            p.add_argument("--op", action="append")
    args = parser.parse_args()
    problems = []
    try:
        if args.cmd == "merge":
            with open(args.plan, encoding="utf-8") as f, open(args.observed, encoding="utf-8") as g:
                problems, ledger = merge_problems(f.read(), g.read(), args.uid)
            if not problems:
                with open(args.out, "w", encoding="utf-8") as f:
                    f.writelines(" ".join(line[n] for n in TAG_FIELDS) + "\n" for line in ledger)
        elif args.cmd == "window":
            start, rows = window_of(read_rows(args.json), args.start, args.end)
            with open(args.window_out, "w", encoding="utf-8") as f:
                f.writelines(json.dumps(e) + "\n" for e in rows)
            with open(args.cursors_out, "w", encoding="utf-8") as f:
                f.writelines(field(e, "__CURSOR") + "\n" for e in rows)
            print(field(start, "__CURSOR"))
        elif args.cmd == "entries":
            problems = entry_problems(read_rows(args.window), read_ledger(args.ledger), args.unit, args.service_uid, args.op)
        elif args.cmd == "extract":
            with open(args.doc, encoding="utf-8") as f:
                found = extract_queries(f.read(), args.uid, args.service_uid, args.key)
            with open(args.out, "w", encoding="utf-8") as f:
                f.writelines(f"{i}\t{' '.join(a)}\t{line}\n" for i, (a, line) in enumerate(found, 1))
        elif args.cmd == "queries":
            problems = cmd_queries(args)
        else:
            cursors = read_set(args.cursors)
            print(sum(1 for e in read_rows(args.json) if field(e, "__CURSOR") in cursors))
    except (ValueError, OSError) as err:
        problems = [str(err)]
    for problem in problems:
        print(f"jo: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
