#!/usr/bin/python3 -I
"""The pieces of the appid-* cases (F95, acceptance 9 of SPEC.md), as functions of files, so that appid-selftest.sh can feed them bad evidence. The calls
are made by alice (appid-user.sh, appid-enter.py), everything here runs as root (appid-run.sh) or in the self-test.

  appid.py names --out F [--seed S]              the scope names of the hostile and the edge callers, each with the state and the id the reader of F67 must give
  appid.py constant --file F --name N            the value of `pub const N: usize = V;` in the source of the reader
  appid.py deadline --doc D                      the lookup bound in seconds, from docs/audit.md
  appid.py slice --mount M --control-group C --uid N   the app.slice of the user manager, where the daemon looks
  appid.py cap-setup|cap-check|cap-teardown|cleanup ...   the children of app.slice that bring the count over the cap (needs root)
  appid.py merge --plan P --names F --observed O --uid N --out L
  appid.py entries --case C --window W --ledger L --unit U --service-uid N
  appid.py outcome --window W --ledger L --unit U --service-uid N --dir D --pub P --data F
  appid.py sweep --export F --names F            nothing of a hostile name is anywhere in the export
  appid.py bound --ledger L --doc D [--scale X]
  appid.py extract --doc D --uid N --service-uid N --key K --ledger L --out F
  appid.py queries --queries F --results DIR --cursors C --ledger L --window W --unit U --service-uid N

A problem names the label, the kind of text and the field, never the hostile text itself."""
import argparse
import importlib.util
import json
import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    """A module of this directory by its path (`python3 -I` puts no directory on sys.path)."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


jo = _load("jo")
rules = _load("appid_rules")  # the reader's rules, the scope names, the cap, the slice
journal = _load("appid_journal")  # the sweep, the bound, the documented queries
globals().update({k: v for m in (rules, journal) for k, v in vars(m).items() if not k.startswith("_") and k != "jo"})

KEY = "ai-key"
PLAN_FIELDS = ("label", "phase", "kind", "cg", "op", "mode", "outcome", "app_state", "app_id", "result")
OBS_FIELDS = ("label", "pid", "uid", "result", "dur_ms", "nreq", "subj")
ROW_FIELDS = ("label", "phase", "kind", "cg", "op", "mode", "outcome", "app_state", "app_id", "result", "pid", "uid", "dur", "nreq", "subj")


# --- the plan, what alice saw, and the ledger that joins them
def read_plan(text):
    plan, problems = {}, []
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            parts = line.split()
            if len(parts) != len(PLAN_FIELDS):
                problems.append(f"plan line '{line}' has {len(parts)} words, expected {len(PLAN_FIELDS)}")
            else:
                plan[parts[0]] = dict(zip(PLAN_FIELDS, parts))
    return plan, problems


def merge_problems(plan_text, names, observed_text, uid):
    """(problems, rows): the plan and the observation agree on the labels, the callers and the uid; every pid and duration is a number, every pid used once.
    What the call gave (result, requests, subject) is judged by outcome_problems, not here."""
    plan, problems = read_plan(plan_text)
    seen = {}
    for line in observed_text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != len(OBS_FIELDS):
            problems.append(f"observed line '{line[:60]}' has {len(parts)} fields, expected {len(OBS_FIELDS)}")
        elif parts[0] in seen:
            problems.append(f"{parts[0]}: observed twice")
        else:
            seen[parts[0]] = dict(zip(OBS_FIELDS, parts))
    problems += [f"{label}: a call the plan does not know" for label in seen if label not in plan]
    rows = []
    for label, p in plan.items():
        if label not in seen:
            problems.append(f"{label}: the call was not made")
            continue
        o = seen[label]
        resolved = None
        if p["app_id"] != "-":
            if p["app_id"] not in names:
                problems.append(f"{label}: the plan names an id '{p['app_id']}' that no scope was made for")
                continue
            resolved = names[p["app_id"]]["id"]
        if p["cg"] != "-":
            named = names.get(p["cg"])
            if named is None:
                problems.append(f"{label}: no scope named '{p['cg']}' was made")
                continue
            if named["state"] != p["app_state"] or named["id"] != resolved:
                problems.append(f"{label}: the plan says {p['app_state']} but the scope made for it says {named['state']}")
        if p["app_state"] == "read" and resolved is None:
            problems.append(f"{label}: state read without a known id")
        if p["app_state"] != "read" and p["app_id"] != "-":
            problems.append(f"{label}: an id with the state {p['app_state']}")
        if not o["pid"].isdigit() or not re.fullmatch(r"\d+", o["dur_ms"]) or not o["nreq"].isdigit():
            problems.append(f"{label}: pid, duration or request count is not a number")
            continue
        if o["uid"] != str(uid):
            problems.append(f"{label}: made by uid '{o['uid']}', expected '{uid}'")
        if p["op"] not in jo.OPERATIONS or p["outcome"] not in jo.OPERATIONS[p["op"]][1]:
            problems.append(f"{label}: '{p['op']} {p['outcome']}' is no documented operation and outcome")
        row = dict(p)
        row.update(pid=o["pid"], uid=o["uid"], dur=int(o["dur_ms"]) / 1000.0, nreq=int(o["nreq"]), subj=o["subj"], got=o["result"])
        row["app_id"] = resolved
        row["key"] = KEY
        row["keytype"] = "rsa_2048" if p["op"] == "import" else "-"
        rows.append(row)
    pids = [r["pid"] for r in rows]
    problems += [f"pid {pid} is on more than one ledger line" for pid in sorted({p for p in pids if pids.count(p) > 1})]
    return problems, rows


def write_rows(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write("\t".join(str(x) for x in [
                r["label"], r["phase"], r["kind"], r["cg"], r["op"], r["mode"], r["outcome"], r["app_state"], r["app_id"] or "-", r["result"],
                r["pid"], r["uid"], r["dur"], r["nreq"], r["subj"], r["got"]]) + "\n")


def read_rows(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                p = line.rstrip("\n").split("\t")
                row = dict(zip(ROW_FIELDS, p[:15]))
                row.update(got=p[15], app_id=None if row["app_id"] == "-" else row["app_id"], dur=float(row["dur"]), nreq=int(row["nreq"]),
                           key=KEY, keytype="rsa_2048" if row["op"] == "import" else "-")
                rows.append(row)
    return rows


# --- the entries
def app_id_problems(entry, row):
    state, ident = jo.field(entry, "CUSTODIO_APP_ID_STATE"), jo.field(entry, "CUSTODIO_APP_ID")
    label, problems = row["label"], []
    if state != row["app_state"]:
        problems.append(f"{label}: CUSTODIO_APP_ID_STATE is {state!r}, expected {row['app_state']!r}")
    if row["app_state"] == "read" and ident != row["app_id"]:
        problems.append(f"{label}: CUSTODIO_APP_ID is {ident!r}, expected {row['app_id']!r}")
    if row["app_state"] != "read" and "CUSTODIO_APP_ID" in entry:
        problems.append(f"{label}: CUSTODIO_APP_ID is present with the state {row['app_state']!r}")
    return problems


def rows_problems(window, rows, unit, uid):
    """Exactly one entry of the service for the pid of each row, with the fields of the row and its app-id."""
    audits = jo.service_audit(window, unit, uid)
    problems = []
    for row in rows:
        mine = [e for e in audits if jo.field(e, "CUSTODIO_PID") == row["pid"]]
        if len(mine) != 1:
            problems.append(f"{row['label']}: {len(mine)} journal entries for pid {row['pid']}, expected exactly 1")
            continue
        problems += jo.line_problems(mine[0], row, check_app=False)
        problems += app_id_problems(mine[0], row)
    return problems


def unexplained_problems(window, rows, unit, uid):
    pids = {r["pid"] for r in rows}
    audits = jo.service_audit(window, unit, uid)
    problems = [f"an entry no ledger line explains: operation {jo.field(e, 'CUSTODIO_OPERATION')} pid {jo.field(e, 'CUSTODIO_PID')}"
                for e in audits if jo.field(e, "CUSTODIO_PID") not in pids]
    return problems


CASES = {  # case -> rows it judges
    "appid-flatpak": lambda r: r["kind"] == "flatpak" and r["op"] == "sign",
    "appid-flatpak-max": lambda r: r["cg"] == "max",
    "appid-cap": lambda r: r["phase"] == "cap",
    "appid-operations": lambda r: r["kind"] == "flatpak" and r["op"] != "sign",
    "appid-none": lambda r: r["app_state"] == "none",
    "appid-hostile": lambda r: r["app_state"] == "undetermined",
}


def case_problems(case, window, rows, unit, uid):
    chosen = [r for r in rows if CASES[case](r)]
    if not chosen:
        return [f"{case}: the ledger has no call for this case"]
    return rows_problems(window, chosen, unit, uid)


def outcome_problems(rows, window, unit, uid, verify, unsigned):
    """Whatever the caller is, the call gives what its mode says and asks polkit once about the caller itself. VERIFY(label) says whether the signature of
    the call verifies against the key's certificate, UNSIGNED(label) whether no signature was kept."""
    problems = unexplained_problems(window, rows, unit, uid) + rows_problems(window, rows, unit, uid)
    base = {}
    for r in rows:
        if r["kind"] in NON_SANDBOXED and r["op"] == "sign":
            base.setdefault(r["mode"], set()).add(r["nreq"])
    for mode in ("approve", "deny"):
        if len(base.get(mode, ())) != 1:
            problems.append(f"the non-sandboxed callers' signatures with the agent in mode {mode} did not all ask the agent the same number of times: {sorted(base.get(mode, ()))}")
    for r in rows:
        label = r["label"]
        if r["got"] != r["result"]:
            problems.append(f"{label}: the caller saw '{r['got']}', expected '{r['result']}'")
        if r["nreq"] != 1:
            problems.append(f"{label}: the agent was asked {r['nreq']} times, expected once")
        if r["op"] == "sign" and r["nreq"] not in base.get(r["mode"], {r["nreq"]}):
            problems.append(f"{label}: the agent was asked {r['nreq']} times, a non-sandboxed caller's call asked {sorted(base[r['mode']])}")
        if r["subj"] != f"{r['pid']}/{r['uid']}":
            problems.append(f"{label}: the polkit subject was '{r['subj']}', the caller is {r['pid']}/{r['uid']}")
        if r["op"] == "sign" and r["mode"] == "approve" and not verify(label):
            problems.append(f"{label}: the signature does not verify against the certificate of the key")
        if r["op"] == "sign" and r["mode"] == "deny" and not unsigned(label):
            problems.append(f"{label}: a signature was kept after the denial")
    return problems


# --- command line
def die(problems):
    for p in problems:
        print(f"appid: {p}", file=sys.stderr)
    return 1 if problems else 0


def verify_with_openssl(directory, pub, data):
    def verify(label):
        sig = os.path.join(directory, f"sig-{label}.bin")
        return os.path.isfile(sig) and subprocess.run(["openssl", "dgst", "-sha256", "-verify", pub, "-signature", sig, data],
                                                      capture_output=True, check=False).returncode == 0

    def unsigned(label):
        sig = os.path.join(directory, f"sig-{label}.bin")
        return not os.path.exists(sig) or os.path.getsize(sig) == 0
    return verify, unsigned


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, opts in {
        "names": ["out"], "constant": ["file", "name"], "deadline": ["doc"], "slice": ["mount", "control-group", "uid"],
        "cap-setup": ["slice", "cap", "uid", "gid", "names"], "cap-check": ["slice", "cap", "names"], "cap-teardown": ["slice", "names"],
        "cleanup": ["slice", "names"], "merge": ["plan", "names", "observed", "uid", "out"],
        "entries": ["case", "window", "ledger", "unit", "service-uid"],
        "outcome": ["window", "ledger", "unit", "service-uid", "dir", "pub", "data"], "sweep": ["export", "names"], "bound": ["ledger", "doc"],
        "extract": ["doc", "uid", "service-uid", "key", "ledger", "out"],
        "queries": ["queries", "results", "cursors", "ledger", "window", "unit", "service-uid"],
    }.items():
        p = sub.add_parser(name)
        for o in opts:
            p.add_argument("--" + o, required=True)
        if name == "names":
            p.add_argument("--seed")
        if name == "bound":
            p.add_argument("--scale", default="1")
    args = parser.parse_args()
    problems = []
    try:
        if args.cmd == "names":
            rng = random.Random(args.seed) if args.seed else random.SystemRandom()
            write_names(args.out, [("flatpak", scope_name(FLATPAK_ID, 5151), "read", FLATPAK_ID, "-")] + generate_names(rng))
        elif args.cmd == "constant":
            with open(args.file, encoding="utf-8") as f:
                m = re.search(rf"pub const {re.escape(args.name)}: usize = ([0-9_]+);", f.read())
            if not m:
                raise ValueError(f"{args.file} has no `pub const {args.name}: usize`")
            print(int(m.group(1).replace("_", "")))
        elif args.cmd == "deadline":
            with open(args.doc, encoding="utf-8") as f:
                print(deadline_seconds(f.read()))
        elif args.cmd == "slice":
            print(slice_path(args.mount, args.control_group, int(args.uid)))
        elif args.cmd == "cap-setup":
            total, after, within = cap_setup(args.slice, int(args.cap), int(args.uid), int(args.gid), args.names)
            print(f"appid: app.slice has {total} children; the over-cap caller is child {after}, the inside caller child {within} (from 0, cap {args.cap})")
        elif args.cmd == "cap-check":
            problems = cap_check(args.slice, int(args.cap), args.names)
        elif args.cmd == "cap-teardown":
            problems = cap_teardown(args.slice, args.names)
        elif args.cmd == "cleanup":
            problems = cleanup(args.slice, args.names)
        elif args.cmd == "merge":
            with open(args.plan, encoding="utf-8") as f, open(args.observed, encoding="utf-8") as g:
                problems, rows = merge_problems(f.read(), read_names(args.names), g.read(), args.uid)
            if not problems:
                write_rows(args.out, rows)
        elif args.cmd == "entries":
            problems = case_problems(args.case, jo.read_rows(args.window), read_rows(args.ledger), args.unit, args.service_uid)
        elif args.cmd == "outcome":
            verify, unsigned = verify_with_openssl(args.dir, args.pub, args.data)
            problems = outcome_problems(read_rows(args.ledger), jo.read_rows(args.window), args.unit, args.service_uid, verify, unsigned)
        elif args.cmd == "sweep":
            with open(args.export, "rb") as f:
                problems = sweep_problems(f.read(), read_names(args.names))
        elif args.cmd == "bound":
            with open(args.doc, encoding="utf-8") as f:
                problems = bound_problems(read_rows(args.ledger), deadline_seconds(f.read()), float(args.scale))
        elif args.cmd == "extract":
            ids = sorted({r["app_id"] for r in read_rows(args.ledger) if r["app_id"]}) + [jo.NO_SUCH_APP]
            with open(args.doc, encoding="utf-8") as f:
                problems, queries = extract(f.read(), args.uid, args.service_uid, args.key, ids)
            with open(args.out, "w", encoding="utf-8") as f:
                f.writelines(f"{i}\t{' '.join(a)}\t{raw}\n" for i, (a, raw) in enumerate(queries, 1))
        else:
            with open(args.queries, encoding="utf-8") as f:
                queries = [(i, a.split()) for i, a, _raw in (line.rstrip("\n").split("\t") for line in f if line.strip())]
            problems = jo.queries_problems(queries, lambda i: jo.read_rows(f"{args.results}/q-{i}.json"), jo.read_set(args.cursors),
                                           read_rows(args.ledger), jo.read_rows(args.window), args.unit, args.service_uid)
    except (ValueError, OSError) as err:
        problems = [str(err)]
    return die(problems)


if __name__ == "__main__":
    sys.exit(main())
