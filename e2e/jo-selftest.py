#!/usr/bin/python3 -I
"""The checks of the journal-ops judgements (jo.py, journal.py sweep) on made-up evidence, good and bad (F94). Container-free; the guest runs it first.
Usage: jo-selftest.py E2E-DIR DOC (the directory with jo.py and journal.py, and docs/audit.md)."""
import base64
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

HERE, DOC = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("jo", os.path.join(HERE, "jo.py"))
jo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jo)
UNIT, SVC, ALICE = "custodio.service", 998, 1000
failures = []


def bad(msg):
    failures.append(msg)
    print(f"jo-selftest: {msg}", file=sys.stderr)


def ok(name, problems):
    if problems:
        bad(f"{name}: problems on good evidence: {problems[:3]}")


def fails(name, problems):
    if not problems:
        bad(f"{name}: no problem on bad evidence")


def line(label, op, outcome, key, pid, keytype="-"):
    return {"label": label, "op": op, "outcome": outcome, "key": key, "pid": str(pid), "uid": str(ALICE), "keytype": keytype}


LEDGER = [line("s", "sign", "signed", "k", 101), line("i", "import", "stored", "k", 102, "rsa_2048"),
          line("d", "delete", "denied", "k", 103), line("r", "replace_certificate", "certificate_mismatch", "k", 104),
          line("s2", "sign", "denied", "k", 105)]


def entry(ln, n=0, **over):
    message_id, outcomes = jo.OPERATIONS[ln["op"]]
    prio, text = outcomes[ln["outcome"]]
    e = {"_SYSTEMD_UNIT": UNIT, "_UID": str(SVC), "MESSAGE_ID": message_id, "CUSTODIO_OPERATION": ln["op"], "CUSTODIO_OUTCOME": ln["outcome"],
         "CUSTODIO_KEY_ID": ln["key"], "CUSTODIO_UID": ln["uid"], "CUSTODIO_PID": ln["pid"], "PRIORITY": prio, "SYSLOG_IDENTIFIER": "custodiod",
         "MESSAGE": f"{text}: uid {ln['uid']} pid {ln['pid']} key {ln['key']}", "CUSTODIO_APP_ID_STATE": "none", "__CURSOR": f"c{ln['pid']}{n}"}
    if ln["keytype"] != "-":
        e["CUSTODIO_KEY_TYPE"] = ln["keytype"]
    e.update(over)
    return {k: v for k, v in e.items() if v is not None}


def good():
    return [entry(ln) for ln in LEDGER]


def check(window, ops=None):
    return jo.entry_problems(window, LEDGER, UNIT, SVC, ops)


# --- the entries of the ledger
ok("entries", check(good()))
for op in ("sign", "import", "delete", "replace_certificate"):
    ok(f"entries {op}", check(good(), [op]))
w = good(); w[0]["CUSTODIO_PID"] = "999"
fails("wrong pid", check(w))
w = good(); w[0]["CUSTODIO_UID"] = "0"
fails("wrong uid", check(w))
w = good(); w[0]["CUSTODIO_KEY_ID"] = "other"
fails("wrong key", check(w))
w = good(); w[0]["CUSTODIO_OPERATION"] = "delete"
fails("wrong operation", check(w))
w = good(); w[0]["CUSTODIO_OUTCOME"] = "denied"
fails("wrong outcome", check(w))
w = good(); w[0]["MESSAGE_ID"] = jo.OPERATIONS["delete"][0]
fails("wrong message id", check(w))
w = good(); w[0]["PRIORITY"] = "3"
fails("wrong priority", check(w))
w = good(); w[0]["MESSAGE"] = "signature made: uid 1000 pid 999 key k"
fails("wrong message", check(w))
w = good(); w.append(entry(LEDGER[0], 1))
fails("two entries for one call", check(w))
for ops in (None, ["sign"]):  # the call itself is reported as having two entries, not only the second one as unexplained
    if not any("2 journal entries" in p and "expected exactly 1" in p for p in check(w, ops)):
        bad(f"two entries for one call: the line is not reported as having two entries (ops {ops})")
fails("missing entry", check(good()[1:]))
w = good(); w.append(entry(line("x", "replace_certificate", "replaced", "k", 777)))
fails("entry without a call", check(w))
fails("entry without a call (its case)", check(w, ["replace_certificate"]))
ok("entry without a call is another case's", check(w, ["sign"]))
w = good(); w[1].pop("CUSTODIO_KEY_TYPE")
fails("stored without key type", check(w))
w = good(); w[1]["CUSTODIO_KEY_TYPE"] = "ecdsa_p256"
fails("stored with the wrong key type", check(w))
w = good(); w[2]["CUSTODIO_KEY_TYPE"] = "rsa_2048"
fails("denied with a key type", check(w))
w = good(); w[0]["CUSTODIO_APP_ID_STATE"] = "maybe"
fails("unknown app-id state", check(w))
w = good(); w[0]["CUSTODIO_APP_ID"] = "org.example.App"
fails("app-id with state none", check(w))
w = good(); w[0]["CUSTODIO_APP_ID_STATE"] = "read"
fails("state read without an app-id", check(w))
w = good(); w[0].update({"CUSTODIO_APP_ID_STATE": "read", "CUSTODIO_APP_ID": "org.example.App"})
ok("state read with an app-id", check(w))
# a forged entry (other account, or another unit) is neither a match nor an unexplained entry
w = good(); w.append(entry(LEDGER[0], 1, _UID="0", CUSTODIO_PID="555"))
ok("forged entry of another account", check(w))
w.append(entry(LEDGER[0], 2, _SYSTEMD_UNIT="other.service", CUSTODIO_PID="556"))
ok("forged entry of another unit", check(w))
w = good(); w.append(entry(LEDGER[0], 1, _UID="0"))
ok("forged entry with the pid of a call", check(w))

# --- the ledger from the plan and what alice saw
PLAN = "# c\na sign signed k - ok\nb import stored k rsa_2048 cli-ok\n"
OBS = "a\t11\t1000\tok\nb\t12\t1000\tcli-ok\n"
p, led = jo.merge_problems(PLAN, OBS, 1000)
ok("merge", p)
if [x["pid"] for x in led] != ["11", "12"] or led[1]["keytype"] != "rsa_2048":
    bad("merge: the ledger is not what the plan and the observation say")
fails("merge: a call not made", jo.merge_problems(PLAN, OBS.split("\n")[0] + "\n", 1000)[0])
fails("merge: a call the plan lacks", jo.merge_problems(PLAN, OBS + "c\t13\t1000\tok\n", 1000)[0])
fails("merge: a call twice", jo.merge_problems(PLAN, OBS + "a\t13\t1000\tok\n", 1000)[0])
fails("merge: wrong result", jo.merge_problems(PLAN, OBS.replace("cli-ok", "cli-failed"), 1000)[0])
fails("merge: another uid", jo.merge_problems(PLAN, OBS, 1001)[0])
fails("merge: same pid twice", jo.merge_problems(PLAN, OBS.replace("12", "11"), 1000)[0])
fails("merge: pid not a number", jo.merge_problems(PLAN, OBS.replace("12", "x"), 1000)[0])
fails("merge: unknown outcome", jo.merge_problems(PLAN.replace("signed", "gone"), OBS, 1000)[0])
fails("merge: short plan line", jo.merge_problems(PLAN + "z sign\n", OBS, 1000)[0])

# --- the window between the markers
rows = [{"MESSAGE": "before", "__CURSOR": "x0"}, {"MESSAGE": "start", "__CURSOR": "x1"}, {"MESSAGE": "in", "__CURSOR": "x2"},
        {"MESSAGE": "end", "__CURSOR": "x3"}, {"MESSAGE": "after", "__CURSOR": "x4"}]
start, win = jo.window_of(rows, "start", "end")
if start["__CURSOR"] != "x1" or [e["__CURSOR"] for e in win] != ["x2"]:
    bad("window: not the entries between the markers")
for name, bad_rows, a, b in (("missing start", rows[2:], "start", "end"), ("missing end", rows[:3], "start", "end"),
                             ("twice", rows + rows[1:2], "start", "end"), ("reversed", rows, "end", "start")):
    try:
        jo.window_of(bad_rows, a, b)
        bad(f"window {name}: accepted")
    except ValueError:
        pass

# --- the queries of docs/audit.md
with open(DOC, encoding="utf-8") as f:
    doc = f.read()
queries = jo.extract_queries(doc, ALICE + 1, SVC, "k")
if len(queries) < 13:
    bad(f"extract: {len(queries)} queries found in the document, expected at least 13")
flat = [" ".join(a) for a, _ in queries]
for want in (f"CUSTODIO_UID={ALICE + 1}", "CUSTODIO_KEY_ID=k", f"CUSTODIO_APP_ID={jo.NO_SUCH_APP}", "CUSTODIO_APP_ID_STATE=none", "CUSTODIO_OPERATION=replace_certificate"):
    if not any(want in f for f in flat):
        bad(f"extract: no query with {want}")
if any("$" in f or "my-key" in f or "org.example" in f for f in flat) or not all(f"_UID={SVC}" in f for f in flat):
    bad("extract: a placeholder is left or the service account is not in every query")
DOC_OK = "```sh\njournalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) MESSAGE_ID=29c3100000 CUSTODIO_OUTCOME=1000 CUSTODIO_KEY_ID=my-key2\n```\n"
q = jo.extract_queries(DOC_OK, ALICE + 1, SVC, "k")
if q[0][0][2:] != ["MESSAGE_ID=29c3100000", "CUSTODIO_OUTCOME=1000", "CUSTODIO_KEY_ID=my-key2"]:
    bad(f"extract: a placeholder replaced inside another token: {q[0][0]}")
for name, text in (("unknown field", DOC_OK.replace("MESSAGE_ID", "CUSTODIO_NEW_FIELD")), ("option", DOC_OK.replace("MESSAGE_ID", "--since")),
                   ("shell", DOC_OK.replace("custodio.service", "custodio.service|cat")), ("no unit", DOC_OK.replace("_SYSTEMD_UNIT=custodio.service", "X=y")),
                   ("no account", DOC_OK.replace("_UID=$(id -u custodio)", "")), ("none", "```sh\nls\n```\n"), ("two accounts", DOC_OK.replace("MESSAGE_ID", "_UID=0 MESSAGE_ID"))):
    try:
        jo.extract_queries(text, ALICE + 1, SVC, "k")
        bad(f"extract {name}: accepted")
    except ValueError:
        pass


def simulate(args, entries):
    """What journalctl returns for the arguments over the entries."""
    pairs = [a.split("=", 1) for a in args]
    return [e for e in entries if all(e.get(n) == v for n, v in pairs)]


def run_queries(window, ledger, results):
    return jo.queries_problems([(i, a) for i, (a, _) in enumerate(queries, 1)], lambda i: results(i, queries[i - 1][0]),
                               {e["__CURSOR"] for e in window}, ledger, window, UNIT, SVC)


win = good()
outside = entry(line("o", "sign", "signed", "k", 900), 7)
everything = win + [outside]
ledger_u = [dict(x, uid=str(ALICE + 1)) for x in LEDGER]
win_u = [entry(x) for x in ledger_u]
for e in win_u:  # the queries have the uid of the extraction above, so the entries carry it too
    e["CUSTODIO_UID"] = str(ALICE + 1)
    e["MESSAGE"] = e["MESSAGE"].replace(f"uid {ALICE}", f"uid {ALICE + 1}")
ok("queries", run_queries(win_u, ledger_u, lambda i, a: simulate(a, win_u + [outside])))  # the outside entry is returned by the query but is not in the window
extra = entry(line("x", "sign", "signed", "k", 777), 8)
fails("a stray entry in the window", run_queries(win_u + [extra], ledger_u, lambda i, a: simulate(a, win_u + [extra])))
fails("a missing entry", run_queries(win_u, ledger_u, lambda i, a: simulate(a, win_u[1:])))
fails("a superset (an unfiltered query)", run_queries(win_u, ledger_u, lambda i, a: simulate([x for x in a if not x.startswith("CUSTODIO_OUTCOME")], win_u)))
forged = entry(LEDGER[0], 9, _UID="0", CUSTODIO_PID="555")
fails("a forged entry returned", run_queries(win_u + [forged], ledger_u, lambda i, a: simulate([x for x in a if not x.startswith("_")], win_u + [forged])))
ok("a forged entry excluded by the documented queries", run_queries(win_u + [forged], ledger_u, lambda i, a: simulate(a, win_u + [forged])))
fails("queries that predict nothing", run_queries(win_u, ledger_u, lambda i, a: []))
ok("queries over no entries at all", run_queries([], [], lambda i, a: []))

# --- the sweep of journal.py
with tempfile.TemporaryDirectory() as tmp:
    ev = os.path.join(tmp, "ev")
    os.mkdir(ev)
    cert = os.urandom(300)
    for name, data in (("cert.der", cert), ("sig.bin", os.urandom(256)), ("pw-wrong", b"not-the-password")):
        with open(os.path.join(ev, name), "wb") as f:
            f.write(data)

    def sweep(blob):
        path = os.path.join(tmp, "export")
        with open(path, "wb") as f:
            f.write(blob)
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "journal.py"), "sweep", "--export", path, "--evidence", ev, "--password", "e2e-password"],
                           capture_output=True, text=True, check=False)
        return r.returncode, r.stderr

    clean = b"MESSAGE=signature made: uid 1000 pid 1 key k\nCUSTODIO_KEY_ID=k\n\n"
    if sweep(clean)[0] != 0:
        bad("sweep: a clean export is reported")
    for form, blob in (("raw", cert), ("hex", cert.hex().encode()), ("base64", base64.b64encode(cert)), ("urlsafe base64", base64.urlsafe_b64encode(cert)),
                       ("password", b"x e2e-password y"), ("wrong password", b"not-the-password")):
        code, err = sweep(clean + b"X=" + blob + b"\n")
        if code == 0:
            bad(f"sweep: {form} planted and not reported")
        elif base64.b64encode(cert)[:16].decode() in err or cert.hex()[:16] in err:
            bad(f"sweep: the report shows the secret ({form})")
sys.exit(1 if failures else 0)
