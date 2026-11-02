#!/usr/bin/python3 -I
"""The checks of the appid judgements (appid.py, with jo.py under it) on made-up evidence, good and bad (F95). Container-free; the guest runs it first.
Usage: appid-selftest.py E2E-DIR DOC (the directory with appid.py, jo.py and appid-ledger.txt, and docs/audit.md)."""
import copy
import importlib.util
import os
import random
import subprocess
import sys
import tempfile

HERE, DOC = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("appid", os.path.join(HERE, "appid.py"))
ai = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ai)
jo = ai.jo
UNIT, SVC, ALICE = "custodio.service", 998, 1000
failures = []


def bad(msg):
    failures.append(msg)
    print(f"appid-selftest: {msg}", file=sys.stderr)


def ok(name, problems):
    if problems:
        bad(f"{name}: problems on good evidence: {problems[:3]}")


def fails(name, problems):
    if not problems:
        bad(f"{name}: no problem on bad evidence")


# --- the world: the names, the plan with what alice saw, the entries, the export
NAMES_LIST = [("flatpak", ai.scope_name(ai.FLATPAK_ID, 5151), "read", ai.FLATPAK_ID, "-")] + ai.generate_names(random.Random(7)) + [
    ("cap-after", ai.scope_name(ai.CAP_ID, 1002), "undetermined", None, "-"), ("cap-within", ai.scope_name(ai.CAP_ID, 1001), "read", ai.CAP_ID, "-")]
with tempfile.TemporaryDirectory() as tmp:
    ai.write_names(os.path.join(tmp, "names.tsv"), NAMES_LIST)
    NAMES = ai.read_names(os.path.join(tmp, "names.tsv"))
with open(os.path.join(HERE, "appid-ledger.txt"), encoding="utf-8") as f:
    PLAN = f.read()


def observed(**over):
    """The observation of every call of the plan: a pid per call, one request, the polkit subject of the call, 300 ms; OVER: label -> field changes."""
    plan, _ = ai.read_plan(PLAN)
    lines = []
    for number, (label, p) in enumerate(plan.items()):
        pid = 2000 + number
        rec = {"label": label, "pid": str(pid), "uid": str(ALICE), "result": p["result"], "dur_ms": "300", "nreq": "1", "subj": f"{pid}/{ALICE}"}
        rec.update(over.get(label, {}))
        lines.append("\t".join(rec[k] for k in ai.OBS_FIELDS))
    return "\n".join(lines) + "\n"


def world(**over):
    problems, rows = ai.merge_problems(PLAN, NAMES, observed(**over), ALICE)
    return problems, rows


p0, ROWS = world()
ok("merge", p0)
if len(ROWS) < 30:
    bad(f"the plan has only {len(ROWS)} calls")


def entry(row, n=0, **over):
    message_id, outcomes = jo.OPERATIONS[row["op"]]
    prio, text = outcomes[row["outcome"]]
    e = {"_SYSTEMD_UNIT": UNIT, "_UID": str(SVC), "MESSAGE_ID": message_id, "CUSTODIO_OPERATION": row["op"], "CUSTODIO_OUTCOME": row["outcome"],
         "CUSTODIO_KEY_ID": row["key"], "CUSTODIO_UID": row["uid"], "CUSTODIO_PID": row["pid"], "PRIORITY": prio, "SYSLOG_IDENTIFIER": "custodiod",
         "MESSAGE": f"{text}: uid {row['uid']} pid {row['pid']} key {row['key']}", "CUSTODIO_APP_ID_STATE": row["app_state"], "__CURSOR": f"c{row['pid']}{n}"}
    if row["app_state"] == "read":
        e["CUSTODIO_APP_ID"] = row["app_id"]
    if row["keytype"] != "-":
        e["CUSTODIO_KEY_TYPE"] = row["keytype"]
    e.update(over)
    return {k: v for k, v in e.items() if v is not None}


def good():
    return [entry(r) for r in ROWS]


def row_of(label, rows=None):
    return next(r for r in (rows or ROWS) if r["label"] == label)


def window_with(label, **over):
    w = good()
    for i, r in enumerate(ROWS):
        if r["label"] == label:
            w[i].update(over)
            w[i] = {k: v for k, v in w[i].items() if v is not None}
    return w


def case(name, window=None, rows=None):
    return ai.case_problems(name, window if window is not None else good(), rows or ROWS, UNIT, SVC)


# --- the names: the reader's rules, mirrored, give what each case needs
for name, want in [(b"app-flatpak-org.example.My_App\\x2dName-5151.scope", ("read", "org.example.My_App-Name")), (b"app-gnome-gedit-99b.scope", ("none", None)),
                   (b"run-p226-i4693560.scope", ("none", None)), (b"app-flatpak-org.a.b-1-2.scope", ("undetermined", None)),
                   (b"app-flatpak-org.a.b-4294967295.scope", ("read", "org.a.b")), (b"app-flatpak-org.a.b-4294967296.scope", ("undetermined", None)),
                   (b"app-flatpak-org.a.b\\x2D-1.scope", ("undetermined", None)), (b"app-flatpak-a.b-1.scope", ("undetermined", None)),
                   (b"app-flatpak-org.a.b-1.scoope", ("undetermined", None)), (b"app-flatpak-org.a.b--1.scope", ("undetermined", None))]:
    if ai.reader_state(name) != want:
        bad(f"reader_state({name!r}) is {ai.reader_state(name)}, expected {want}")
if len(NAMES["max"]["name"]) != 255 or ai.reader_state(NAMES["max"]["name"])[0] != "read":
    bad("the edge name is not 255 bytes and valid")
if [len(NAMES[k]["name"]) for k in ("h-256", "h-255-invalid")] != [256, 255]:
    bad("the oversized names are not 256 and 255 bytes")
for label, row in NAMES.items():
    if row["marker"] and (row["state"] != "undetermined" or row["id"] is not None):
        bad(f"{label}: a hostile name that is not undetermined")
    if row["marker"] and row["marker"].encode() not in row["name"]:
        bad(f"{label}: the marker is not in the name")
markers = [r["marker"] for r in NAMES.values() if r["marker"]]
if len(set(markers)) != len(markers) or len(markers) < 10:
    bad("the markers are not unique or too few")
for hostile in ("h-escape-other", "h-instance-overflow", "h-id-digit-start", "h-256"):
    if hostile not in NAMES:
        bad(f"no hostile name {hostile}")
# a name that would be valid is refused when it is made a hostile one
orig = ai.reader_state
ai.reader_state = lambda name: ("read", "org.a.b")
try:
    ai.generate_names(random.Random(1))
    bad("generate_names accepts names the reader would read")
except ValueError:
    pass
ai.reader_state = orig
if ai.generate_names(random.Random(7)) != ai.generate_names(random.Random(7)):
    bad("generate_names is not a function of the seed")
if ai.slice_path("/sys/fs/cgroup", "/abc123/system.slice/custodio.service", 1000) != "/sys/fs/cgroup/abc123/user.slice/user-1000.slice/user@1000.service/app.slice":
    bad("slice_path in a container is wrong")
if ai.slice_path("/sys/fs/cgroup", "/system.slice/custodio.service", 7) != "/sys/fs/cgroup/user.slice/user-7.slice/user@7.service/app.slice":
    bad("slice_path on a host is wrong")
try:
    ai.slice_path("/sys/fs/cgroup", "/abc/custodio.service", 1)
    bad("slice_path accepts a control group without system.slice")
except ValueError:
    pass

# --- merge: the plan and what alice saw
p, _ = world()
ok("merge", p)
obs = observed().splitlines()
for what, text in [("a call not made", "\n".join(obs[1:]) + "\n"), ("a call twice", "\n".join(obs + obs[:1]) + "\n"),
                   ("a call the plan lacks", "\n".join(obs + ["nosuch\t1\t1000\tok\t1\t1\t-"]) + "\n"), ("a short line", "\n".join(obs + ["x\ty"]) + "\n")]:
    fails(f"merge {what}", ai.merge_problems(PLAN, NAMES, text, ALICE)[0])
fails("merge another uid", ai.merge_problems(PLAN, NAMES, observed(**{"sign-flatpak-approve": {"uid": "0"}}), ALICE)[0])
fails("merge a pid used twice", ai.merge_problems(PLAN, NAMES, observed(**{"sign-flatpak-approve": {"pid": "2002"}}), ALICE)[0])
fails("merge a pid that is no number", ai.merge_problems(PLAN, NAMES, observed(**{"sign-flatpak-approve": {"pid": "x"}}), ALICE)[0])
fails("merge a scope that was not made", ai.merge_problems(PLAN.replace(" h-two-hyphens ", " h-nowhere ", 1), NAMES, observed(), ALICE)[0])
fails("merge a state the scope does not give", ai.merge_problems(PLAN.replace("main cg h-two-hyphens sign approve signed undetermined -", "main cg h-two-hyphens sign approve signed none -"), NAMES, observed(), ALICE)[0])
fails("merge an id with the state none", ai.merge_problems(PLAN.replace("sign approve signed none -", "sign approve signed none flatpak", 1), NAMES, observed(), ALICE)[0])
fails("merge state read without an id", ai.merge_problems(PLAN.replace("import approve stored read flatpak", "import approve stored read -", 1), NAMES, observed(), ALICE)[0])
fails("merge an operation that is none", ai.merge_problems(PLAN.replace(" sign approve signed", " zap approve signed", 1), NAMES, observed(), ALICE)[0])

# --- the cases: exactly one entry per call with its fields, its state and its id
for c in ai.CASES:
    ok(c, case(c))
    if not [r for r in ROWS if ai.CASES[c](r)]:
        bad(f"{c}: the plan has no call for it")
for c in ai.CASES:
    fails(f"{c} without a call", ai.case_problems(c, good(), [r for r in ROWS if not ai.CASES[c](r)], UNIT, SVC))
CASE_ROW = {"appid-flatpak": "sign-flatpak-approve", "appid-flatpak-max": "sign-max-approve", "appid-cap": "sign-cap-after-deny", "appid-operations": "import-flatpak",
            "appid-none": "sign-gnome-deny", "appid-hostile": "sign-h-256-approve"}
for c, label in CASE_ROW.items():
    fails(f"{c} wrong state", case(c, window_with(label, CUSTODIO_APP_ID_STATE="read" if row_of(label)["app_state"] != "read" else "none")))
    fails(f"{c} state missing", case(c, window_with(label, CUSTODIO_APP_ID_STATE=None)))
    fails(f"{c} wrong pid", case(c, window_with(label, CUSTODIO_PID="1")))
    fails(f"{c} outcome", case(c, window_with(label, CUSTODIO_OUTCOME="authorization_unavailable")))
    fails(f"{c} uid", case(c, window_with(label, CUSTODIO_UID="0")))
    if row_of(label)["app_state"] != "read":
        fails(f"{c} an app-id with the state {row_of(label)['app_state']}", case(c, window_with(label, CUSTODIO_APP_ID="org.example.Other")))
    w = good()
    w.append(copy.deepcopy(w[[i for i, r in enumerate(ROWS) if r["label"] == label][0]]))
    fails(f"{c} the call twice", case(c, w))
    fails(f"{c} the entry missing", case(c, [e for e in good() if e["CUSTODIO_PID"] != row_of(label)["pid"]]))
fails("flatpak id missing", case("appid-flatpak", window_with("sign-flatpak-approve", CUSTODIO_APP_ID=None)))
fails("flatpak id of another app", case("appid-flatpak", window_with("sign-flatpak-approve", CUSTODIO_APP_ID="org.example.My_App")))
fails("flatpak id not unescaped", case("appid-flatpak", window_with("sign-flatpak-approve", CUSTODIO_APP_ID="org.example.My_App\\x2dName")))
fails("max id cut", case("appid-flatpak-max", window_with("sign-max-approve", CUSTODIO_APP_ID=NAMES["max"]["id"][:-1])))
fails("hostile entry that read the id of the name", case("appid-hostile", window_with("sign-h-256-approve", CUSTODIO_APP_ID_STATE="read", CUSTODIO_APP_ID="org.hostile")))
fails("cap-within given undetermined", case("appid-cap", window_with("sign-cap-within-approve", CUSTODIO_APP_ID_STATE="undetermined", CUSTODIO_APP_ID=None)))
fails("an operation with the state of another", case("appid-operations", window_with("delete-flatpak", CUSTODIO_APP_ID_STATE="none", CUSTODIO_APP_ID=None)))
# loosely compared state: an entry that says `read` for a call that must be `none` or `undetermined` is wrong, whatever else it holds
fails("hostile read as none", case("appid-hostile", window_with("sign-h-two-hyphens-deny", CUSTODIO_APP_ID_STATE="none")))
fails("none read as undetermined", case("appid-none", window_with("sign-session-approve", CUSTODIO_APP_ID_STATE="undetermined")))

# --- the whole: no entry without a call, as many entries as calls, and what each call gave
VERIFY, UNSIGNED = (lambda label: True), (lambda label: True)


def outcome(window=None, rows=None, verify=VERIFY, unsigned=UNSIGNED):
    return ai.outcome_problems(rows or ROWS, window if window is not None else good(), UNIT, SVC, verify, unsigned)


ok("outcome", outcome())
fails("outcome an entry no call explains", outcome(good() + [entry(dict(ROWS[0], pid="9"))]))
fails("outcome an entry short", outcome(good()[1:]))
fails("outcome an entry of another unit", outcome([dict(e, _SYSTEMD_UNIT="other.service") for e in good()]))
for label, over, name in [("sign-h-256-approve", {"result": "denied"}, "result"), ("sign-session-approve", {"nreq": "2"}, "two requests"),
                          ("sign-flatpak-approve", {"nreq": "0"}, "no request"), ("sign-max-deny", {"subj": "5/1000"}, "subject pid"),
                          ("sign-gnome-deny", {"subj": f"{2000 + 8}/0"}, "subject uid"), ("sign-h-chars-approve", {"subj": "-"}, "no subject"),
                          ("import-flatpak", {"result": "denied"}, "import result")]:
    _, rows = ai.merge_problems(PLAN, NAMES, observed(**{label: over}), ALICE)
    if "result" in over:
        rows = [dict(r, got=over["result"]) if r["label"] == label else r for r in rows]
    fails(f"outcome {name}", outcome(rows=rows))
fails("outcome a signature that does not verify", outcome(verify=lambda label: label != "sign-h-chars-approve"))
fails("outcome a signature after a denial", outcome(unsigned=lambda label: label != "sign-h-chars-deny"))
fails("outcome no non-sandboxed baseline", outcome(rows=[r for r in ROWS if r["kind"] not in ai.NON_SANDBOXED]))
rows = copy.deepcopy(ROWS)
for r in rows:  # every call asked twice, the baseline too: still wrong, a call asks the agent once
    r["nreq"] = 2
fails("outcome every call asked twice", outcome(rows=rows))

# --- the sweep: nothing of a hostile name anywhere


def export(entries):
    out = b""
    for e in entries:
        for k, v in e.items():
            if isinstance(v, bytes):
                out += k.encode() + b"\n" + len(v).to_bytes(8, "little") + v + b"\n"
            elif k != "__CURSOR":
                out += f"{k}={v}\n".encode()
        out += b"\n"
    return out


def sweep(entries=None, extra=b""):
    return ai.sweep_problems(export(entries if entries is not None else good()) + extra, NAMES)


ok("sweep", sweep())
ok("sweep with a valid name in the journal", sweep(good() + [{"MESSAGE": "Started " + NAMES["flatpak"]["name"].decode(), "_SYSTEMD_UNIT": "user@1000.service"}]))
ok("sweep with the 255-byte valid name in an entry", sweep(good() + [{"MESSAGE": NAMES["max"]["name"].decode(), "_SYSTEMD_UNIT": "user@1000.service"}]))
H = NAMES["h-two-hyphens"]
for what, e in [("MESSAGE of the service", {"MESSAGE": "see " + H["name"].decode(), "_SYSTEMD_UNIT": UNIT}),
                ("MESSAGE of another unit", {"MESSAGE": "Started " + H["name"].decode(), "_SYSTEMD_UNIT": "user@1000.service"}),
                ("the marker alone", {"MESSAGE": "x " + H["marker"], "_SYSTEMD_UNIT": UNIT}),
                ("a CUSTODIO field", {"CUSTODIO_APP_ID": H["name"].decode(), "_SYSTEMD_UNIT": UNIT}),
                ("the unit field", {"_SYSTEMD_UNIT": H["name"].decode()}),
                ("a field that is not text", {"_SYSTEMD_UNIT": UNIT, "MESSAGE": b"\x00\x01" + H["name"]}),
                ("_CMDLINE", {"_CMDLINE": "systemd-run " + H["marker"], "_SYSTEMD_UNIT": "x.service"}),
                ("the unescaped form", {"MESSAGE": NAMES["h-id-hyphen-early"]["name"].replace(b"\\x2d", b"-").decode(), "_SYSTEMD_UNIT": "x.service"}),
                ("the escaped id text", {"MESSAGE": NAMES["h-escape-other"]["name"][12:].split(b"-")[0].decode() + "x", "_SYSTEMD_UNIT": "x.service"}),
                ("a 256-byte name", {"MESSAGE": NAMES["h-256"]["name"].decode(), "_SYSTEMD_UNIT": "x.service"})]:
    probs = sweep(good() + [e])
    fails(f"sweep {what}", probs)
    if any(H["name"].decode(errors="replace") in p for p in probs):
        bad(f"sweep {what}: the problem repeats the hostile text")
fails("sweep with no hostile name to look for", ai.sweep_problems(export(good()), {k: dict(v, marker=None) for k, v in NAMES.items()}))
for label in [k for k, v in NAMES.items() if v["marker"]]:  # every hostile name is looked for
    fails(f"sweep for {label}", sweep(good() + [{"MESSAGE": "n " + NAMES[label]["marker"], "_SYSTEMD_UNIT": "x.service"}]))
entries = ai.parse_export(export([{"A": "1", "B": b"two\nlines", "C": "3"}, {"A": "4"}]))
if entries != [[("A", b"1"), ("B", b"two\nlines"), ("C", b"3")], [("A", b"4")]]:
    bad(f"parse_export: {entries}")

# --- the bound
ok("bound", ai.bound_problems(ROWS, 1))
slow = copy.deepcopy(ROWS)
row_of("sign-h-256-approve", slow)["dur"] = 2.6
fails("bound a call over the limit", ai.bound_problems(slow, 1))
slow = copy.deepcopy(ROWS)
row_of("sign-cap-after-deny", slow)["dur"] = 1.29
ok("bound the limit is the bound plus the slowest quiet call (0.3 s)", ai.bound_problems(slow, 1))
row_of("sign-cap-after-deny", slow)["dur"] = 1.31
fails("bound just over", ai.bound_problems(slow, 1))
slow = copy.deepcopy(ROWS)
for r in slow:
    if r["kind"] in ai.NON_SANDBOXED:
        r["dur"] = ai.ABS_SLACK_CEILING + 1
fails("bound slack above the ceiling", ai.bound_problems(slow, 1))
fails("bound without a quiet caller", ai.bound_problems([r for r in ROWS if r["kind"] not in ai.NON_SANDBOXED], 1))
fails("bound scaled to zero", ai.bound_problems(ROWS, 1, 0))
fails("bound a bound of zero seconds", ai.bound_problems(ROWS, 0, 0.5))
if ai.deadline_seconds(open(DOC, encoding="utf-8").read()) != 1:
    bad("the document does not state a 1 s bound")
try:
    ai.deadline_seconds("nothing")
    bad("deadline_seconds accepts a document without the bound")
except ValueError:
    pass

# --- the cap
ORDER = [b"n%05d" % i for i in range(4400)]
ok("cap", ai.cap_problems(ORDER, ORDER[4300], ORDER[20], 4096))
ok("cap just after", ai.cap_problems(ORDER, ORDER[4098], ORDER[4093], 4096))
fails("cap the over-cap caller is the last of the cap", ai.cap_problems(ORDER, ORDER[4095], ORDER[20], 4096))
fails("cap the over-cap caller is the first past the cap", ai.cap_problems(ORDER, ORDER[4096], ORDER[20], 4096))
fails("cap the inside caller is too close to the cap", ai.cap_problems(ORDER, ORDER[4300], ORDER[4094], 4096))
fails("cap the inside caller is past the cap", ai.cap_problems(ORDER, ORDER[4300], ORDER[4200], 4096))
fails("cap the count is not over the cap", ai.cap_problems(ORDER[:4096], ORDER[4090], ORDER[20], 4096))
fails("cap a caller that is no child", ai.cap_problems(ORDER, b"nothing", ORDER[20], 4096))
if ai.cap_pick(ORDER, [ORDER[5], ORDER[900], ORDER[4300]], 4096) != (ORDER[4300], ORDER[5]):
    bad("cap_pick does not choose the highest and the lowest place")
if ai.cap_pick(ORDER, [ORDER[5]], 4096) is not None:
    bad("cap_pick chose with a single candidate")

# --- the documented queries
SVC_TXT = jo.SERVICE_UID_TEXT
DOC_TEXT = open(DOC, encoding="utf-8").read()
IDS = sorted({r["app_id"] for r in ROWS if r["app_id"]}) + [jo.NO_SUCH_APP]
p, QUERIES = ai.extract(DOC_TEXT, ALICE, SVC, ai.KEY, IDS)
ok("extract", p)
if len(QUERIES) < 8:
    bad(f"only {len(QUERIES)} queries extracted")
if len([q for q in QUERIES if any(a.startswith("CUSTODIO_APP_ID=") for a in q[0])]) != len(IDS):
    bad("the by-id query is not run once per id")
fails("extract a document with an app-id query this step does not judge",
      ai.extract(DOC_TEXT.replace("```\n\n", f"journalctl _SYSTEMD_UNIT=custodio.service _UID={SVC_TXT} CUSTODIO_APP_ID_STATE=read CUSTODIO_OUTCOME=signed\n```\n\n", 1), ALICE, SVC, ai.KEY, IDS)[0])
fails("extract a document with a state it does not judge", ai.extract(DOC_TEXT.replace("CUSTODIO_APP_ID_STATE=none", "CUSTODIO_APP_ID_STATE=maybe"), ALICE, SVC, ai.KEY, IDS)[0])
fails("extract a document without the query by state", ai.extract(DOC_TEXT.replace("CUSTODIO_APP_ID_STATE=undetermined", "CUSTODIO_OUTCOME=denied"), ALICE, SVC, ai.KEY, IDS)[0])
try:
    ai.extract(DOC_TEXT.replace("CUSTODIO_APP_ID_STATE=none", "CUSTODIO_APP_ID_STATE=none CUSTODIO_PID=7"), ALICE, SVC, ai.KEY, IDS)
    bad("extract accepts a field it does not know how to judge")
except ValueError:
    pass


def journalctl(query_args, entries):
    """What `journalctl ARGS` would return from ENTRIES: the entries that hold every field=value."""
    want = [a.split("=", 1) for a in query_args]
    return [e for e in entries if all(e.get(k) == v for k, v in want)]


def queries_run(window=None, ledger=None, results=None):
    w = window if window is not None else good()
    # the entries of other units, and the entries of the service from before the window (earlier steps): a query returns them, the window drops them
    noise = [dict(e, _SYSTEMD_UNIT="other.service", __CURSOR="n" + e["__CURSOR"]) for e in w] + [dict(e, __CURSOR="old" + e["__CURSOR"]) for e in w]
    qs = [(i, a) for i, (a, _raw) in enumerate(QUERIES, 1)]
    got = results or (lambda i: journalctl(dict(qs)[i], w + noise))
    return jo.queries_problems(qs, got, {e["__CURSOR"] for e in w}, ledger or ROWS, w, UNIT, SVC)


ok("queries", queries_run())
fails("queries an entry missing from a query", queries_run(results=lambda i: journalctl(dict((i2, a) for i2, (a, _r) in enumerate(QUERIES, 1))[i], good())[1:]))
w = good()
fails("queries an entry that says the state loosely", queries_run(window=window_with("sign-h-256-deny", CUSTODIO_APP_ID_STATE="none", CUSTODIO_APP_ID=None)))
fails("queries a ledger that lists another id", queries_run(ledger=[dict(r, app_id="org.example.Other") if r["label"] == "sign-flatpak-approve" else r for r in ROWS]))
fails("queries no query predicts anything", queries_run(ledger=[dict(r, app_state="none", app_id=None) for r in ROWS[:1]], window=good()[:1]))
used = [a for a, _r in QUERIES if f"CUSTODIO_APP_ID={ai.FLATPAK_ID}" in a]
if not used or not journalctl(used[0], good()):
    bad("the query by a used id returns nothing in the good world")
unused = [a for a, _r in QUERIES if f"CUSTODIO_APP_ID={jo.NO_SUCH_APP}" in a]
if not unused or journalctl(unused[0], good()):
    bad("the query by an id no call used returns something")

# --- the ledger file and the signatures with the real openssl
rows_file = os.path.join(tempfile.mkdtemp(), "ledger")
ai.write_rows(rows_file, ROWS)
if [{k: v for k, v in r.items() if k not in ("key", "keytype")} for r in ai.read_rows(rows_file)] != [{k: v for k, v in r.items() if k not in ("key", "keytype")} for r in ROWS]:
    bad("the ledger file does not read back as written")
if subprocess.run(["openssl", "version"], capture_output=True, check=False).returncode == 0:
    with tempfile.TemporaryDirectory() as d:
        run = lambda *a: subprocess.run(a, cwd=d, capture_output=True, check=True)  # noqa: E731
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "k.pem")
        run("openssl", "pkey", "-in", "k.pem", "-pubout", "-out", "pub.pem")
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "k2.pem")
        with open(os.path.join(d, "data.bin"), "wb") as f:
            f.write(os.urandom(2000))
        run("openssl", "dgst", "-sha256", "-sign", "k.pem", "-out", "sig-a.bin", "data.bin")
        run("openssl", "dgst", "-sha256", "-sign", "k2.pem", "-out", "sig-b.bin", "data.bin")
        open(os.path.join(d, "sig-c.bin"), "w").close()
        verify, unsigned = ai.verify_with_openssl(d, os.path.join(d, "pub.pem"), os.path.join(d, "data.bin"))
        if not verify("a") or verify("b") or verify("c") or verify("missing"):
            bad("verify_with_openssl: a signature that verifies, one of another key, an empty one or a missing one")
        if unsigned("a") or not unsigned("c") or not unsigned("missing"):
            bad("verify_with_openssl: unsigned")

sys.exit(1 if failures else 0)
