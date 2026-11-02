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
_spec = importlib.util.spec_from_file_location("jo", os.path.join(HERE, "jo.py"))
jo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(jo)

PREFIX, SUFFIX = b"app-flatpak-", b".scope"
MAX_NAME = MAX_ID = 255  # MAX_SCOPE_NAME_LEN and MAX_APP_ID_LEN of crates/custodiod/src/app_id.rs; the reader's own rules, mirrored to build the names
MAX_INSTANCE_DIGITS = 10
FILL, CAP_ID = b"appid-fill-", "org.example.CapCaller"
FLATPAK_ID = "org.example.My_App-Name"
KEY = "ai-key"
ABS_SLACK_CEILING = 5.0  # seconds: the slowest call of a non-sandboxed caller may not be slower than this, so that the slack cannot grow the limit unnoticed
PLAN_FIELDS = ("label", "phase", "kind", "cg", "op", "mode", "outcome", "app_state", "app_id", "result")
OBS_FIELDS = ("label", "pid", "uid", "result", "dur_ms", "nreq", "subj")
ROW_FIELDS = ("label", "phase", "kind", "cg", "op", "mode", "outcome", "app_state", "app_id", "result", "pid", "uid", "dur", "nreq", "subj")
NON_SANDBOXED = ("session", "gnome")


# --- the reader's rules (crates/custodiod/src/app_id.rs, mirrored)
def valid_id(ident):
    if not ident or len(ident) > MAX_ID:
        return False
    parts = ident.split(b".")
    if len(parts) < 3:
        return False
    for number, element in enumerate(parts):
        if not element or element[:1].isdigit():
            return False
        for ch in element:
            if not (chr(ch).isascii() and (chr(ch).isalnum() or chr(ch) == "_" or (chr(ch) == "-" and number == len(parts) - 1))):
                return False
    return True


def reader_state(name):
    """(state, id) the reader gives for the name of a scope, apart from the cap on the number of children."""
    if not name.startswith(PREFIX):
        return "none", None
    if len(name) > MAX_NAME:
        return "undetermined", None
    middle = name[len(PREFIX):]
    if not middle.endswith(SUFFIX):
        return "undetermined", None
    middle = middle[:-len(SUFFIX)]
    split = middle.find(b"-")
    if split < 0 or middle.rfind(b"-") != split:
        return "undetermined", None
    escaped, instance = middle[:split], middle[split + 1:]
    if not (instance and len(instance) <= MAX_INSTANCE_DIGITS and instance.isdigit() and int(instance) <= 0xFFFFFFFF):
        return "undetermined", None
    ident, rest = b"", escaped
    while rest:
        if rest[:1] == b"\\":
            if not rest[1:].startswith(b"x2d"):
                return "undetermined", None
            ident, rest = ident + b"-", rest[4:]
        else:
            ident, rest = ident + rest[:1], rest[1:]
    if not valid_id(ident):
        return "undetermined", None
    return "read", ident.decode("ascii")


def scope_name(ident, instance):
    return PREFIX + ident.replace("-", "\\x2d").encode() + b"-" + str(instance).encode() + SUFFIX


def padded(head, tail, size, fill=b"a"):
    """head + fill * n + tail, exactly SIZE bytes."""
    return head + fill * (size - len(head) - len(tail)) + tail


def generate_names(rng):
    """[(label, name, state, id, marker)]: the callers that are not made by a plain systemd-run, with the answer the reader must give. A hostile name holds a
    marker of its own (unique to the run), which must be found nowhere in the journal. The cap callers are added by cap_setup."""
    def marker():
        return "Mk" + "".join(rng.choice("0123456789abcdef") for _ in range(10))

    rows = []
    maxid = padded(b"org.example.Max", b"", MAX_NAME - len(PREFIX) - len(SUFFIX) - 2).decode()  # the instance "1" and its "-"
    rows.append(("max", scope_name(maxid, 1), "read", maxid, "-"))
    hostile = {  # label -> function of the marker
        "h-two-hyphens": lambda m: b"app-flatpak-org.hostile.%s-1-2.scope" % m,
        "h-instance-text": lambda m: b"app-flatpak-org.hostile.%s-abc.scope" % m,
        "h-instance-long": lambda m: b"app-flatpak-org.hostile.%s-12345678901.scope" % m,
        "h-instance-overflow": lambda m: b"app-flatpak-org.hostile.%s-4294967296.scope" % m,
        "h-escape-other": lambda m: b"app-flatpak-org.hostile.%s\\x41-1.scope" % m,
        "h-escape-upper": lambda m: b"app-flatpak-org.hostile.%s\\x2Dx-1.scope" % m,
        "h-id-two-elements": lambda m: b"app-flatpak-hostile.%s-1.scope" % m,
        "h-id-digit-start": lambda m: b"app-flatpak-org.9hostile.%s-1.scope" % m,
        "h-id-hyphen-early": lambda m: b"app-flatpak-org.host\\x2dile.%s-1.scope" % m,
        "h-chars": lambda m: b"app-flatpak-org.hostile.%s ;$(x)'\"\xc3\xa9-1.scope" % m,
        "h-no-suffix": lambda m: b"app-flatpak-org.hostile.%s-1.scoop" % m,
        "h-256": lambda m: padded(b"app-flatpak-org.hostile.%s" % m, b"-1.scope", 256),
        "h-255-invalid": lambda m: padded(b"app-flatpak-org.9hostile.%s" % m, b"-1.scope", 255),
    }
    for label, make in hostile.items():
        m = marker()
        name = make(m.encode())
        rows.append((label, name, "undetermined", None, m))
    for label, name, state, ident, _m in rows:
        if reader_state(name) != (state, ident):
            raise ValueError(f"{label}: the reader's rules give {reader_state(name)}, expected {(state, ident)}: the name is not what its case needs")
    if len(rows[0][1]) != MAX_NAME:
        raise ValueError("the edge name is not exactly 255 bytes")
    return rows


def write_names(path, rows, append=False):
    with open(path, "a" if append else "w", encoding="ascii") as f:
        for label, name, state, ident, m in rows:
            f.write(f"{label}\t{name.hex()}\t{state}\t{ident or '-'}\t{m}\n")


def read_names(path):
    out = {}
    with open(path, encoding="ascii") as f:
        for line in f:
            if line.strip():
                label, hexname, state, ident, m = line.rstrip("\n").split("\t")
                out[label] = {"label": label, "name": bytes.fromhex(hexname), "state": state, "id": None if ident == "-" else ident, "marker": None if m == "-" else m}
    return out


# --- the cap: more children of app.slice than the reader walks
def cap_pick(order, candidates, cap):
    """(after, within) among CANDIDATES by their place in ORDER (the order of os.listdir, the order the scan walks): the one with the highest index
    and the one with the lowest, or None when the first is not past the cap or the second not inside it."""
    index = {name: i for i, name in enumerate(order)}
    placed = sorted((index[c], c) for c in candidates if c in index)
    if len(placed) < 2:
        return None
    return placed[-1][1], placed[0][1]


def cap_problems(order, after, within, cap):
    """The place of the two callers in the walk. The 4097th child is the first the scan refuses (scan.rs: seen > MAX_CHILDREN), i.e. index CAP counting from 0.
    Past the cap also means more children than the cap. A margin of 2 and 3: the scope of the systemd-run that starts a caller is one more child while the caller moves, and it goes away after."""
    problems = []
    if after not in order or within not in order:
        return problems + ["a cap caller is not a child of app.slice"]
    if order.index(after) < cap + 2:
        problems.append(f"the over-cap caller is child number {order.index(after)} (from 0), not after the cap {cap}")
    if order.index(within) > cap - 3:
        problems.append(f"the inside caller is child number {order.index(within)} (from 0), not within the first {cap}")
    return problems


def as_user(uid, gid, function):
    os.setegid(gid)
    os.seteuid(uid)
    try:
        return function()
    finally:
        os.seteuid(0)
        os.setegid(0)


def cap_setup(slice_path, cap, uid, gid, names_path, tries=30):
    sl = os.fsencode(slice_path)
    existing = os.listdir(sl)
    if any(n.startswith(FILL) for n in existing):
        raise ValueError("children of an earlier run are still in app.slice")
    for i in range(max(0, cap + 300 - len(existing))):
        os.mkdir(os.path.join(sl, FILL + str(i).encode()))  # root's own children: only the count matters
    for attempt in range(tries):
        base = 1000 + 100 * attempt
        names = [scope_name(CAP_ID, base + k) for k in range(40)]
        for n in names:  # alice's: she must be able to write their cgroup.procs
            as_user(uid, gid, lambda n=n: os.mkdir(os.path.join(sl, n)))
        picked = cap_pick(os.listdir(sl), names, cap)
        for n in names:
            if picked is None or n not in picked:
                os.rmdir(os.path.join(sl, n))
        if picked is not None and not cap_problems(os.listdir(sl), picked[0], picked[1], cap):
            write_names(names_path, [("cap-after", picked[0], "undetermined", None, "-"), ("cap-within", picked[1], "read", CAP_ID, "-")], append=True)
            return len(os.listdir(sl)), os.listdir(sl).index(picked[0]), os.listdir(sl).index(picked[1])
        for n in picked or ():
            os.rmdir(os.path.join(sl, n))
    raise ValueError("no pair of cap callers found: after the cap and inside it")


def cap_check(slice_path, cap, names_path):
    names = read_names(names_path)
    order = os.listdir(os.fsencode(slice_path))
    return cap_problems(order, names["cap-after"]["name"], names["cap-within"]["name"], cap)


def cap_teardown(slice_path, names_path):
    sl = os.fsencode(slice_path)
    names = read_names(names_path)
    gone = {names[k]["name"] for k in ("cap-after", "cap-within") if k in names}
    for n in os.listdir(sl):
        if n.startswith(FILL) or n in gone:
            os.rmdir(os.path.join(sl, n))
    left = [n for n in os.listdir(sl) if n.startswith(FILL) or n in gone]
    return [f"{len(left)} children of the cap step are still in app.slice"] if left else []


def cleanup(slice_path, names_path):
    sl = os.fsencode(slice_path)
    for row in read_names(names_path).values():
        try:
            os.rmdir(os.path.join(sl, row["name"]))
        except FileNotFoundError:
            pass
    left = {row["name"] for row in read_names(names_path).values()} & set(os.listdir(sl))
    return [f"{len(left)} scopes of the step are still in app.slice"] if left else []


def slice_path(mount, control_group, uid):
    """The tree the daemon walks (scan.rs tree_root and open_app_slice): everything in front of system.slice in the daemon's own cgroup."""
    parts = control_group.strip().strip("/").split("/")
    if "system.slice" not in parts:
        raise ValueError("the control group of the service has no system.slice")
    prefix = parts[:parts.index("system.slice")]
    return os.path.join(mount, *prefix, "user.slice", f"user-{uid}.slice", f"user@{uid}.service", "app.slice")


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


# --- the journal as a whole
def parse_export(data):
    """[[(name, value)]]: the entries of `journalctl -o export`: text fields NAME=value, binary fields NAME, 8 bytes of length, the data."""
    entries, current, pos = [], [], 0
    while pos < len(data):
        end = data.find(b"\n", pos)
        end = len(data) if end < 0 else end
        line = data[pos:end]
        if not line:
            if current:
                entries.append(current)
            current, pos = [], end + 1
        elif b"=" in line:
            name, _, value = line.partition(b"=")
            current.append((name.decode("ascii", "replace"), value))
            pos = end + 1
        else:
            size = int.from_bytes(data[end + 1:end + 9], "little")
            current.append((line.decode("ascii", "replace"), data[end + 9:end + 9 + size]))
            pos = end + 9 + size + 1
    if current:
        entries.append(current)
    return entries


def needles_of(row):
    """Texts of a hostile scope that must be nowhere: its marker, the whole name, and the id part in its escaped and unescaped forms."""
    name = row["name"]
    out = [("marker", row["marker"].encode()), ("name", name)]
    middle = name[len(PREFIX):]
    cut = middle.find(b"-")
    if cut > 0:
        out += [("escaped id text", middle[:cut]), ("unescaped id text", middle[:cut].replace(b"\\x2d", b"-"))]
    return [(kind, text) for kind, text in out if len(text) >= 8]


def sweep_problems(export, names):
    """The hostile names found in the export of the journal: in any field of any entry of any unit, with no exclusion."""
    needles = [(label, kind, text) for label, row in names.items() if row["marker"] for kind, text in needles_of(row)]
    if not needles:
        return ["no hostile name to look for"]
    problems = []
    for entry in parse_export(export):
        unit = next((v for n, v in entry if n == "_SYSTEMD_UNIT"), b"no unit")
        # the name of a unit is shown only if it is a plain unit name that holds nothing of a hostile scope
        unit = unit.decode() if re.fullmatch(rb"[A-Za-z0-9@._-]{1,80}", unit) and not any(t in unit for _l, _k, t in needles) else "a unit with an odd name"
        for name, value in entry:
            for label, kind, text in needles:
                if text in value:
                    problems.append(f"{label}: the {kind} of a hostile scope is in the field {name} of an entry of unit {unit}")
    return sorted(set(problems))


def deadline_seconds(doc_text):
    m = re.search(r"longer than (\d+) s \(the bound, `LOOKUP_DEADLINE`\)", doc_text)
    if not m:
        raise ValueError("docs/audit.md does not state the lookup bound (`LOOKUP_DEADLINE`)")
    return int(m.group(1))


def bound_problems(rows, deadline, scale=1.0):
    """Every call returns within the documented bound plus a slack: the slowest call of the non-sandboxed callers of the same step, itself under a
    stated ceiling."""
    quiet = [r["dur"] for r in rows if r["kind"] in NON_SANDBOXED]
    if not quiet:
        return ["no call of a non-sandboxed caller to measure the slack by"]
    slack = max(quiet)
    problems = []
    if slack > ABS_SLACK_CEILING:
        problems.append(f"the slowest non-sandboxed call took {slack:.2f} s, more than the ceiling {ABS_SLACK_CEILING} s of the slack")
    limit = (deadline + slack) * scale
    for r in rows:
        if r["dur"] > limit:
            problems.append(f"{r['label']}: the call took {r['dur']:.2f} s, the limit is {limit:.2f} s")
    return problems


def app_query_problems(queries, ids):
    """Every documented query that names the app-id is one this step judges: by id, or by one of the three states; and all four forms are there."""
    problems, forms = [], set()
    for args, raw in queries:
        filters = [a for a in args if a.split("=")[0] not in ("_SYSTEMD_UNIT", "_UID")]
        if not any(a.startswith("CUSTODIO_APP_ID") for a in filters):
            continue
        if len(filters) == 1 and filters[0].startswith("CUSTODIO_APP_ID="):
            forms.add("id")
        elif len(filters) == 1 and filters[0] in {f"CUSTODIO_APP_ID_STATE={s}" for s in jo.APP_ID_STATES}:
            forms.add(filters[0].split("=")[1])
        else:
            problems.append(f"the documented query '{raw}' names the app-id in a way this step does not judge")
    problems += [f"docs/audit.md has no query by {m}" for m in ("id", *jo.APP_ID_STATES) if m not in forms]
    return problems


def extract(doc_text, uid, service_uid, key, app_ids):
    found = {}
    for ident in app_ids:
        for args, raw in jo.extract_queries(doc_text, uid, service_uid, key, ident):
            found.setdefault(tuple(args), (args, raw))
    queries = list(found.values())
    return app_query_problems(queries, app_ids), queries


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
