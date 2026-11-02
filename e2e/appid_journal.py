#!/usr/bin/python3 -I
"""The judgements of the journal as a whole in the appid-* cases (F95): the sweep for hostile text, the bound on the wall time and the documented queries; a
part of appid.py, which re-exports it."""
import importlib.util
import os
import re

_spec = importlib.util.spec_from_file_location("jo", os.path.join(os.path.dirname(os.path.abspath(__file__)), "jo.py"))
jo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(jo)

PREFIX = b"app-flatpak-"  # as in appid_rules.py: this file is loaded by its path, and `python3 -I` puts no directory on sys.path
ABS_SLACK_CEILING = 5.0  # seconds: the slowest call of a non-sandboxed caller may not be slower than this, so that the slack cannot grow the limit unnoticed
NON_SANDBOXED = ("session", "gnome")

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


