#!/usr/bin/env python3
"""Judge of the doctor-* cases (F204). Usage: doctor.py CASE OBSDIR.

The guest step (e2e/doctor-run.sh) writes observation files `OBSDIR/<name>`; this reads the ones a case needs and prints one problem per line on stdout
(exit 1 if any). A run R of `custodio doctor` leaves R.out, R.err, R.rc (and R.pam.before/R.pam.after, manifests of /etc/pam.d around it). The runs: base (no
override), on (override enabled), broken (override on, the file its include names moved aside), off (disabled again), nofox (~/.mozilla is a file), jflip (the
journal staged to the other state), nosvc (service stopped). Exit 0 cannot happen in a container (state directory on overlay); the 0 branch is F203's
(doctor_acceptance). Here the exit code is judged against the printed states, not alone. The report's format is known in parse() only;
the rules judge states, sections, the exit code and fix lines, and of the words only the commands and paths a person acts on.
"""
import os
import re
import sys

FINGERPRINT, BROWSERS, SYSTEM = "Fingerprint (optional)", "Browsers", "System"
SECTIONS = [FINGERPRINT, BROWSERS, SYSTEM]
READER, FINGER, POLKIT, PROFILES, JOURNAL, STORAGE = "reader", "finger", "polkit", "profiles", "journal", "key storage"
FINGERPRINT_NAMES = [READER, FINGER, POLKIT]
SYSTEM_NAMES = [JOURNAL, STORAGE]
STATES = {"ok": "ok", "FAIL": "not ok", "warn": "warn", "?": "could not check"}
SUMMARY = re.compile(r"^(\d+) problems?\.$")


def parse(out):
    """-> (checks, problems line count or None, stray headings). Each check: word (ok, not ok, warn, could not check, or None for a line
    that is no check), section, name, text, fixes, notes, warnings, raw (the check line and the lines under it)."""
    checks, summary, headings, section = [], None, [], None
    for ln in out.splitlines():
        if not ln:
            continue
        if not ln.startswith(" "):
            m = SUMMARY.match(ln)
            if m:
                summary = int(m.group(1))
            else:
                section = ln
                headings.append(ln)
            continue
        body = ln.lstrip(" ")
        if len(ln) - len(body) == 2:
            word, _, rest = body.partition(" ")
            name, _, text = rest.lstrip(" ").partition("  ")
            checks.append({"word": STATES.get(word), "section": section, "name": name, "text": text.lstrip(" "),
                           "fixes": [], "notes": [], "warnings": [], "raw": ln})
            continue
        if not checks:
            checks.append({"word": None, "section": section, "name": "?", "text": ln, "fixes": [], "notes": [], "warnings": [], "raw": ln})
            continue
        c = checks[-1]
        c["raw"] += "\n" + ln
        if body.startswith("Fix: "):
            c["fixes"].append(body[5:])
        elif body.startswith("Warning: "):
            c["warnings"].append(body[9:])
        else:
            c["notes"].append(body)
    return checks, summary, headings


def section_of(name):
    return FINGERPRINT if name in FINGERPRINT_NAMES else SYSTEM if name in SYSTEM_NAMES else BROWSERS


def broken_include(checks, c):
    """A broken include is the polkit line printed first, not ok, with a note of what it breaks."""
    return bool(checks) and c is checks[0] and c["name"] == POLKIT and c["word"] == "not ok" and bool(c["notes"])


def counting(checks):
    """The names of the lines the exit status counts: a broken include, and the Browsers and System lines that are not ok."""
    return [c["name"] for c in checks if broken_include(checks, c) or (c["section"] in (BROWSERS, SYSTEM) and c["word"] != "ok")]


def later(checks):
    return [c["raw"] for c in checks if c["section"] in (BROWSERS, SYSTEM)]


def main(case, d):
    problems = []

    def need(ok, msg):
        if not ok:
            problems.append(msg)

    def read(name):
        p = os.path.join(d, name)
        if not os.path.isfile(p):
            raise KeyError(f"observation {name} is missing")
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()

    def rc(run):
        return int(read(f"{run}.rc").strip())

    def run(name):
        return parse(read(f"{name}.out"))[0]

    def line(checks, name):
        found = [c for c in checks if c["name"] == name]
        need(len(found) == 1, f"{len(found)} lines for '{name}'")
        return found[0] if found else {"word": None, "section": None, "name": name, "text": "", "fixes": [], "notes": [], "warnings": [], "raw": ""}

    def user_runs():
        return read("runs").split()

    def exit_rule(r):
        checks, code = run(r), rc(r)
        want = 1 if counting(checks) else 0
        need(code == want, f"{r}: exit {code} but the printed lines say {want} (counting lines: {counting(checks) or 'none'})")
        if code == 1:
            need(bool(counting(checks)), f"{r}: exit 1 without a counting line")
        need(code in (0, 1), f"{r}: exit {code} is not 0 or 1")

    if case == "six-checks":
        for r in user_runs():
            checks, summary, headings = parse(read(f"{r}.out"))
            fp = [c["name"] for c in checks if c["section"] == FINGERPRINT]
            fp_order = [POLKIT, READER, FINGER] if checks and broken_include(checks, checks[0]) else FINGERPRINT_NAMES  # a broken include comes first
            browsers = [c for c in checks if c["section"] == BROWSERS]
            need(headings == SECTIONS, f"{r}: the headings are {headings}, not {SECTIONS}")
            need(fp == fp_order and [c["name"] for c in checks if c["section"] == SYSTEM] == SYSTEM_NAMES and len(browsers) >= 1,
                 f"{r}: the lines are {[c['name'] for c in checks]}, not the checks in order")
            for c in checks:
                need(c["word"] is not None, f"{r}: '{c['raw']}' does not start with ok, FAIL, warn or ?")
                need(c["word"] is None or c["section"] == section_of(c["name"]), f"{r}: '{c['name']}' is under {c['section']}")
            for c in browsers:
                need(c["word"] == "ok" or any(b["fixes"] for b in browsers), f"{r}: the browser line '{c['name']}' is {c['word']} and the section has no fix line")
            for c in checks:
                if c["section"] != BROWSERS:
                    need(c["word"] in ("ok", None) or bool(c["fixes"]), f"{r}: '{c['name']}' is {c['word']} and has no fix line")
            problems_n = sum(1 for c in checks if c["word"] != "ok" or c["warnings"])
            need(summary == (problems_n or None), f"{r}: the problems line says {summary}, the report has {problems_n}")
            err = read(f"{r}.err")
            need(not re.search(r"panic|backtrace|RUST_BACKTRACE|Traceback", err + read(f"{r}.out"), re.I), f"{r}: panic or backtrace text")
            need(err.strip() == "", f"{r}: stderr is not empty after a report: {err.strip()!r}")
    elif case == "no-reader":
        base, on = run("base"), run("on")
        for r, checks in (("base", base), ("on", on)):
            one, two = line(checks, READER), line(checks, FINGER)
            need(one["word"] in ("not ok", "could not check"), f"{r}: no reader in a container, but check 1 is {one['word']}")
            need(one["word"] != "not ok" or bool(one["fixes"]), f"{r}: check 1 is not ok without a fix")
            need(two["word"] != "not ok", f"{r}: check 2 is not ok although check 1 saw no reader")
            exit_rule(r)
        need(line(base, POLKIT)["word"] != line(on, POLKIT)["word"], "check 3 did not change its state between base and on")
        need(rc("base") == rc("on"), "checks 1 to 3 changed the exit status")
        need(later(base) == later(on), "the Browsers and System lines changed between base and on")
    elif case == "override-active":
        base, on, off = run("base"), run("on"), run("off")
        b, o, f = (line(x, POLKIT) for x in (base, on, off))
        # Someone else's file and the global fingerprint name the file that does it; Custodio's own names none.
        need(o["word"] == "ok" and "/" not in o["text"] and not o["fixes"], f"on: polkit is '{o['raw']}', not ok through Custodio's own file")
        need(b["word"] != "ok", "base: polkit is ok before enable")
        need(read("on.include.exists").strip() == "1", "the file the override's include names does not exist")
        need(read("override.present").strip() == "1", "on: Custodio's override is not on the system")
        need(f["raw"] == b["raw"], "after disable polkit is not back to the first line")
        for x in (on, off):
            need(later(x) == later(base), "the Browsers and System lines differ across base/on/off")
    elif case == "broken-include":
        on, br = run("on"), run("broken")
        inc = read("broken.include").strip()
        need(inc.startswith("/"), "the include path was not read from the override")
        c3 = line(br, POLKIT)
        need(c3["word"] == "not ok", f"broken: polkit is '{c3['raw']}', not 'not ok'")
        need(inc in c3["text"], f"broken: polkit does not name {inc}")
        need(any("sudo custodio fingerprint disable" in x for x in c3["fixes"]), "broken: the fix is not 'sudo custodio fingerprint disable'")
        need(bool(br) and broken_include(br, br[0]), "broken: the include line is not the first line")
        need(POLKIT in counting(br), "broken: the include line is not among the counting lines")
        need(POLKIT not in counting(on), "on: the intact include counts")
        need(sorted(c["raw"] for c in br if c["name"] != POLKIT) == sorted(c["raw"] for c in on if c["name"] != POLKIT), "broken: other lines differ from the intact run")
        need(rc("broken") == 1, "broken: exit is not 1")
        exit_rule("broken")
    elif case == "no-firefox-profile":
        base, nf = run("base"), run("nofox")
        lines = [c for c in base if c["section"] == BROWSERS]
        need(len(lines) == 1 and lines[0]["name"] == PROFILES, f"base: the Browsers lines are {[c['raw'] for c in lines]}, not the one '{PROFILES}' line")
        c = line(base, PROFILES)
        need(c["word"] == "ok", f"base: '{c['raw']}' is not ok")
        need(not c["fixes"], "base: the no-profile line has a fix")
        need(PROFILES not in counting(base), "base: the no-profile line counts")
        n = line(nf, PROFILES)
        need(n["word"] == "could not check", f"nofox: with ~/.mozilla a file the line is '{n['raw']}', not could not check")
        need(PROFILES in counting(nf), "nofox: the line does not count")
        need(read("home.before") == read("home.after"), "the home is not as before the runs")
    elif case == "journal":
        for r, tag in (("base", "journal"), ("jflip", "jflip")):
            c = line(run(r), JOURNAL)
            dir_ = read(f"{tag}.dir").strip() == "1"
            storage = read(f"{tag}.storage").strip() or "auto"
            want = "ok" if dir_ and storage not in ("volatile", "none") else "not ok"
            need(c["word"] == want, f"{r}: journal is '{c['raw']}' but dir={int(dir_)} Storage={storage} says {want}")
            if want != "ok":
                fix = " ".join(c["fixes"])
                need(("mkdir -p /var/log/journal" in fix) if not dir_ else ("restart systemd-journald" in fix), f"{r}: the fix does not name the documented step: {fix!r}")
        b, j = run("base"), run("jflip")
        need(line(b, JOURNAL)["word"] != line(j, JOURNAL)["word"], "the staged journal did not flip the line")
        need([c["raw"] for c in b if c["name"] != JOURNAL] == [c["raw"] for c in j if c["name"] != JOURNAL], "the flip changed another line")
    elif case == "state-storage":
        c = line(run("base"), STORAGE)
        st, reason = read("storage.state").strip(), read("storage.reason").strip()
        if st == "encrypted":
            need(c["word"] == "ok", f"service says encrypted, doctor says '{c['raw']}'")
        elif st == "not-encrypted":
            need(c["word"] == "warn" and any("LUKS" in x for x in c["fixes"]), f"service says not-encrypted, doctor says '{c['raw']}'")
        elif st == "unknown":
            need(c["word"] == "not ok" and bool(c["fixes"]), f"service says unknown, doctor says '{c['raw']}'")
            need(bool(reason) and reason in c["text"], f"the line does not name StateStorageReason {reason!r}: {c['text']!r}")
        else:
            need(False, f"the service's StateStorage is {st!r}")
        s = line(run("nosvc"), STORAGE)
        need(s["word"] == "could not check" and any("custodio.service" in x for x in s["fixes"]), f"nosvc: '{s['raw']}' is not could not check with a fix naming custodio.service")
    elif case == "exit-status":
        for r in user_runs():
            exit_rule(r)
    elif case == "never-prompts":
        need(rc("never") in (0, 1), f"never: exit {rc('never')} (124 is the time limit)")
        need(read("never.pk.before") == read("never.pk.after"), "a polkit request appeared in the journal")
        need(read("never.sig.before") == read("never.sig.after"), "a signature entry appeared in the journal")
        need(not (set(read("never.groups").split()) & {"sudo", "wheel", "admin", "root"}), "the account has sudo rights")
    elif case == "root-refused":
        need(rc("root") == 2, f"root: exit {rc('root')}, not 2")
        need(read("root.out").strip() == "", "root: stdout is not empty (check lines were printed)")
        need("refused to run as root" in read("root.err"), "root: the refusal is not on stderr")
        need(read("root.etc.before") == read("root.etc.after") and read("root.etc.before").strip() != "", "root: /etc changed")
    elif case == "changes-nothing":
        for n in ("etc", "home"):
            b, a = read(f"{n}.before"), read(f"{n}.after")
            need(b.strip() != "", f"{n}: the manifest taken before is empty")
            need(b == a, f"{n}: the manifests differ before and after")
        for r in user_runs():
            b = read(f"{r}.pam.before")
            need(b.strip() != "", f"{r}: the /etc/pam.d manifest is empty")
            need(b == read(f"{r}.pam.after"), f"{r}: /etc/pam.d changed during the run")
    else:
        problems.append(f"unknown case {case}")
    return problems


if __name__ == "__main__":
    try:
        found = main(sys.argv[1], sys.argv[2])
    except KeyError as e:
        found = [str(e.args[0])]
    for p in found:
        print(p)
    sys.exit(1 if found else 0)
