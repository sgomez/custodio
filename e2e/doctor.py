#!/usr/bin/env python3
"""Judge of the doctor-* cases (F204). Usage: doctor.py CASE OBSDIR.

The guest step (e2e/doctor-run.sh) writes observation files `OBSDIR/<name>`; this reads the ones a case needs and prints one problem per line on stdout
(exit 1 if any). A run R of `custodio doctor` leaves R.out, R.err, R.rc (and R.pam.before/R.pam.after, manifests of /etc/pam.d around it). The runs: base (no
override), on (override enabled), broken (override on, the file its include names moved aside), off (disabled again), nofox (~/.mozilla is a file), jflip (the
journal staged to the other state), nosvc (service stopped). Exit 0 cannot happen in a container (state directory on overlay); the 0 branch is F203's
(doctor_acceptance). Here the exit code is judged against the printed words, not alone.
"""
import os
import re
import sys

NAMES = ["fingerprint reader", "enrolled finger", "fingerprint for polkit", "module in browsers", "persistent journal", "state directory storage"]
WORDS = ("not ok", "could not check", "ok")  # longest-match order does not matter: each is followed by spaces
LINE = re.compile(r"^(ok|not ok|could not check) +([^:]+): (.*)$")
FIX = re.compile(r"^ {16}fix: (.*)$")
OPEN = "active through Custodio's override"
LATER = NAMES[3:]


def parse(out):
    """-> list of dicts word, name, text, fix (None when absent); a stray line is a dict with word None."""
    checks = []
    for ln in out.splitlines():
        m = LINE.match(ln)
        if m:
            checks.append({"word": m.group(1), "name": m.group(2), "text": m.group(3), "fix": None, "raw": ln})
            continue
        f = FIX.match(ln)
        if f and checks:
            checks[-1]["fix"] = f.group(1)
        elif re.match(r"^ {16}warning: ", ln) and checks:
            continue
        else:
            checks.append({"word": None, "name": "?", "text": ln, "fix": None, "raw": ln})
    return checks


def broken_include(c):
    return c["name"] == NAMES[2] and c["word"] == "not ok" and " includes " in c["text"] and ("is missing" in c["text"] or "not a regular file" in c["text"])


def counting(checks):
    """The names of the lines the exit status counts: a broken include and checks 4 to 6 that are not ok."""
    return [c["name"] for c in checks if broken_include(c) or (c["name"] in LATER and c["word"] != "ok")]


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
        return parse(read(f"{name}.out"))

    def line(checks, name):
        found = [c for c in checks if c["name"] == name]
        need(len(found) == 1, f"{len(found)} lines for '{name}'")
        return found[0] if found else {"word": None, "name": name, "text": "", "fix": None, "raw": ""}

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
            checks = run(r)
            order = [NAMES[2]] + NAMES[:2] + NAMES[3:] if checks and broken_include(checks[0]) else NAMES  # a broken include comes first
            need([c["name"] for c in checks] == order, f"{r}: the lines are {[c['name'] for c in checks]}, not the six checks in order")
            for c in checks:
                need(c["word"] in ("ok", "not ok", "could not check"), f"{r}: '{c['raw']}' does not start with ok, not ok or could not check")
                need(c["word"] == "ok" or bool(c["fix"]), f"{r}: '{c['name']}' is {c['word']} and has no fix line")
            err = read(f"{r}.err")
            need(not re.search(r"panic|backtrace|RUST_BACKTRACE|Traceback", err + read(f"{r}.out"), re.I), f"{r}: panic or backtrace text")
            lines = err.splitlines()
            need(all(x.startswith(("custodio", "Do what")) for x in lines) and len(lines) <= 3, f"{r}: stderr is more than the one-line diagnostic of the exit status: {err.strip()!r}")
            need(rc(r) == 1 or not lines, f"{r}: stderr is not empty on exit 0")
    elif case == "no-reader":
        base, on = run("base"), run("on")
        for r, checks in (("base", base), ("on", on)):
            one, two = line(checks, NAMES[0]), line(checks, NAMES[1])
            need(one["word"] in ("not ok", "could not check"), f"{r}: no reader in a container, but check 1 is {one['word']}")
            need(one["word"] != "not ok" or bool(one["fix"]), f"{r}: check 1 is not ok without a fix")
            need(two["word"] != "not ok", f"{r}: check 2 is not ok although check 1 saw no reader")
            exit_rule(r)
        need(line(base, NAMES[2])["word"] != line(on, NAMES[2])["word"], "check 3 did not change its word between base and on")
        need(rc("base") == rc("on"), "checks 1 to 3 changed the exit status")
        need([c["raw"] for c in base if c["name"] in LATER] == [c["raw"] for c in on if c["name"] in LATER], "checks 4 to 6 changed between base and on")
    elif case == "override-active":
        base, on, off = run("base"), run("on"), run("off")
        b, o, f = (line(x, NAMES[2]) for x in (base, on, off))
        need(o["word"] == "ok" and OPEN in o["text"], f"on: check 3 is '{o['raw']}', not ok with '{OPEN}'")
        need(OPEN not in b["text"], "base: check 3 names Custodio's override before enable")
        need(b["word"] != o["word"] or b["text"] != o["text"], "enable did not change check 3")
        need(read("on.include.exists").strip() == "1", "the file the override's include names does not exist")
        need(read("override.present").strip() == "1", "on: Custodio's override is not on the system")
        need(f["raw"] == b["raw"] and f["fix"] == b["fix"], "after disable check 3 is not back to the first line")
        for x in (on, off):
            need([c["raw"] for c in x if c["name"] in LATER] == [c["raw"] for c in base if c["name"] in LATER], "checks 4 to 6 differ across base/on/off")
    elif case == "broken-include":
        on, br = run("on"), run("broken")
        inc = read("broken.include").strip()
        need(inc.startswith("/"), "the include path was not read from the override")
        c3 = line(br, NAMES[2])
        need(c3["word"] == "not ok" and "missing" in c3["text"], f"broken: check 3 is '{c3['raw']}', not 'not ok' with the include missing")
        need(inc in c3["text"], f"broken: check 3 does not name {inc}")
        need("Reinstall polkit" in (c3["fix"] or "") and "custodio fingerprint disable" in (c3["fix"] or ""), "broken: the fix is not 'reinstall polkit or disable'")
        need(bool(br) and broken_include(br[0]), "broken: the include line is not the first line")
        need(NAMES[2] in counting(br), "broken: the include line is not among the counting lines")
        need(NAMES[2] not in counting(on), "on: the intact include counts")
        need(sorted(c["raw"] for c in br if c["name"] != NAMES[2]) == sorted(c["raw"] for c in on if c["name"] != NAMES[2]), "broken: other lines differ from the intact run")
        need(rc("broken") == 1, "broken: exit is not 1")
        exit_rule("broken")
    elif case == "no-firefox-profile":
        base, nf = run("base"), run("nofox")
        c = line(base, NAMES[3])
        need(c["word"] == "ok" and "no browser profile was found" in c["text"], f"base: '{c['raw']}' is not ok with 'no browser profile was found'")
        need(c["fix"] is None, "base: the no-profile line has a fix")
        need(NAMES[3] not in counting(base), "base: the no-profile line counts")
        n = line(nf, NAMES[3])
        need(n["word"] == "could not check", f"nofox: with ~/.mozilla a file the line is '{n['raw']}', not could not check")
        need(NAMES[3] in counting(nf), "nofox: the line does not count")
        need(read("home.before") == read("home.after"), "the home is not as before the runs")
    elif case == "journal":
        for r, tag in (("base", "journal"), ("jflip", "jflip")):
            c = line(run(r), NAMES[4])
            dir_ = read(f"{tag}.dir").strip() == "1"
            storage = read(f"{tag}.storage").strip() or "auto"
            want = "ok" if dir_ and storage not in ("volatile", "none") else "not ok"
            need(c["word"] == want, f"{r}: persistent journal is '{c['raw']}' but dir={int(dir_)} Storage={storage} says {want}")
            if want == "ok":
                need("the journal is persistent" in c["text"], f"{r}: ok without 'the journal is persistent'")
            else:
                fix = c["fix"] or ""
                need(("mkdir -p /var/log/journal" in fix) if not dir_ else ("restart systemd-journald" in fix), f"{r}: the fix does not name the documented step: {fix!r}")
        b, j = run("base"), run("jflip")
        need(line(b, NAMES[4])["word"] != line(j, NAMES[4])["word"], "the staged journal did not flip the line")
        need([c["raw"] for c in b if c["name"] != NAMES[4]] == [c["raw"] for c in j if c["name"] != NAMES[4]], "the flip changed another line")
    elif case == "state-storage":
        c = line(run("base"), NAMES[5])
        st, reason = read("storage.state").strip(), read("storage.reason").strip()
        if st == "encrypted":
            need(c["word"] == "ok", f"service says encrypted, doctor says '{c['raw']}'")
        elif st == "not-encrypted":
            need(c["word"] == "not ok" and "full-disk encryption" in (c["fix"] or ""), f"service says not-encrypted, doctor says '{c['raw']}'")
        elif st == "unknown":
            m = re.search(r"reason ([^:)]+)[:)]", c["text"])
            need(c["word"] == "not ok", f"service says unknown, doctor says '{c['raw']}'")
            need(bool(m) and m.group(1) == reason, f"the printed reason {m and m.group(1)!r} is not StateStorageReason {reason!r}")
        else:
            need(False, f"the service's StateStorage is {st!r}")
        s = line(run("nosvc"), NAMES[5])
        need(s["word"] == "could not check" and bool(s["fix"]), f"nosvc: '{s['raw']}' is not could not check with a fix")
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
