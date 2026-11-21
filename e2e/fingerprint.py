#!/usr/bin/env python3
"""Judge of the fingerprint-* cases (F199). Usage: fingerprint.py CASE OBSDIR.

The guest step (e2e/fingerprint-run.sh) writes observation files `OBSDIR/<case>.<name>`; this reads those of one case and prints one
problem per line on stdout (exit 1 if any). Notes the run record must show (SELinux not enforcing) go to stderr, prefixed `note:`.
Manifests: one line per path, `path type mode owner label hash [mtime]`, sorted; equal text means nothing changed.
"""
import os
import sys

# What `custodio setup fingerprint enable` writes (crates/custodio-cli/src/fingerprint_decide.rs, FILE).
EXPECTED = (
    "#%PAM-1.0\n"
    "# Written by 'custodio setup fingerprint enable'. Remove it with 'sudo custodio setup fingerprint disable'.\n"
    "# If you edit this file, Custodio treats it as yours and will not touch it again.\n"
    "auth     [success=done default=ignore] pam_fprintd.so max-tries=1 timeout=10\n"
    "auth     include /usr/lib/pam.d/polkit-1\n"
    "account  include /usr/lib/pam.d/polkit-1\n"
    "password include /usr/lib/pam.d/polkit-1\n"
    "session  include /usr/lib/pam.d/polkit-1\n"
)


def main(case, d):
    def read(name):
        p = os.path.join(d, f"{case}.{name}")
        if not os.path.isfile(p):
            raise KeyError(f"observation {case}.{name} is missing")
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()

    def pam_client(name):  # "rc=N fprintd=0|1"
        kv = dict(w.split("=", 1) for w in read(name).split() if "=" in w)
        return int(kv["rc"]), kv["fprintd"]

    problems = []

    def need(ok, msg):
        if not ok:
            problems.append(msg)

    def unchanged(before, after, what):
        b, a = read(before), read(after)
        need(b.strip() != "", f"{what}: the manifest taken before is empty (nothing was observed)")
        need(b == a, f"{what}: the manifests differ before and after")

    if case == "enable-file":
        need(read("rc").strip() == "0", "enable did not exit 0")
        need(read("content") == EXPECTED, "the file is not exactly Custodio's content")
        need(read("stat").split() == ["644", "root:root", "regular", "file"], f"mode, owner or type wrong: {read('stat').strip()}")
    elif case == "pam-password":
        rc, fp = pam_client("right")
        need(rc == 0, f"the right password was refused (rc {rc})")
        need(fp == "1", "pam_fprintd.so was not loaded: polkit-1 did not go through the override")
        rc, _ = pam_client("wrong")
        need(rc != 0, "a wrong password was accepted")
        rc, fp = pam_client("disabled")
        need(rc == 0, f"after disable the right password was refused (rc {rc})")
        need(fp == "0", "after disable pam_fprintd.so is still loaded")
    elif case == "enable-twice":
        need(read("rc").strip() == "0", "the second enable did not exit 0")
        unchanged("before", "after", "the second enable")
    elif case.startswith("refuse-"):
        need(read("rc").strip() not in ("0", ""), "the command did not refuse")
        cause = {"refuse-foreign": "/etc/pam.d/polkit-1", "refuse-no-vendor": "/usr/lib/pam.d/polkit-1", "refuse-no-module": "pam_fprintd"}[case]
        need(cause in read("out"), f"the message does not name the cause ({cause})")
        unchanged("before", "after", "the refusal")
    elif case == "disable-restores":
        need(read("rc").strip() == "0", "disable did not exit 0")
        before = read("before")
        need(before.strip() != "" and "/etc/pam.d/polkit-1 " not in before, "the manifest before enable is empty or holds polkit-1")
        need(before == read("after"), "/etc/pam.d is not byte for byte what it was before enable")
        need(read("agent-before") == read("agent-after") and read("agent-before").strip() != "", "the test agent's file is not back as it was")
    elif case == "pam-auth-update":
        need(read("rc-enable").strip() == "0" and read("rc-disable").strip() == "0", "pam-auth-update failed")
        o = read("override-before")
        need(o.strip() != "", "no override was observed")
        need(o == read("override-enabled"), "--enable fprintd altered the override")
        need(o == read("override-disabled"), "--disable fprintd altered the override")
        need(read("common-before") != read("common-enabled"), "common-auth did not change under --enable (the tool did not run)")
        need(read("common-before") == read("common-disabled"), "common-auth is not back after --disable")
    elif case == "selinux-label":
        need(read("rc").strip() == "0", "enable did not exit 0")
        if read("enforcing").strip() == "1":
            lab, dflt = read("label").strip(), read("default").strip()
            need(lab != "" and lab == dflt, f"label {lab!r} is not the policy default {dflt!r}")
            need(read("restorecon").strip() == "", "restorecon -n has something to change")
        else:
            print("note: SELinux not enforcing here: the label of the written file was NOT proven (enable ran, no label step failed)", file=sys.stderr)
    elif case == "authselect":
        need(read("rc").strip() == "0", "authselect apply-changes failed")
        o = read("override-before")
        need(o.strip() != "", "no override was observed")
        need(o == read("override-after"), "authselect apply-changes altered the override")
        need(read("system-modified") != read("system-original"), "the managed file was not modified before the call")
        need(read("system-after") == read("system-original"), "apply-changes did not regenerate the managed file (the tool did not act)")
    else:
        problems.append(f"unknown case {case}")
    for p in problems:
        print(f"{case}: {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    try:
        sys.exit(main(sys.argv[1], sys.argv[2]))
    except KeyError as e:
        print(f"{sys.argv[1]}: {e.args[0]}")
        sys.exit(1)
