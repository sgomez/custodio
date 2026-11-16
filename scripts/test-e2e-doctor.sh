#!/usr/bin/env bash
# F204: container-free check of e2e/doctor.py, the judge of the doctor-* cases: one accepted set of observations and, for each rule, a set that breaks only that rule and must be rejected
# with the rule's words. NOT checked here: the real runs (`just e2e-cases <target> 'doctor-*'`).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-doctor: $*" >&2; fail=1; }
w() { printf '%s' "$2" > "$1"; }
L1='not ok          fingerprint reader: fprintd is not installed
                fix: Install fprintd and libpam-fprintd.'
L2='could not check enrolled finger: there is no reader to ask (see the line above)
                fix: Fix the reader first, then run '"'"'custodio doctor'"'"' again.'
L2=${L2/could not check enrolled/could not check enrolled}
L3_OFF='not ok          fingerprint for polkit: fingerprint is not active for polkit
                fix: Run: sudo custodio fingerprint enable'
L3_ON="ok              fingerprint for polkit: active through Custodio's override /etc/pam.d/polkit-1"
L3_BR='not ok          fingerprint for polkit: Custodio'"'"'s override /etc/pam.d/polkit-1 includes /usr/lib/pam.d/polkit-1, which is missing: no polkit dialog can authenticate
                fix: Reinstall polkit (it ships that file), or remove the override: sudo custodio fingerprint disable'
L4='ok              module in browsers: no browser profile was found, so there is nothing to register'
L4N='could not check module in browsers: could not look for browser profiles: x
                fix: Fix or remove that file, then run '"'"'custodio doctor'"'"' again.'
L5='ok              persistent journal: the journal is persistent (/var/log/journal exists)'
L5N='not ok          persistent journal: Storage=volatile: the journal is kept in memory
                fix: As root: remove or change the line at x, then restart systemd-journald.'
L6='not ok          state directory storage: the service'"'"'s state directory is not known to be on an encrypted device (reason not-block-filesystem: x)
                fix: x Or use full-disk encryption on the disk that holds /var/lib/custodio (LUKS: x).'
L6N='could not check state directory storage: could not ask the Custodio service: x
                fix: Start it.'
ERR1='custodio doctor: did not pass: state directory storage'
# run DIR NAME OUT RC ERR
run() { w "$1/$2.out" "$3"$'\n'; w "$1/$2.rc" "$4"; w "$1/$2.err" "$5"; w "$1/$2.pam.before" 'a'; w "$1/$2.pam.after" 'a'; }
good() {
    local d=$1
    mkdir -p "$d"
    run "$d" base "$L1"$'\n'"$L2"$'\n'"$L3_OFF"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6" 1 "$ERR1"
    run "$d" on "$L1"$'\n'"$L2"$'\n'"$L3_ON"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6" 1 "$ERR1"
    run "$d" off "$L1"$'\n'"$L2"$'\n'"$L3_OFF"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6" 1 "$ERR1"
    run "$d" broken "$L3_BR"$'\n'"$L1"$'\n'"$L2"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6" 1 "$ERR1"$'\ncustodio doctor: a polkit include is broken'
    run "$d" nofox "$L1"$'\n'"$L2"$'\n'"$L3_OFF"$'\n'"$L4N"$'\n'"$L5"$'\n'"$L6" 1 "$ERR1"
    run "$d" jflip "$L1"$'\n'"$L2"$'\n'"$L3_OFF"$'\n'"$L4"$'\n'"$L5N"$'\n'"$L6" 1 "$ERR1"
    run "$d" nosvc "$L1"$'\n'"$L2"$'\n'"$L3_OFF"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6N" 1 "$ERR1"
    run "$d" never_run "$L1"$'\n'"$L2"$'\n'"$L3_OFF"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6" 1 "$ERR1"
    w "$d/runs" $'base\njflip\nnever_run\non\nbroken\noff\nnofox\nnosvc'
    w "$d/journal.dir" 1; w "$d/journal.storage" auto; w "$d/jflip.dir" 1; w "$d/jflip.storage" volatile
    w "$d/storage.state" unknown; w "$d/storage.reason" not-block-filesystem
    w "$d/never.rc" 1; w "$d/never.pk.before" 0; w "$d/never.pk.after" 0; w "$d/never.sig.before" 0; w "$d/never.sig.after" 0; w "$d/never.groups" 'docuser users'
    w "$d/override.present" 1; w "$d/on.include.exists" 1; w "$d/broken.include" /usr/lib/pam.d/polkit-1
    w "$d/home.before" 'h'; w "$d/home.after" 'h'; w "$d/etc.before" 'e'; w "$d/etc.after" 'e'
    w "$d/root.rc" 2; w "$d/root.out" ''; w "$d/root.err" 'custodio doctor: refused to run as root'; w "$d/root.etc.before" 'e'; w "$d/root.etc.after" 'e'
}
J() { python3 -I "$ROOT/e2e/doctor.py" "$@"; }
CASES="six-checks no-reader override-active broken-include no-firefox-profile journal state-storage exit-status never-prompts root-refused changes-nothing"
good "$tmp/ok"
for c in $CASES; do J "$c" "$tmp/ok" > "$tmp/out" 2>&1 || bad "accepted set rejected for $c: $(cat "$tmp/out")"; done
# ctl NAME CASE WORDS FILE CONTENT: a copy of the accepted set with one file changed must be rejected with WORDS
ctl() {
    local d=$tmp/c-$1
    cp -r "$tmp/ok" "$d"
    printf '%s' "$5" > "$d/$4"
    if J "$2" "$d" > "$tmp/out" 2>&1; then bad "$1: accepted"; elif ! grep -qF -- "$3" "$tmp/out"; then bad "$1: rejected without '$3': $(cat "$tmp/out")"; fi
}
ctl missing-check six-checks 'not the six checks' base.out "$L1"$'\n'"$L3_OFF"$'\n'
ctl no-word six-checks 'does not start with' base.out "fingerprint reader: x"$'\n'
ctl no-fix six-checks 'no fix line' base.out "$L1"$'\n'"$L2"$'\n'"$L3_OFF"$'\n'"$L4"$'\n'"$L5"$'\n''not ok          state directory storage: x'$'\n'
ctl stderr six-checks 'stderr' base.err 'thread main panicked'
ctl stderr-on-zero-run exit-status 'exit 0' base.rc 0
ctl check2-notok no-reader 'check 2 is not ok' base.out "$L1"$'\n''not ok          enrolled finger: none'$'\n'"$L3_OFF"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6"$'\n'
ctl check1-counted no-reader 'changed the exit status' on.rc 0
ctl exit1-without-counting exit-status 'without a counting line' off.out "$L1"$'\n'"$L2"$'\n'"$L3_OFF"$'\n'"$L4"$'\n'"$L5"$'\n'"ok              state directory storage: the service's state directory is on an encrypted device"$'\n'
ctl exit0-with-notok exit-status 'exit 0' base.rc 0
ctl override-no-file override-active 'not on the system' override.present 0
ctl override-text override-active 'not ok with' on.out "$L1"$'\n'"$L2"$'\n'"ok              fingerprint for polkit: active for the whole system"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6"$'\n'
ctl override-not-back override-active 'not back' off.out "$L1"$'\n'"$L2"$'\n'"$L3_ON"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6"$'\n'
ctl broken-ignored broken-include 'not ok' broken.out "$L1"$'\n'"$L2"$'\n'"$L3_ON"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6"$'\n'
ctl broken-no-fix broken-include 'the fix is not' broken.out "${L3_BR%%$'\n'*}"$'\n''                fix: x'$'\n'"$L1"$'\n'"$L2"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6"$'\n'
ctl broken-first-notok broken-include 'not the first line' broken.out "$L1"$'\n'"$L2"$'\n'"$L3_BR"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6"$'\n'
ctl fox-notok no-firefox-profile 'is not ok with' base.out "$L1"$'\n'"$L2"$'\n'"$L3_OFF"$'\n'"$L4N"$'\n'"$L5"$'\n'"$L6"$'\n'
ctl fox-home no-firefox-profile 'home is not as before' home.after 'changed'
ctl journal-ok-no-dir journal 'says not ok' journal.dir 0
ctl journal-no-flip journal 'did not flip' jflip.out "$L1"$'\n'"$L2"$'\n'"$L3_OFF"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6"$'\n'
ctl storage-reason state-storage 'StateStorageReason' storage.reason 'no-mount'
ctl storage-ok state-storage 'service says encrypted' storage.state encrypted
ctl storage-nosvc state-storage 'nosvc' nosvc.out "$L1"$'\n'"$L2"$'\n'"$L3_OFF"$'\n'"$L4"$'\n'"$L5"$'\n'"$L6"$'\n'
ctl never-limit never-prompts 'time limit' never.rc 124
ctl never-pk never-prompts 'polkit request' never.pk.after 1
ctl never-sig never-prompts 'signature entry' never.sig.after 1
ctl never-sudo never-prompts 'sudo rights' never.groups 'docuser sudo'
ctl root-ok root-refused 'not 2' root.rc 0
ctl root-etc root-refused '/etc changed' root.etc.after 'x'
ctl etc-changed changes-nothing 'etc: the manifests differ' etc.after 'x'
ctl home-changed changes-nothing 'home: the manifests differ' home.after 'x'
ctl pam-changed changes-nothing 'on: /etc/pam.d changed' on.pam.after 'b'
# a missing observation is a rejection
rm "$tmp/ok/base.out"; J six-checks "$tmp/ok" > "$tmp/out" 2>&1 && bad "a missing observation was accepted"
[ "$fail" = 0 ] || exit 1
echo "test-e2e-doctor: passed"
