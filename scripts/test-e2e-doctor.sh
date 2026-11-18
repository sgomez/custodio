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
# c WORD NAME TEXT [UNDER...]: one check line of the report and the lines under it, as doctor aligns them (the longest name is "key storage").
c() { local t; t=$(printf '  %-4s  %-11s  %s' "$1" "$2" "$3"); shift 3; for u in "$@"; do t+=$'\n'$(printf '%21s%s' '' "$u"); done; printf '%s' "$t"; }
# rep FINGERPRINT BROWSERS SYSTEM: a whole report, with its headings and the problems line.
rep() {
    local t=$'Fingerprint (optional)\n'"$1"$'\nBrowsers\n'"$2"$'\nSystem\n'"$3" p w
    p=$(printf '%s\n' "$t" | grep -cE '^  (FAIL|\?) ' || true)
    w=$(printf '%s\n' "$t" | grep -cE '^  warn |^ +Warning: ' || true)
    local sum=""
    [ "$p" = 0 ] || sum="$p problem$([ "$p" = 1 ] || echo s)"
    [ "$w" = 0 ] || sum+="${sum:+, }$w warning$([ "$w" = 1 ] || echo s)"
    [ -z "$sum" ] || t+=$'\n\n'"$sum."
    printf '%s' "$t"
}
L1=$(c FAIL reader 'fprintd is not installed' 'Fix: install fprintd and libpam-fprintd')
L2=$(c '?' finger 'no reader to ask' 'Fix: fix the reader first')
L3_OFF=$(c FAIL polkit off 'Fix: sudo custodio fingerprint enable')
L3_ON=$(c ok polkit on)
L3_BR=$(c FAIL polkit '/etc/pam.d/polkit-1 includes /usr/lib/pam.d/polkit-1, which is missing' 'No polkit dialog works, not even with the password.' 'Fix: reinstall polkit, or: sudo custodio fingerprint disable')
L4=$(c ok profiles 'none found, nothing to register')
L4N=$(c '?' profiles 'cannot look for them: x' "Fix: fix or remove that file, then run 'custodio doctor' again")
L5=$(c ok journal persistent)
L5N=$(c FAIL journal 'lost at reboot (Storage=volatile at x)' 'Fix: set Storage=persistent at x, then sudo systemctl restart systemd-journald')
L6=$(c warn 'key storage' '/var/lib/custodio: cannot tell if encrypted, x (not-block-filesystem)' 'Fix: x, or use disk encryption (LUKS)')
L6N=$(c '?' 'key storage' 'cannot ask the Custodio service: x' 'Fix: systemctl status custodio.service')
SYS="$L5"$'\n'"$L6"
# run DIR NAME OUT RC ERR
run() { w "$1/$2.out" "$3"$'\n'; w "$1/$2.rc" "$4"; w "$1/$2.err" "$5"; w "$1/$2.pam.before" 'a'; w "$1/$2.pam.after" 'a'; }
good() {
    local d=$1
    mkdir -p "$d"
    run "$d" base "$(rep "$L1"$'\n'"$L2"$'\n'"$L3_OFF" "$L4" "$SYS")" 0 ''
    run "$d" on "$(rep "$L1"$'\n'"$L2"$'\n'"$L3_ON" "$L4" "$SYS")" 0 ''
    run "$d" off "$(rep "$L1"$'\n'"$L2"$'\n'"$L3_OFF" "$L4" "$SYS")" 0 ''
    run "$d" broken "$(rep "$L3_BR"$'\n'"$L1"$'\n'"$L2" "$L4" "$SYS")" 1 ''
    run "$d" nofox "$(rep "$L1"$'\n'"$L2"$'\n'"$L3_OFF" "$L4N" "$SYS")" 1 ''
    run "$d" jflip "$(rep "$L1"$'\n'"$L2"$'\n'"$L3_OFF" "$L4" "$L5N"$'\n'"$L6")" 1 ''
    run "$d" nosvc "$(rep "$L1"$'\n'"$L2"$'\n'"$L3_OFF" "$L4" "$L5"$'\n'"$L6N")" 1 ''
    run "$d" never_run "$(rep "$L1"$'\n'"$L2"$'\n'"$L3_OFF" "$L4" "$SYS")" 0 ''
    w "$d/runs" $'base\njflip\nnever_run\non\nbroken\noff\nnofox\nnosvc'
    w "$d/journal.dir" 1; w "$d/journal.storage" auto; w "$d/jflip.dir" 1; w "$d/jflip.storage" volatile
    w "$d/storage.state" unknown; w "$d/storage.reason" not-block-filesystem
    w "$d/never.rc" 0; w "$d/never.pk.before" 0; w "$d/never.pk.after" 0; w "$d/never.sig.before" 0; w "$d/never.sig.after" 0; w "$d/never.groups" 'docuser users'
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
FP="$L1"$'\n'"$L2"$'\n'"$L3_OFF"
ctl missing-check six-checks 'not the checks in order' base.out "$(rep "$L1"$'\n'"$L3_OFF" "$L4" "$SYS")"
ctl no-word six-checks 'does not start with' base.out "$(rep "$FP"$'\n''  bad   reader       x' "$L4" "$SYS")"
ctl no-fix six-checks 'no fix line' base.out "$(rep "$FP" "$L4" "$L5"$'\n'"$(c FAIL 'key storage' x)")"
ctl wrong-section six-checks 'is under Browsers' base.out "$(rep "$FP" "$L4"$'\n'"$L5" "$L6")"
ctl problems-count six-checks 'the problems line says' base.out "$(rep "$FP" "$L4" "$SYS")"$'\n\n9 problems.'
ctl stderr six-checks 'stderr' base.err 'thread main panicked'
ctl stderr-after-report six-checks 'stderr is not empty' base.err 'custodio doctor: did not pass: key storage'
ctl exit0-with-unreachable exit-status 'exit 0' nosvc.rc 0
ctl check2-notok no-reader 'check 2 is not ok' base.out "$(rep "$L1"$'\n'"$(c FAIL finger none 'Fix: x')"$'\n'"$L3_OFF" "$L4" "$SYS")"
ctl check1-counted no-reader 'changed the exit status' on.rc 1
ctl exit1-without-counting exit-status 'without a counting line' base.rc 1
ctl exit0-with-notok exit-status 'exit 0' jflip.rc 0
ctl override-no-file override-active 'not on the system' override.present 0
ctl override-text override-active "through Custodio's own file" on.out "$(rep "$L1"$'\n'"$L2"$'\n'"$(c ok polkit 'on for the whole system (/etc/pam.d/common-auth), sudo too')" "$L4" "$SYS")"
ctl override-not-back override-active 'not back' off.out "$(rep "$L1"$'\n'"$L2"$'\n'"$L3_ON" "$L4" "$SYS")"
ctl broken-ignored broken-include "not 'not ok'" broken.out "$(rep "$L1"$'\n'"$L2"$'\n'"$L3_ON" "$L4" "$SYS")"
ctl broken-no-fix broken-include 'the fix is not' broken.out "$(rep "$(c FAIL polkit '/etc/pam.d/polkit-1 includes /usr/lib/pam.d/polkit-1, which is missing' 'No polkit dialog works.' 'Fix: x')"$'\n'"$L1"$'\n'"$L2" "$L4" "$SYS")"
ctl broken-first-notok broken-include 'not the first line' broken.out "$(rep "$L1"$'\n'"$L2"$'\n'"$L3_BR" "$L4" "$SYS")"
ctl fox-notok no-firefox-profile 'is not ok' base.out "$(rep "$FP" "$L4N" "$SYS")"
ctl fox-profile-line no-firefox-profile "not the one 'profiles' line" base.out "$(rep "$FP" "$(c FAIL Firefox 'a.default: not registered' 'Fix: custodio register, then restart the browsers')" "$SYS")"
ctl fox-home no-firefox-profile 'home is not as before' home.after 'changed'
ctl journal-ok-no-dir journal 'says not ok' journal.dir 0
ctl journal-no-flip journal 'did not flip' jflip.out "$(rep "$FP" "$L4" "$SYS")"
ctl storage-reason state-storage 'StateStorageReason' storage.reason 'no-mount'
ctl storage-ok state-storage 'service says encrypted' storage.state encrypted
ctl storage-warn state-storage 'service says not-encrypted' storage.state not-encrypted
ctl storage-nosvc state-storage 'nosvc' nosvc.out "$(rep "$FP" "$L4" "$SYS")"
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
