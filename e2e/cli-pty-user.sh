#!/usr/bin/env bash
# Runs as carol in one logind session (`su -l`) with WORK and MODULE set by cli-run.sh (F97): the cases in which NO polkit agent is registered, so that what answers
# polkit is `pkttyagent`, started by the CLI. PAM service polkit-1 checks carol's password (cli-run.sh set it up), so the password typed is really checked.
# Snapshots go through root as in cli-user.sh (NAME.user, NAME.state, NAME.slots). Calls are recorded in $CLI/pcalls as "LABEL<TAB>RESULT<TAB>LOGGED" (LOGGED empty:
# there is no agent to log). Passwords come from files cli-run.sh wrote.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
CLI=$WORK/cli
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
PW=$(cat "$CLI/account.pw")
WRONG=$(cat "$CLI/wrong.pw")
CALLS=$CLI/pcalls
: > "$CALLS"
rootdo() {
    touch "$CLI/want-$1"
    for _ in $(seq 600); do [ -e "$CLI/have-$1" ] && return 0; sleep 0.2; done
    fail "root did not do '$1'"
}
usnap() { # NAME
    local id
    {
        custodio list
        for id in $(custodio list | sed -n 's/^id: //p'); do
            printf 'cert %s %s\n' "$id" "$(pkcs11-tool --module "$MODULE" --token-label "$id" --label "$id" --type cert --read-object 2> /dev/null | sha256sum | cut -d' ' -f1)"
        done
    } > "$CLI/$1.user"
    pkcs11-tool --module "$MODULE" --list-token-slots > "$CLI/$1.slots" 2>&1 || true
    rootdo "snap-$1"
}
procs() { ps -u "$(id -u)" -o pid=,args= > "$1"; } # the account's processes
rec_pty() { # LABEL then cli-pty.py STEP... -- custodio ARGS
    local label=$1 res st=0
    shift
    timeout 150 python3 -I /e2e/cli-pty.py "$CLI/$label.out" "$CLI/$label.events" /nonexistent "$@" || st=$?
    case $st in 0) res=ok ;; 124) res=timeout ;; *) res=cli-failed ;; esac
    printf '%s\t%s\t\n' "$label" "$res" >> "$CALLS"
    procs "$CLI/$label.procs"
}

# no agent is registered: the processes of the account hold none, and the same import over D-Bus (no terminal, no interactive flag) is refused
procs "$CLI/pre.procs"
usnap p0
result=$(timeout 60 python3 -I /e2e/owner-call.py import cli-pre "$CLI/rsa.p12" e2e-password) || result="no-reply"
printf 'pre-import\t%s\t\n' "$result" >> "$CALLS"
usnap p1

# a wrong account password: pkttyagent asks, PAM refuses, nothing is imported
rec_pty import-wrong --repeat "Password: =$WRONG\\n" "expect=Password for .*rsa\\.p12: " 'send=e2e-password\n' -- custodio import --id cli-pty "$CLI/rsa.p12"
usnap p2
# the right one
rec_pty import-right "expect=Password for .*rsa\\.p12: " 'send=e2e-password\n' 'expect=AUTHENTICATING FOR' 'expect=Password: ' "send=$PW\\n" -- custodio import --id cli-pty "$CLI/rsa.p12"
usnap p3
# delete: the confirmation, then the account password
rec_pty delete-right 'expect=recovered' 'send=yes\n' 'expect=AUTHENTICATING FOR' 'expect=Password: ' "send=$PW\\n" -- custodio delete -- cli-pty
usnap p4
echo "cli-pty-user: done"
