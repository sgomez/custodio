#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`) with WORK and MODULE set by cli-run.sh (F97), the list and delete cases of the CLI. Her test agent runs in the
# session (approving or denying by $E2E_DIR/mode); the CLI runs on a pseudo-terminal (cli-pty.py, which also records how many requests the agent had logged when
# each prompt was seen). The state directory belongs to the service user, so a snapshot of it goes through root: `rootdo NAME` creates $CLI/want-NAME and waits for
# $CLI/have-NAME; root writes $CLI/NAME.state. A snapshot NAME is $CLI/NAME.user (custodio list and the sha256 of the certificate the module shows per key) and
# $CLI/NAME.state. Calls are recorded in $CLI/calls as "LABEL<TAB>RESULT<TAB>LOGGED" (RESULT ok, cli-failed or timeout; LOGGED the agent's new request lines).
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
CLI=$WORK/cli
export E2E_DIR=$CLI/agent
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
CALLS=$CLI/calls
: > "$CALLS"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

requests() { wc -l < "$E2E_DIR/requests"; }
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
    pkcs11-tool --module "$MODULE" --list-token-slots > "$CLI/$1.slots" 2>&1 || true # judged on its content
    rootdo "snap-$1"
}
import_key() { python3 -I /e2e/import.py "$CLI/$2.p12" "$1" e2e-password > /dev/null || fail "import of $1 failed"; }
rec_pty() { # LABEL then cli-pty.py STEP... -- custodio ARGS: the call is recorded, the transcript and events kept as $CLI/LABEL.out and .events
    local label=$1 before res st=0
    shift
    before=$(requests)
    timeout 150 python3 -I /e2e/cli-pty.py "$CLI/$label.out" "$CLI/$label.events" "$E2E_DIR/requests" "$@" || st=$?
    case $st in 0) res=ok ;; 124) res=timeout ;; *) res=cli-failed ;; esac
    printf '%s\t%s\t%s\n' "$label" "$res" "$(tail -n +$((before + 1)) "$E2E_DIR/requests" | paste -sd';' -)" >> "$CALLS"
}

usnap c0
import_key cli-rsa rsa
import_key cli-ec ec
usnap c1
custodio list > "$CLI/list.out" && echo 0 > "$CLI/list.exit" || echo $? > "$CLI/list.exit"
rootdo carol-list # carol has a session and no keys; alice's list is not empty at this moment
: > "$E2E_DIR/requests"

# the confirmation answered "no": nothing is asked of polkit and nothing is deleted
rec_pty declined-confirmation 'expect=recovered' 'send=no\n' -- custodio delete -- cli-ec
usnap c2
# the confirmation answered, polkit refused
echo deny > "$E2E_DIR/mode"
rec_pty declined-polkit 'expect=recovered' 'send=yes\n' -- custodio delete -- cli-ec
echo approve > "$E2E_DIR/mode"
usnap c3
# the confirmation answered, polkit approves
: > "$E2E_DIR/requests"
rec_pty confirms 'expect=recovered' 'send=yes\n' -- custodio delete -- cli-ec
usnap c4
python3 -I /e2e/delete.py cli-rsa > /dev/null || fail "delete of cli-rsa failed"
usnap c5
echo "cli-user: done"
