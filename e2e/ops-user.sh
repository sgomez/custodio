#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`), with WORK set by ops-run.sh (F92). Her test agent registers for this session and answers according to
# $E2E_DIR/mode; every call is made here and recorded in $OPS/calls as "LABEL<TAB>RESULT<TAB>LOGGED" (ops-lib.sh). The state directory belongs to the service
# user, and polkit is stopped and started by root, so snapshots and the stop/start go through files: `rootdo NAME` creates $OPS/want-NAME and waits for
# $OPS/have-NAME, which ops-run.sh creates after it did the work (a snapshot of the state directory into $OPS/NAME.state, or the polkit stop/start).
# A snapshot NAME is $OPS/NAME.user (custodio list and the sha256 of each certificate the module shows) and $OPS/NAME.state.
# The sequence, one block per case (comments say which): see the labels in ops-run.sh.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
OPS=$WORK/ops
export E2E_DIR=$OPS/agent
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
P12=$OPS/k1.p12
CALLS=$OPS/calls
: > "$CALLS"
agent=''
start_agent() {
    : > "$E2E_DIR/agent.log"
    python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
    agent=$!
    for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
    grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }
}
trap '[ -z "$agent" ] || kill "$agent" 2>/dev/null || true' EXIT
start_agent
mode() { echo "$1" > "$E2E_DIR/mode"; }
requests() { wc -l < "$E2E_DIR/requests"; }
rootdo() { # NAME: ask ops-run.sh (root) for something, and wait until it is done
    touch "$OPS/want-$1"
    for _ in $(seq 600); do [ -e "$OPS/have-$1" ] && return 0; sleep 0.2; done
    fail "root did not do '$1'"
}
usnap() { # NAME
    local id
    {
        custodio list
        for id in $(custodio list | sed -n 's/^id: //p'); do
            printf 'cert %s %s\n' "$id" "$(pkcs11-tool --module "$MODULE" --token-label "$id" --label "$id" --type cert --read-object 2> /dev/null | sha256sum | cut -d' ' -f1)"
        done
    } > "$OPS/$1.user"
    rootdo "snap-$1"
    cat "$OPS/$1.user" "$OPS/$1.state" > "$OPS/$1.snap"
}
rec() { # LABEL then the command of a D-Bus call (owner-call.py ARGS...): records its result and the lines the agent logged during it
    local label=$1 before res st=0
    shift
    before=$(requests)
    res=$(timeout 60 python3 -I /e2e/owner-call.py "$@") || st=$?
    [ "$st" -ne 124 ] || fail "$label: the call did not return within 60 s"
    [ "$st" -eq 0 ] || fail "$label: owner-call.py gave no D-Bus reply (status $st)"
    printf '%s\t%s\t%s\n' "$label" "$res" "$(tail -n +$((before + 1)) "$E2E_DIR/requests" | paste -sd';' -)" >> "$CALLS"
}
rec_cli() { # LABEL then the command (import.py / delete.py ARGS...): the CLI on a terminal; "ok", "cli-denied" or "cli-failed"
    local label=$1 before res st=0 out
    shift
    before=$(requests)
    out=$(timeout 60 python3 -I "$@") || st=$?
    [ "$st" -ne 124 ] || fail "$label: the CLI did not return within 60 s"
    if [ "$st" -eq 0 ]; then res=ok; elif grep -qi 'not authorized' <<< "$out"; then res=cli-denied; else res=cli-failed; fi
    printf '%s\t%s\t%s\n' "$label" "$res" "$(tail -n +$((before + 1)) "$E2E_DIR/requests" | paste -sd';' -)" >> "$CALLS"
}
call() { python3 -I /e2e/owner-call.py "$@"; }

# Setup (not a case): alice's base key, imported with the CLI; the agent logs it.
python3 -I /e2e/import.py "$P12" ops-base e2e-password > /dev/null || fail "import of ops-base failed"
[ "$(requests)" -eq 1 ] || fail "the import of ops-base made $(requests) requests"
: > "$E2E_DIR/requests"

# asks-once: the agent approves; one call each.
rec import-once import ops-imp "$P12" e2e-password
usnap a1
rec delete-once delete ops-imp
usnap a2
usnap b0
rec replace-once replace ops-base "$OPS/cert2.der"
usnap b1

# denied: the agent denies, through the service and, for import and delete, the CLI.
mode deny
usnap d0
rec den-import import ops-den "$P12" e2e-password
rec den-delete delete ops-base
rec den-replace replace ops-base "$OPS/cert1.der"
rec_cli den-cli-import /e2e/import.py "$P12" ops-den-cli e2e-password
rec_cli den-cli-delete /e2e/delete.py ops-base
usnap d1

# asks-again: the same call twice, denied and then approved; nothing is cached.
mode deny
rec again-import-1 import ops-again "$P12" e2e-password
rec again-replace-1 replace ops-base "$OPS/cert1.der"
mode approve
rec again-import-2 import ops-again "$P12" e2e-password
rec again-replace-2 replace ops-base "$OPS/cert1.der"
mode deny
rec again-delete-1 delete ops-again
mode approve
rec again-delete-2 delete ops-again

# wrong password: denied first (the .p12 is not opened), then approved.
mode deny
usnap w0
rec wp-denied import ops-wp "$P12" not-the-password
usnap w1
mode approve
rec wp-approved import ops-wp "$P12" not-the-password
usnap w2
rec wp-correct import ops-wp "$P12" e2e-password
usnap w3

# unavailable: polkit stopped and masked by root; the agent would deny, so a request that got through would show in its log and refuse.
mode deny
usnap u0
rootdo polkit-stop
rec un-import import ops-un "$P12" e2e-password
rec un-delete delete ops-base
rec un-replace replace ops-base "$OPS/cert2.der"
rec un-wp import ops-un2 "$P12" not-the-password
usnap u1
rootdo polkit-start
# polkit lost every agent registration when it stopped: register again before the deletes below
kill "$agent" 2> /dev/null || true
wait "$agent" 2> /dev/null || true
start_agent
mode approve

# cleanup: every key of this step goes
[ "$(call delete ops-base)" = ok ] || fail "cleanup: delete of ops-base failed"
[ "$(call delete ops-wp)" = ok ] || fail "cleanup: delete of ops-wp failed"
echo "ops-user: done"
