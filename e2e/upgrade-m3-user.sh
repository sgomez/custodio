#!/usr/bin/env bash
# Runs as an ordinary user (alice or bob) in a logind session of his or her own (`su -l`), with WORK set by upgrade-m3.sh (F142). The test agent registers for the session
# it runs in, so the imports, which ask polkit, are made here with this session's agent; its log is $ACC/agent-USER/requests. Everything observed goes to files in $ACC.
# The user's keys are alice: rsa1 and ec1; bob: rsa1 and bobonly, with their p12 files in $ACC/USER-ID.p12 (password e2e-password).
#   upgrade-m3-user.sh seed           imports the user's keys (with the M3 build's CLI)
#   upgrade-m3-user.sh collect DIR    the API list and the CLI list into DIR/USER.api and DIR/USER.cli, the exit status of each in DIR/USER.api.rc and DIR/USER.cli.rc
#   upgrade-m3-user.sh import         imports the user's keys again (with this tree's CLI), the exit status of each into $ACC/reimported/import/USER-ID.rc and the number of polkit requests the agent saw into USER.requests (the directory is made by upgrade-m3.sh)
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
user=$(id -un)
ACC=$WORK/upgrade-m3
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
case $user in
alice) ids='rsa1 ec1' ;;
bob) ids='rsa1 bobonly' ;;
*) fail "unexpected user $user" ;;
esac
mode=${1:-}

start_agent() {
    export E2E_DIR=$ACC/agent-$user-$1
    mkdir -p "$E2E_DIR"
    : > "$E2E_DIR/requests"
    echo approve > "$E2E_DIR/mode"
    python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
    agent=$!
    trap 'kill $agent 2>/dev/null || true' EXIT
    for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
    grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "$user: the agent did not register"; }
}

case $mode in
seed)
    start_agent seed
    for id in $ids; do
        python3 -I /e2e/import.py "$ACC/$user-$id.p12" "$id" e2e-password > "$ACC/$user-seed-$id.out" 2>&1 || { cat "$ACC/$user-seed-$id.out" >&2; fail "$user: the import of $id with the M3 build failed"; }
    done
    [ "$(wc -l < "$E2E_DIR/requests")" -eq 2 ] || fail "$user: expected 2 requests in the agent's log, saw $(wc -l < "$E2E_DIR/requests")"
    ;;
collect)
    dir=${2:?}
    st=0
    timeout 60 python3 -I /e2e/owner-call.py list > "$dir/$user.api" 2> "$dir/$user.api.err" || st=$?
    echo "$st" > "$dir/$user.api.rc"
    st=0
    timeout 60 custodio list > "$dir/$user.cli" 2> "$dir/$user.cli.err" || st=$?
    echo "$st" > "$dir/$user.cli.rc"
    ;;
import)
    start_agent import
    for id in $ids; do
        st=0
        python3 -I /e2e/import.py "$ACC/$user-$id.p12" "$id" e2e-password > "$ACC/reimported/import/$user-$id.out" 2>&1 || st=$?
        echo "$st" > "$ACC/reimported/import/$user-$id.rc"
    done
    wc -l < "$E2E_DIR/requests" > "$ACC/reimported/import/$user.requests"
    ;;
*) fail "usage: upgrade-m3-user.sh seed|collect DIR|import" ;;
esac
echo "upgrade-m3-user $user: $mode done"
