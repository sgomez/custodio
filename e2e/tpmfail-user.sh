#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`) with WORK set by tpmfail-run.sh (F139). Usage: tpmfail-user.sh OUTDIR import ID P12 | delete ID...
# Her test agent approves; it keeps its state in $WORK/tpmfail/agent. import: `custodio import` (output in OUTDIR/import.out, status in OUTDIR/import.rc, which may be non-zero),
# then the API's list (OUTDIR/list.out). delete: the deletes, at once, then the list.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
out=$1 action=$2
export E2E_DIR=$WORK/tpmfail/agent
mkdir -p "$E2E_DIR" "$out"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }
case $action in
import)
    rc=0
    timeout 60 python3 -I /e2e/import.py "$4" "$3" e2e-password > "$out/import.out" || rc=$?
    echo "$rc" > "$out/import.rc"
    [ "$rc" -ne 124 ] || fail "the import hung"
    ;;
delete) # the ids from $3 on, at once (each is a polkit round trip of a few seconds)
    shift 2
    pids=()
    for id in "$@"; do
        timeout 60 python3 -I /e2e/delete.py "$id" > "$out/delete-$id.out" 2>&1 & pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" || fail "a delete failed (see $out/delete-*.out)"; done
    ;;
*) fail "unknown action $action" ;;
esac
timeout 60 python3 -I /e2e/owner-call.py list > "$out/list.out" || fail "ListKeys gave no reply"
echo "tpmfail-user: done"
