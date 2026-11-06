#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`), with WORK set by noplain-run.sh (F135). Her test agent approves and keeps its state in $NP/agent.
#   noplain-user.sh import rsa|ec   imports $NP/<t>.p12 as np-<t> with the CLI and writes ListKeys to $NP/list-<t>.out
#   noplain-user.sh delete          deletes both keys and writes ListKeys to $NP/list-after.out
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
NP=$WORK/noplain
export E2E_DIR=$NP/agent
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }
case ${1:-} in
import)
    t=${2:?}
    timeout 60 python3 -I /e2e/import.py "$NP/$t.p12" "np-$t" e2e-password > "$NP/import-$t.out" || { cat "$NP/import-$t.out" >&2; fail "import of np-$t failed"; }
    timeout 60 python3 -I /e2e/owner-call.py list > "$NP/list-$t.out" || fail "ListKeys gave no reply"
    ;;
delete)
    for t in rsa ec; do timeout 60 python3 -I /e2e/delete.py "np-$t" > /dev/null || fail "delete of np-$t failed"; done
    timeout 60 python3 -I /e2e/owner-call.py list > "$NP/list-after.out" || fail "ListKeys after the deletes gave no reply"
    ;;
*) fail "usage: noplain-user.sh import rsa|ec | delete" ;;
esac
echo "noplain-user: done"
