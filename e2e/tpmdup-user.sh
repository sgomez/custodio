#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`), with WORK set by tpmdup-run.sh (F136). Her test agent approves and keeps its state in $TD/agent.
#   tpmdup-user.sh import     imports $TD/rsa.p12 and $TD/ec.p12 as td-rsa and td-ec with the API and writes ListKeys to $TD/list.out
#   tpmdup-user.sh delete     deletes both keys and writes ListKeys to $TD/list-after.out
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
TD=$WORK/tpmdup
export E2E_DIR=$TD/agent
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
    for t in rsa ec; do
        timeout 60 python3 -I /e2e/import.py "$TD/$t.p12" "td-$t" e2e-password > "$TD/import-$t.out" 2>&1 || { cat "$TD/import-$t.out" >&2; fail "import of td-$t failed"; }
    done
    timeout 60 python3 -I /e2e/owner-call.py list > "$TD/list.out" || fail "ListKeys gave no reply"
    ;;
delete)
    for t in rsa ec; do timeout 60 python3 -I /e2e/delete.py "td-$t" > /dev/null || fail "delete of td-$t failed"; done
    timeout 60 python3 -I /e2e/owner-call.py list > "$TD/list-after.out" || fail "ListKeys after the deletes gave no reply"
    ;;
*) fail "usage: tpmdup-user.sh import | delete" ;;
esac
echo "tpmdup-user: done"
