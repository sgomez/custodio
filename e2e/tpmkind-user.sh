#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`) with WORK set by tpmkind-run.sh (F133). Her test agent approves; the agent keeps its state in
# $TK/agent, not in $WORK/agent, so that the request count the journal step read is unchanged. She imports an RSA 2048 and a P-256 key with the CLI, keeps
# every output (the import result, the API's list, `custodio list`), then deletes both and keeps the list after. Root judges all of it.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
TK=$WORK/tpmkind
export E2E_DIR=$TK/agent
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

for t in rsa ec; do
    timeout 60 python3 -I /e2e/import.py "$TK/$t.p12" "tk-$t" e2e-password > "$TK/import-$t.out" || { cat "$TK/import-$t.out" >&2; fail "import of tk-$t failed"; }
done
timeout 60 python3 -I /e2e/owner-call.py list > "$TK/api.out" || fail "ListKeys gave no reply"
timeout 60 custodio list > "$TK/cli.out" || fail "custodio list failed"
for t in rsa ec; do
    timeout 60 python3 -I /e2e/delete.py "tk-$t" > /dev/null || fail "delete of tk-$t failed"
done
timeout 60 python3 -I /e2e/owner-call.py list > "$TK/api-after.out" || fail "ListKeys after the deletes gave no reply"
[ "$(wc -l < "$E2E_DIR/requests")" -eq 4 ] || fail "expected 4 authentication requests (2 imports, 2 deletes), saw $(wc -l < "$E2E_DIR/requests")"
echo "tpmkind-user: done"
