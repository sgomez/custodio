#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`) with WORK set by fallback-run.sh (F138). Her test agent approves; it keeps its state in $FB/agent, apart from
# $WORK/agent. She imports an RSA 2048 and a P-256 key with the CLI, keeps every output (the import result, the API's list, `custodio list`), then deletes
# both and keeps the list after. Root judges all of it.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
FB=$WORK/fallback
export E2E_DIR=$FB/agent
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
    timeout 60 python3 -I /e2e/import.py "$FB/$t.p12" "fb-$t" e2e-password > "$FB/import-$t.out" || { cat "$FB/import-$t.out" >&2; fail "import of fb-$t failed"; }
done
timeout 60 python3 -I /e2e/owner-call.py list > "$FB/api.out" || fail "ListKeys gave no reply"
timeout 60 custodio list > "$FB/cli.out" || fail "custodio list failed"
if [ -n "${FB_READ:-}" ]; then # F161: root reads the stored credentials now (fallback-run.sh), before the keys are deleted
    : > "$FB/imported"
    for _ in $(seq 600); do [ -e "$FB/read-done" ] && break; sleep 0.2; done
    [ -e "$FB/read-done" ] || fail "root did not finish reading the credentials"
fi
for t in rsa ec; do
    timeout 60 python3 -I /e2e/delete.py "fb-$t" > /dev/null || fail "delete of fb-$t failed"
done
timeout 60 python3 -I /e2e/owner-call.py list > "$FB/api-after.out" || fail "ListKeys after the deletes gave no reply"
[ "$(wc -l < "$E2E_DIR/requests")" -eq 4 ] || fail "expected 4 authentication requests (2 imports, 2 deletes), saw $(wc -l < "$E2E_DIR/requests")"
echo "fallback-user: done"
