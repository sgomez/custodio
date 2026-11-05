#!/usr/bin/env bash
# Runs as the ordinary user "alice" in one logind session, with WORK set by guest.sh. Import asks polkit (F73), and the test agent
# registers only for the session it runs in, so the agent and the imports must share this one session. The agent keeps its state
# in $WORK/agent-import, not in $WORK/agent: the request count of user.sh (0 at the first step, then 1, 2, 3...) and the total
# that journal-check.sh reads are those of $WORK/agent, and these two imports must not be counted there.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
export E2E_DIR=$WORK/agent-import
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo deny > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"

python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill $agent 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

# Approve only after the agent registered, then import on a pseudo-terminal (the password is only read from /dev/tty).
echo approve > "$E2E_DIR/mode"
for k in rsa1 ec1; do
    python3 -I /e2e/import.py "$WORK/$k.p12" "$k" e2e-password > "$WORK/import-$k.out" || { cat "$WORK/import-$k.out" >&2; fail "import of $k failed"; }
done
[ "$(wc -l < "$E2E_DIR/requests")" -eq 2 ] || fail "expected 2 authentication requests for the 2 imports, saw $(wc -l < "$E2E_DIR/requests")"
