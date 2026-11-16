#!/usr/bin/env bash
# Runs as the test user in one logind session (`su -l`) with WORK and MODULE set by e2e/vm/fingerprint.sh (F200), while the harness's pam_permit file still stands for polkit:
# her test agent approves the import of the key P12 under the id ID; the certificate the module serves gives the public key the judge verifies the signature with.
# Usage: fingerprint-user.sh OUTDIR ID P12
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
out=$1 id=$2 p12=$3
export E2E_DIR=$out/agent
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }
timeout 60 python3 -I /e2e/import.py "$p12" "$id" e2e-password > "$out/import.out" || { cat "$out/import.out" >&2; fail "the import of $id failed"; }
timeout 60 pkcs11-tool --module "$MODULE" --token-label "$id" --read-object --type cert --label "$id" --output-file "$out/cert.der" > "$out/cert.log" 2>&1 \
    || { cat "$out/cert.log" >&2; fail "the module did not serve the certificate of $id"; }
openssl x509 -inform der -in "$out/cert.der" -pubkey -noout > "$out/pub.pem" || fail "no public key in the certificate of $id"
