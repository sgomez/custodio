#!/usr/bin/env bash
# Runs as the ordinary user "alice" in a logind session for the upgrade case (upgrade.sh), with WORK and MODULE set.
#   upgrade-user.sh list   prints the listing of the tokens and keys seen through the PKCS#11 module (no polkit call)
#   upgrade-user.sh sign   with the test agent: an approved RSA and an approved ECDSA signature, each verified against the public key,
#                          then a denied one; the agent's request counter must rise by exactly one each time
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"

if [ "${1:-}" = list ]; then
    pkcs11-tool --module "$MODULE" --list-token-slots
    for token in ec1 rsa1; do pkcs11-tool --module "$MODULE" --token-label "$token" --list-objects; done
    exit 0
fi
[ "${1:-}" = sign ] || fail "usage: upgrade-user.sh list|sign"

[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
export E2E_DIR=$WORK/agent-upgrade
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill $agent 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }
requests() { wc -l < "$E2E_DIR/requests"; }
expect_requests() { [ "$(requests)" -eq "$1" ] || fail "expected $1 authentication requests, saw $(requests)"; }

sig=$WORK/upgrade-sig.bin
p11sign() { # key, mechanism, extra pkcs11-tool arguments
    local key=$1 mech=$2
    shift 2
    rm -f "$sig"
    pkcs11-tool --module "$MODULE" --token-label "$key" --label "$key" --type privkey --sign --mechanism "$mech" \
        --input-file "$WORK/data.bin" --output-file "$sig" "$@" > "$WORK/upgrade-p11.log" 2>&1
}

p11sign rsa1 RSA-PKCS || { cat "$WORK/upgrade-p11.log" >&2; python3 -I /e2e/tpmclear-sign.py rsa1 rsa >&2 2>&1; pkcs11-tool --module "$MODULE" --token-label rsa1 --list-mechanisms >/dev/null 2>&1; pkcs11-tool --module "$MODULE" --token-label rsa1 --list-objects >&2 2>&1; fail "approved RSA signature after the upgrade failed"; }
recovered=$(openssl pkeyutl -verifyrecover -pubin -inkey "$WORK/rsa.pub" -in "$sig" 2> /dev/null | sha256sum)
[ "$recovered" = "$(sha256sum < "$WORK/data.bin")" ] \
    || fail "the RSA signature after the upgrade does not verify against the public key"
expect_requests 1
p11sign ec1 ECDSA-SHA256 --signature-format openssl || { cat "$WORK/upgrade-p11.log" >&2; fail "approved ECDSA signature after the upgrade failed"; }
openssl dgst -sha256 -verify "$WORK/ec.pub" -signature "$sig" "$WORK/data.bin" 2>&1 | grep -q "Verified OK" \
    || fail "the ECDSA signature after the upgrade does not verify against the public key"
expect_requests 2
# Nothing is cached from before the upgrade (or from the signature just made): a denied signature fails and is still asked.
echo deny > "$E2E_DIR/mode"
if p11sign rsa1 RSA-PKCS; then fail "a denied signature after the upgrade succeeded"; fi
[ ! -s "$sig" ] || fail "a denied signature after the upgrade produced output"
expect_requests 3
echo "upgrade-user: signed and verified RSA and ECDSA; the agent was asked 3 times for 3 signatures"
