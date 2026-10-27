#!/usr/bin/env bash
# Runs as the ordinary user "alice" in a logind session, with WORK and MODULE set by guest.sh.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
export E2E_DIR=$WORK/agent
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo deny > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"

python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill $agent 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

requests() { wc -l < "$E2E_DIR/requests"; }
# expect_requests N: the agent was asked exactly N times so far.
expect_requests() { [ "$(requests)" -eq "$1" ] || fail "expected $1 authentication requests, saw $(requests)"; }

# --- Acceptance 1: the user cannot read the key files -------------------------------------------
[ -z "$(find -L /var/lib/custodio -mindepth 1 -maxdepth 3 2>/dev/null | head -n 1)" ] || fail "alice can list the state directory"
if cat /var/lib/custodio/* >/dev/null 2>&1; then fail "alice read a key file"; fi
if ls /var/lib/custodio >/dev/null 2>&1; then fail "alice listed /var/lib/custodio"; fi
if grep -rl "PRIVATE KEY\|PKCS" /var/lib/custodio >/dev/null 2>&1; then fail "alice grepped a key file"; fi
expect_requests 0
echo "ok: the user cannot read the key files"

sig="$WORK/sig.bin"
p11sign() { # key id, mechanism; output in $sig
    rm -f "$sig"
    pkcs11-tool --module "$MODULE" --token-label "$1" --label "$1" --type privkey --sign --mechanism "$2" \
        --input-file "$WORK/data.bin" --output-file "$sig" >"$WORK/p11.log" 2>&1
}

# --- pkcs11-tool --------------------------------------------------------------------------------
pkcs11-tool --module "$MODULE" --list-token-slots 2>&1 | grep -q "rsa1" || fail "pkcs11-tool does not see the token rsa1"

echo approve > "$E2E_DIR/mode"
p11sign rsa1 RSA-PKCS || { cat "$WORK/p11.log" >&2; fail "approved RSA signature failed"; }
[ "$(stat -c %s "$sig")" -eq 256 ] || fail "RSA signature is not 256 bytes"
expect_requests 1
echo "ok: pkcs11-tool approve (RSA)"

echo deny > "$E2E_DIR/mode"
if p11sign rsa1 RSA-PKCS; then fail "a denied signature succeeded"; fi
[ ! -s "$sig" ] || fail "a denied signature produced output"
expect_requests 2
echo "ok: pkcs11-tool deny"

# Second signature asks again: approve once, then sign twice more; each one reaches the agent.
echo approve > "$E2E_DIR/mode"
p11sign rsa1 RSA-PKCS || fail "approved signature (first of two) failed"
expect_requests 3
p11sign rsa1 RSA-PKCS || fail "approved signature (second of two) failed"
expect_requests 4
echo deny > "$E2E_DIR/mode"
if p11sign rsa1 RSA-PKCS; then fail "the second signature reused the previous authorization"; fi
expect_requests 5
echo "ok: every signature asks again"

echo approve > "$E2E_DIR/mode"
p11sign ec1 ECDSA || { cat "$WORK/p11.log" >&2; fail "approved ECDSA signature failed"; }
expect_requests 6
echo "ok: pkcs11-tool approve (ECDSA)"

# --- NSS: modutil and certutil ------------------------------------------------------------------
db=$WORK/nssdb
mkdir -p "$db"
certutil -N -d "sql:$db" --empty-password
modutil -dbdir "sql:$db" -add custodio -libfile "$MODULE" -force >/dev/null
modutil -dbdir "sql:$db" -list 2>&1 | grep -q custodio || fail "NSS did not load the module"
certutil -L -d "sql:$db" -h all 2>&1 | grep -q "rsa1" || fail "NSS does not list the custodied certificate"

nsssign() { # issues a certificate from the CSR with the custodied key rsa1
    rm -f "$WORK/issued.der"
    certutil -C -d "sql:$db" -c "rsa1:rsa1" -i "$WORK/csr.der" -o "$WORK/issued.der" -v 1 -Z SHA256 \
        >"$WORK/nss.log" 2>&1 < /dev/null
}
before=$(requests)
echo approve > "$E2E_DIR/mode"
nsssign || { cat "$WORK/nss.log" >&2; fail "NSS signing with approval failed"; }
[ "$(requests)" -eq $((before + 1)) ] || fail "NSS signing: expected exactly one request, saw $(( $(requests) - before ))"
openssl x509 -inform DER -in "$WORK/issued.der" -noout -subject | grep -q "e2e subject" || fail "NSS did not produce the certificate"
echo "ok: NSS approve"

echo deny > "$E2E_DIR/mode"
if nsssign; then fail "NSS signed after a denial"; fi
[ ! -s "$WORK/issued.der" ] || fail "NSS produced a certificate after a denial"
[ "$(requests)" -eq $((before + 2)) ] || fail "NSS deny: the agent was not asked"
echo "ok: NSS deny"

echo approve > "$E2E_DIR/mode"
nsssign || fail "NSS signing (again) failed"
[ "$(requests)" -eq $((before + 3)) ] || fail "NSS second signature did not ask again"
echo "ok: NSS second signature asks again"

echo "user.sh: passed"
