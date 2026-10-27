#!/usr/bin/env bash
# Regenerates the test-only .p12 fixtures. Every file uses the password "test-password".
# The keys are throwaway and must never be used for anything else.
set -euo pipefail
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

make() { # name, key-generation args...
  local name=$1
  shift
  openssl genpkey "$@" -out "$tmp/$name.key" 2>/dev/null
  openssl req -new -x509 -key "$tmp/$name.key" -subj "/CN=custodio test $name" -days 36500 \
    -out "$tmp/$name.crt"
  openssl pkcs12 -export -inkey "$tmp/$name.key" -in "$tmp/$name.crt" -name "$name" \
    -passout pass:test-password -out "$name.p12"
}

make rsa2048 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
make rsa3072 -algorithm RSA -pkeyopt rsa_keygen_bits:3072
make p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
make p384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384
make ed25519 -algorithm ED25519

# Legacy PBE (3DES / RC2, SHA-1 MAC), as older tools and some issuers still produce.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/legacy.key" 2>/dev/null
openssl req -new -x509 -key "$tmp/legacy.key" -subj "/CN=custodio test legacy" -days 36500 \
  -out "$tmp/legacy.crt"
openssl pkcs12 -export -legacy -inkey "$tmp/legacy.key" -in "$tmp/legacy.crt" \
  -passout pass:test-password -out rsa2048-legacy.p12
# A second, unrelated P-256 key and certificate (for key/certificate mismatch tests).
make p256-other -algorithm EC -pkeyopt ec_paramgen_curve:P-256

# A key bag without a localKeyId, next to its certificate bag.
openssl pkcs12 -export -inkey "$tmp/p256.key" -certfile "$tmp/p256.crt" -nocerts \
  -passout pass:test-password -out p256-nokid.p12 2>/dev/null
chmod 644 ./*.p12
