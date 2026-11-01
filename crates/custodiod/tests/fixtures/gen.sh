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

# The same keys under a distinctive password, so a leak scan can look for it (tests/audit).
# Re-encrypt from the PEM files made above; the password is P@ss-sentinel-7f3a91c4.
export OLD_PW=test-password
for n in p256 rsa2048; do
  openssl pkcs12 -in "$n.p12" -password env:OLD_PW -nodes -out "$tmp/$n.pem" 2>/dev/null
  openssl pkcs12 -export -in "$tmp/$n.pem" -name "$n" -passout pass:P@ss-sentinel-7f3a91c4 \
    -out "$n-sentinel.p12" 2>/dev/null
done
chmod 644 ./*.p12

# Certificates (DER) for the ReplaceCertificate tests (tests/replace.rs). The ones over an existing
# key are made from that key in the .p12 above, so no existing fixture changes.
export OLD_PW=test-password
recert() { # name, extra `openssl req` args...
  local name=$1 src=$2
  shift 2
  openssl pkcs12 -in "$src.p12" -password env:OLD_PW -nodes -nocerts -out "$tmp/$src.pem" 2>/dev/null
  openssl req -new -x509 -key "$tmp/$src.pem" -subj "/CN=custodio test $name" "$@" -outform DER \
    -out "cert-$name.der"
}
recert p256-recert p256 -days 36500 -set_serial 4242
recert rsa2048-recert rsa2048 -days 36500 -set_serial 4243
# A second certificate for the key of p256-other.p12, whose bytes differ from the one in the .p12.
recert p256-other-recert p256-other -days 36500 -set_serial 4244
# Expired: valid only in 2020.
recert p256-expired p256 -not_before 20200101000000Z -not_after 20201231000000Z
recert rsa2048-expired rsa2048 -not_before 20200101000000Z -not_after 20201231000000Z
# Certificates of other keys: another RSA 2048 key, and the keys of the other fixtures.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/rsa-other.key" 2>/dev/null
openssl req -new -x509 -key "$tmp/rsa-other.key" -subj "/CN=custodio test rsa other" -days 36500 \
  -outform DER -out cert-rsa2048-other.der
for n in p256-other p384 ed25519 rsa3072; do
  openssl pkcs12 -in "$n.p12" -password env:OLD_PW -nokeys -clcerts -out "$tmp/$n.crt.pem" 2>/dev/null
  openssl x509 -in "$tmp/$n.crt.pem" -outform DER -out "cert-$n.der"
done
chmod 644 ./*.der
