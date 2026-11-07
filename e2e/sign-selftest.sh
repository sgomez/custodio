#!/usr/bin/env bash
# Self-test of the sign-* judgements (F134), run by sign-run.sh before the cases and by scripts/test-e2e-sign.sh: sign.py passes on signatures openssl made, fails on each kind
# of bad evidence (sign-selftest.py), and the fixture check refuses a key of another size or curve.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
python3 -I "$here/sign-selftest.py" "$tmp/run" 2>&1 || { echo "sign-selftest: the judgements are wrong (see above)" >&2; exit 1; }
# the fixtures: a 2048-bit RSA key and a P-256 key pass, a 3072-bit one and a P-384 one are refused
mkdir "$tmp/fx"
tk_make "$tmp/fx" sign
[ -z "$(fixture_problems "$tmp/fx/rsa.p12" rsa)$(fixture_problems "$tmp/fx/ec.p12" ec)" ] || { echo "sign-selftest: the fixtures are refused" >&2; exit 1; }
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$tmp/fx/big.key" 2> /dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$tmp/fx/p384.key" 2> /dev/null
for k in big p384; do
    openssl req -new -x509 -key "$tmp/fx/$k.key" -subj /CN=x -days 1 -out "$tmp/fx/$k.crt"
    openssl pkcs12 -export -inkey "$tmp/fx/$k.key" -in "$tmp/fx/$k.crt" -passout "pass:$TK_PASSWORD" -out "$tmp/fx/$k.p12"
done
[ -n "$(fixture_problems "$tmp/fx/big.p12" rsa)" ] || { echo "sign-selftest: a 3072-bit RSA key is accepted as the fixture" >&2; exit 1; }
[ -n "$(fixture_problems "$tmp/fx/p384.p12" ec)" ] || { echo "sign-selftest: a P-384 key is accepted as the fixture" >&2; exit 1; }
echo "sign-selftest: fixtures checked"
