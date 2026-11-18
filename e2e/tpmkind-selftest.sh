#!/usr/bin/env bash
# The judgements of the tpm-kind-* cases (tpmkind.py, tpmkind-lib.sh) on made-up evidence, good and bad. Container-free; the guest runs it first.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "tpmkind-selftest: $*" >&2; fail=1; }
# shellcheck disable=SC2329 # used through expect_ok/expect_bad
tk() { python3 -I "$here/tpmkind.py" "$@"; }
expect_ok() { local n=$1 out; shift; out=$("$@"); [ -z "$out" ] || bad "$n: problems on good evidence: $out"; }
expect_bad() { local n=$1 out; shift; out=$("$@"); [ -n "$out" ] || bad "$n: no problem on bad evidence"; }

NEXT=$'Next:\n  shred -u x.p12    the file still holds your private key\n  restart Firefox   and any other program that loaded Custodio, to see the key'
# imp WORD KIND [NOTE]: the output of `custodio import --id k1` of an rsa2048 key, laid out as the CLI does
imp() { { printf '%-4s  k1  rsa2048  %s\n' "$1" "$2"; [ -z "${3:-}" ] || printf '      %s\n' "$3"; printf '\n%s\n' "$NEXT"; } > "$tmp/imp"; }
imp ok tpm; expect_ok import tk import "$tmp/imp" k1 rsa2048
printf 'Password for x: \r\nok    k1  rsa2048  tpm\r\n\r\nNext:\r\n' > "$tmp/imp-crlf"; expect_ok import-crlf tk import "$tmp/imp-crlf" k1 rsa2048
imp warn encrypted-tpm 'root can use this key while the machine runs.'; expect_bad import-encrypted-tpm tk import "$tmp/imp" k1 rsa2048
imp warn encrypted-host 'root, and anyone with a copy of /var/lib, can use this key.'; expect_bad import-encrypted-host tk import "$tmp/imp" k1 rsa2048
imp ok tpm-x; expect_bad import-prefix tk import "$tmp/imp" k1 rsa2048
imp ok tpm; expect_bad import-wrong-type tk import "$tmp/imp" k1 ecdsa-p256
expect_bad import-wrong-id tk import "$tmp/imp" k2 rsa2048
printf 'ok    k1  rsa2048\n' > "$tmp/imp0"; expect_bad import-no-kind tk import "$tmp/imp0" k1 rsa2048
printf 'ok    k1  rsa2048  tpm\nok    k1  rsa2048  tpm\n' > "$tmp/imp2"; expect_bad import-two-keys tk import "$tmp/imp2" k1 rsa2048
imp ok tpm 'root can use this key while the machine runs.'; expect_bad import-weaker-note tk import "$tmp/imp" k1 rsa2048
imp warn tpm; expect_bad import-warn tk import "$tmp/imp" k1 rsa2048
# lacking: encrypted-tpm, a warning with its note
imp warn encrypted-tpm 'root can use this key while the machine runs.'; expect_ok lacking tk --mode lacking import "$tmp/imp" k1 rsa2048
imp warn encrypted-tpm; expect_bad lacking-no-note tk --mode lacking import "$tmp/imp" k1 rsa2048
imp ok encrypted-tpm 'root can use this key while the machine runs.'; expect_bad lacking-ok tk --mode lacking import "$tmp/imp" k1 rsa2048
imp ok tpm; expect_bad lacking-tpm tk --mode lacking import "$tmp/imp" k1 rsa2048

printf 'k1\trsa2048\ttpm\nk2\tecdsa-p256\ttpm\nother\trsa2048\tencrypted-host\n' > "$tmp/api"
expect_ok api tk api "$tmp/api" k1:rsa2048 k2:ecdsa-p256
expect_bad api-short-type tk api "$tmp/api" k1:rsa k2:ec
expect_bad api-missing tk api "$tmp/api" k1:rsa2048 k3:ecdsa-p256
sed 's/^k2\(.*\)tpm$/k2\1encrypted-tpm/' "$tmp/api" > "$tmp/api2"; expect_bad api-encrypted-tpm tk api "$tmp/api2" k1:rsa2048 k2:ecdsa-p256
sed 's/^k1\(.*\)tpm$/k1\1encrypted-host/' "$tmp/api" > "$tmp/api3"; expect_bad api-encrypted-host tk api "$tmp/api3" k1:rsa2048 k2:ecdsa-p256
{ cat "$tmp/api"; echo 'k1	rsa2048	tpm'; } > "$tmp/api4"; expect_bad api-twice tk api "$tmp/api4" k1:rsa2048 k2:ecdsa-p256

blk() { printf '%s  %s  %s  x  2030-01-01\n' "$@"; }
{ blk k1 rsa2048 tpm; blk k2 ecdsa-p256 tpm; blk other rsa2048 encrypted-host; } > "$tmp/cli"
expect_ok cli tk cli "$tmp/cli" k1:rsa2048 k2:ecdsa-p256
{ blk k1 rsa2048 encrypted-tpm; blk k2 ecdsa-p256 tpm; } > "$tmp/cli2"; expect_bad cli-encrypted-tpm tk cli "$tmp/cli2" k1:rsa2048 k2:ecdsa-p256
{ blk k1 rsa2048 tpm; blk k2 ecdsa-p256 encrypted-host; } > "$tmp/cli3"; expect_bad cli-encrypted-host tk cli "$tmp/cli3" k1:rsa2048 k2:ecdsa-p256
{ blk k1 rsa2048 tpm; } > "$tmp/cli4"; expect_bad cli-missing tk cli "$tmp/cli4" k1:rsa2048 k2:ecdsa-p256
{ blk k1 rsa2048 tpm; blk k2 rsa2048 tpm; } > "$tmp/cli5"; expect_bad cli-wrong-type tk cli "$tmp/cli5" k1:rsa2048 k2:ecdsa-p256
# A hostile subject is one escaped line: it cannot add a row for k2.
printf 'k1  rsa2048  tpm  CN=y\\x0ak2  ecdsa-p256  tpm  z  2030-01-01\n' > "$tmp/cli7"; expect_bad cli-forged-row tk cli "$tmp/cli7" k1:rsa2048 k2:ecdsa-p256
printf 'You have no keys in the custodio service.\nImport one with: custodio import <file.p12>\n' > "$tmp/cli6"; expect_bad cli-none tk cli "$tmp/cli6" k1:rsa2048

row() { printf '{"_SYSTEMD_UNIT":"%s","CUSTODIO_OPERATION":"%s","CUSTODIO_KEY_ID":"%s","CUSTODIO_OUTCOME":"%s"%s}\n' "$1" "$2" "$3" "$4" "$5"; }
KIND=',"CUSTODIO_STORAGE_KIND":"tpm"'
{ row custodio.service import k1 stored "$KIND"; row custodio.service import k2 stored "$KIND"; row custodio.service sign k1 signed ''; } > "$tmp/j"
expect_ok journal tk journal "$tmp/j" k1 k2
{ row custodio.service import k1 stored ''; row custodio.service import k2 stored "$KIND"; } > "$tmp/j1"; expect_bad journal-no-kind tk journal "$tmp/j1" k1 k2
{ row custodio.service import k1 stored ',"CUSTODIO_STORAGE_KIND":"encrypted-tpm"'; row custodio.service import k2 stored "$KIND"; } > "$tmp/j2"; expect_bad journal-other-kind tk journal "$tmp/j2" k1 k2
{ row custodio.service import k1 stored "$KIND"; } > "$tmp/j3"; expect_bad journal-missing tk journal "$tmp/j3" k1 k2
{ cat "$tmp/j"; row custodio.service import k1 stored "$KIND"; } > "$tmp/j4"; expect_bad journal-twice tk journal "$tmp/j4" k1 k2
{ row custodio.service import k1 denied "$KIND"; row custodio.service import k2 stored "$KIND"; } > "$tmp/j5"; expect_bad journal-denied tk journal "$tmp/j5" k1 k2
{ row forged.service import k1 stored "$KIND"; row custodio.service import k2 stored "$KIND"; } > "$tmp/j6"; expect_bad journal-forged-unit tk journal "$tmp/j6" k1 k2

# the fixtures: judged by OpenSSL; a 3072-bit RSA key and a P-384 key are rejected
mkdir "$tmp/fx"; tk_make "$tmp/fx"
expect_ok fixture-rsa fixture_problems "$tmp/fx/rsa.p12" rsa
expect_ok fixture-ec fixture_problems "$tmp/fx/ec.p12" ec
expect_bad fixture-rsa-as-ec fixture_problems "$tmp/fx/rsa.p12" ec
expect_bad fixture-ec-as-rsa fixture_problems "$tmp/fx/ec.p12" rsa
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$tmp/fx/big.key" 2> /dev/null
openssl req -new -x509 -key "$tmp/fx/big.key" -subj /CN=big -days 1 -out "$tmp/fx/big.crt"
openssl pkcs12 -export -inkey "$tmp/fx/big.key" -in "$tmp/fx/big.crt" -passout "pass:$TK_PASSWORD" -out "$tmp/fx/big.p12"
expect_bad fixture-3072 fixture_problems "$tmp/fx/big.p12" rsa
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$tmp/fx/p384.key" 2> /dev/null
openssl req -new -x509 -key "$tmp/fx/p384.key" -subj /CN=p384 -days 1 -out "$tmp/fx/p384.crt"
openssl pkcs12 -export -inkey "$tmp/fx/p384.key" -in "$tmp/fx/p384.crt" -passout "pass:$TK_PASSWORD" -out "$tmp/fx/p384.p12"
expect_bad fixture-p384 fixture_problems "$tmp/fx/p384.p12" ec
exit "$fail"
