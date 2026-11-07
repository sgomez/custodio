#!/usr/bin/env bash
# Fails when any file under STATE_DIR holds the private key of P12 in a form we can derive: the raw scalar or primes (and RSA
# exponents), PKCS#1, PKCS#8, SEC1 and the .p12 itself, searched as raw bytes, hex (both cases, with and without ':') and
# base64 (three alignments, PEM line breaks ignored). The password is read from stdin, never from the command line.
# usage: scripts/check-no-plaintext.sh STATE_DIR P12 < password
# Exit 0: no match. 1: a match; the files are named on stdout (never the key or the password). 2: bad usage or unusable
# input. 3: a derivation failed (wrong password, not a .p12, openssl error): never a clean result.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
die() { echo "check-no-plaintext: $1" >&2; exit "${2:-2}"; }
[ $# -eq 2 ] || die "usage: check-no-plaintext.sh STATE_DIR P12 < password"
state=$1
p12=$2
for tool in openssl python3; do
    command -v "$tool" >/dev/null || die "required tool '$tool' is not installed"
done
[ -d "$state" ] && [ -r "$state" ] && [ -x "$state" ] || die "$state: not a readable directory"
[ -f "$p12" ] && [ -r "$p12" ] || die "$p12: not a readable file"
IFS= read -r CUSTODIO_PW || [ -n "${CUSTODIO_PW:-}" ] || CUSTODIO_PW=
export CUSTODIO_PW

umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
case "$(cd "$state" && pwd -P)/" in "$(cd "$work" && pwd -P)/"*) die "$state is the scratch directory" ;; esac
secrets="$work/secrets"
mkdir "$secrets"
quiet() { "$@" 2>"$work/err"; }
fail() { die "$1 failed (wrong password, not a .p12, or unsupported key)" 3; }

# Encoded form of the key as PKCS#8 PEM; the legacy provider is tried when the default one cannot read the file.
if ! quiet openssl pkcs12 -in "$p12" -passin env:CUSTODIO_PW -nocerts -noenc -out "$work/key.pem"; then
    quiet openssl pkcs12 -legacy -in "$p12" -passin env:CUSTODIO_PW -nocerts -noenc -out "$work/key.pem" || fail "reading the .p12"
fi
grep -q 'PRIVATE KEY' "$work/key.pem" || fail "finding a private key in the .p12"
quiet openssl pkey -in "$work/key.pem" -outform DER -out "$secrets/pkcs8.der" || fail "PKCS#8 derivation"
cp -- "$p12" "$secrets/file.p12"

# asn1 FILE: the ASN.1 dump of a DER file; fails closed when it cannot be parsed.
asn1() { openssl asn1parse -inform DER -in "$1" 2>/dev/null; }
text=$(quiet openssl pkey -in "$work/key.pem" -noout -text) || fail "key text"
if grep -q '^modulus:' <<<"$text"; then
    quiet openssl rsa -in "$work/key.pem" -traditional -outform DER -out "$secrets/pkcs1.der" || fail "PKCS#1 derivation"
    # PKCS#1: version, n, e, d, p, q, dp, dq, qinv. d, p, q, dp, dq and qinv are secret; leading zero bytes are dropped.
    n=0
    while IFS= read -r line; do
        n=$((n + 1))
        [ "$n" -ge 4 ] || continue
        hex=${line##*:}
        printf '%s' "$hex" | python3 -I -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read()).lstrip(b"\0"))' >"$secrets/int$n.raw"
    done < <(asn1 "$secrets/pkcs1.der" | grep -E 'prim: INTEGER' | sed -n '1,9p')
    [ "$n" -eq 9 ] || fail "RSA integers (got $n of 9)"
elif grep -q '^priv:' <<<"$text"; then
    quiet openssl ec -in "$work/key.pem" -outform DER -out "$secrets/sec1.der" || fail "SEC1 derivation"
    # SEC1: version, the private scalar as an OCTET STRING of the curve's size, parameters, public key.
    hex=$(asn1 "$secrets/sec1.der" | grep -E -m1 'OCTET STRING +\[HEX DUMP\]:' | sed 's/.*HEX DUMP\]://') || true
    [ -n "$hex" ] || fail "EC scalar"
    printf '%s' "$hex" | python3 -I -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read()))' >"$secrets/scalar.raw"
else
    fail "recognising the key type"
fi

set +e
python3 -I -B "$ROOT/scripts/check_no_plaintext.py" "$state" "$secrets"
rc=$?
set -e
case $rc in 0 | 1) exit "$rc" ;; *) die "the search failed" 3 ;; esac
