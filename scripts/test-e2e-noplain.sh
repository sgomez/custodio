#!/usr/bin/env bash
# F135: container-free checks of the noplain-* cases: the no-key-file judgement rejects each planted unencrypted form and accepts an encrypted-only directory (an encrypted PEM
# never prompts), the kind judgement accepts only the mode's kinds. NOT checked here: a real run (`just e2e-cases debian13 'noplain-*'` in swtpm, none and lacking).
# shellcheck disable=SC2086,SC2013,SC2015,SC2016 # the ids are words; the reader line is cut by sed on purpose (single quotes keep the $)
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap "[ -n \"\${KEEP:-}\" ] || rm -rf \"\$tmp\"" EXIT
fail=0
bad() { echo "test-e2e-noplain: $*" >&2; fail=1; }
np() { python3 -I "$ROOT/e2e/noplain.py" "$@"; }

# kind judgement
printf 'np-rsa\trsa2048\ttpm\nnp-ec\tecdsa-p256\ttpm\n' > "$tmp/k-tpm"
printf 'np-rsa\trsa2048\tencrypted-host\nnp-ec\tecdsa-p256\tencrypted-host\n' > "$tmp/k-host"
printf 'np-rsa\trsa2048\tencrypted-tpm\nnp-ec\tecdsa-p256\tencrypted-tpm\n' > "$tmp/k-etpm"
printf 'np-rsa\trsa2048\ttpm\n' > "$tmp/k-one"
specs="np-rsa:rsa2048 np-ec:ecdsa-p256"
for m in swtpm lacking; do
    [ -z "$(np kind "$tmp/k-tpm" $m $specs)" ] || bad "mode $m: kinds tpm/tpm are refused"
    for f in k-host k-etpm k-one; do [ -n "$(np kind "$tmp/$f" $m $specs)" ] || bad "mode $m: $f is accepted"; done
done
[ -z "$(np kind "$tmp/k-host" none $specs)" ] || bad "mode none: encrypted-host is refused"
for f in k-tpm k-etpm k-one; do [ -n "$(np kind "$tmp/$f" none $specs)" ] || bad "mode none: $f is accepted"; done

# no-key-file judgement: planted forms (in parallel) and a directory that holds only protected files
(
    cd "$tmp"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.pem 2> /dev/null
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.pem 2> /dev/null
    openssl req -new -x509 -key rsa.pem -subj /CN=x -days 1 -out rsa.crt
    for n in pkcs8 pkcs1 der p12 sec1 enc good; do mkdir "d-$n"; done
    cp rsa.pem d-pkcs8/key.pem
    openssl rsa -in rsa.pem -traditional -out d-pkcs1/key.pem 2> /dev/null
    openssl pkey -in rsa.pem -outform DER -out d-der/key.bin
    openssl pkcs12 -export -inkey rsa.pem -in rsa.crt -passout pass: -out d-p12/key.bin 2> /dev/null || openssl pkcs12 -export -legacy -inkey rsa.pem -in rsa.crt -passout pass: -out d-p12/key.bin
    openssl ec -in ec.pem -out d-sec1/key.pem 2> /dev/null
    openssl pkey -in rsa.pem -aes256 -passout pass:secret -out d-enc/key.pem
    cp d-enc/key.pem d-good/key.pem
    head -c 300 /dev/urandom > d-good/opaque.bin
    printf 'x\n' > d-good/record.txt
)
for n in pkcs8 pkcs1 der p12 sec1; do
    (
        out=$(np files "$tmp/d-$n") || true
        [ -n "$out" ] || echo "the planted form '$n' is accepted"
        grep -q "d-$n/key" <<< "$out" || [ -z "$out" ] || echo "the judgement for '$n' does not name the file"
    ) > "$tmp/res-$n" &
done
wait
for n in pkcs8 pkcs1 der p12 sec1; do
    while IFS= read -r l; do bad "$l"; done < "$tmp/res-$n"
done
start=$SECONDS
out=$(timeout 60 python3 -I "$ROOT/e2e/noplain.py" files "$tmp/d-good") || bad "judging the encrypted-only directory failed"
[ -z "$out" ] || bad "an encrypted-only directory is rejected: $out"
[ $((SECONDS - start)) -lt 30 ] || bad "judging the encrypted directory took $((SECONDS - start)) s (a prompt?)"
[ -n "$(np list "$tmp/d-good")" ] || bad "the listing of a directory is empty"

exit "$fail"
