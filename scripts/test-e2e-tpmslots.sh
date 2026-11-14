#!/usr/bin/env bash
# F143: container-free checks of the tpm-slots-* cases: the judgements of e2e/tpmslots.py on good and bad evidence (fewer calls than slots + 3, a failed call, a signature that does not verify, a gap in the numbering,
# a missing mechanism, a wrong kind, a key missing after the imports, a transient handle left after the run, a slot count of zero or unreadable). NOT checked here: a real run
# (`just e2e-cases debian13 'tpm-slots-*'` in swtpm, lacking and none).
# shellcheck disable=SC2086 # the ids are words
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-tpmslots: $*" >&2; fail=1; }
ts() { python3 -I "$ROOT/e2e/tpmslots.py" "$@"; }

expect_ok() { local out; out=$("$@") || { bad "failed to run: $*"; return; }; [ -z "$out" ] || bad "good evidence rejected ($*): $out"; }
expect_bad() { local out; out=$("$@" 2>&1) || true; [ -n "$out" ] || bad "bad evidence accepted ($*)"; }

# the slot count
printf 'TPM2_PT_HR_TRANSIENT_MIN:\n  raw: 0x3\nTPM2_PT_HR_PERSISTENT_MIN:\n  raw: 0x7\n' > "$tmp/slots3"
printf 'TPM2_PT_HR_TRANSIENT_MIN:\n  raw: 0x0\n' > "$tmp/slots0"
printf 'TPM2_PT_HR_TRANSIENT_MIN:\n  raw: 0x1000\n' > "$tmp/slots-huge"
printf 'ERROR: no tpm\n' > "$tmp/slots-err"
printf 'TPM2_PT_HR_PERSISTENT_MIN:\n  raw: 0x7\n' > "$tmp/slots-other"
[ "$(ts slotcount "$tmp/slots3")" = 3 ] || bad "slotcount does not read 3"
for f in slots0 slots-huge slots-err slots-other missing; do ts slotcount "$tmp/$f" > /dev/null 2>&1 && bad "slotcount accepts $f"; done

# signatures, made by openssl
S=$tmp/s
mkdir -p "$S/in" "$S/out"
head -c 300 /dev/urandom > "$S/in/msg.bin"
openssl dgst -sha256 -binary "$S/in/msg.bin" > "$S/in/dgst.bin"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/rsa.key" 2> /dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/ec.key" 2> /dev/null
openssl pkey -in "$tmp/rsa.key" -pubout -out "$S/rsa.pub.pem"
openssl pkey -in "$tmp/ec.key" -pubout -out "$S/ec.pub.pem"
openssl dgst -sha256 -sign "$tmp/rsa.key" -out "$S/out/pkcs.sig" "$S/in/msg.bin"
openssl pkeyutl -sign -inkey "$tmp/rsa.key" -in "$S/in/dgst.bin" -out "$S/out/pss.sig" -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_mgf1_md:sha256 -pkeyopt rsa_pss_saltlen:32
openssl dgst -sha256 -sign "$tmp/ec.key" -out "$S/out/ecdsa.sig" "$S/in/msg.bin"
rec() { # FILE KIND N: n records, the mechanisms alternating for rsa
    local f=$1 kind=$2 n=$3 i m inp
    : > "$f"
    for i in $(seq "$n"); do
        if [ "$kind" = ec ]; then m=ecdsa; inp=in/msg.bin
        elif [ $((i % 2)) = 1 ]; then m=pkcs; inp=in/msg.bin
        else m=pss; inp=in/dgst.bin; fi
        printf '%s\t%s\t0\tout/%s.sig\t%s\n' "$i" "$m" "$m" "$inp" >> "$f"
    done
}
rec "$S/rsa6" rsa 6
rec "$S/rsa9" rsa 9
rec "$S/ec6" ec 6
expect_ok ts calls "$S" rsa6 "$S/rsa.pub.pem" rsa2048 6
expect_ok ts calls "$S" rsa9 "$S/rsa.pub.pem" rsa2048 6
expect_ok ts calls "$S" ec6 "$S/ec.pub.pem" ecdsa-p256 6
expect_bad ts calls "$S" rsa6 "$S/rsa.pub.pem" rsa2048 7  # fewer calls than slots + 3
expect_bad ts calls "$S" ec6 "$S/ec.pub.pem" ecdsa-p256 7
expect_bad ts calls "$S" rsa6 "$S/rsa.pub.pem" rsa2048 0  # nothing required proves nothing
expect_bad ts calls "$S" rsa6 "$S/ec.pub.pem" rsa2048 6   # signatures of another key
expect_bad ts calls "$S" ec6 "$S/rsa.pub.pem" ecdsa-p256 6
expect_bad ts calls "$S" rsa6 "$S/rsa.pub.pem" ecdsa-p256 6 # a mechanism that does not fit the type
expect_bad ts calls "$S" missing "$S/rsa.pub.pem" rsa2048 6
expect_bad ts calls "$S" rsa6 "$S/rsa.pub.pem" ed25519 6
sed '3s/\t0\tout/\t2\tout/' "$S/rsa6" > "$S/failed"; expect_bad ts calls "$S" failed "$S/rsa.pub.pem" rsa2048 6 # a failed call
sed '3d' "$S/rsa6" > "$S/gap"; expect_bad ts calls "$S" gap "$S/rsa.pub.pem" rsa2048 5                          # a gap in the numbering
sed '3s#out/pkcs.sig#out/gone.sig#' "$S/rsa6" > "$S/nosig"; expect_bad ts calls "$S" nosig "$S/rsa.pub.pem" rsa2048 6
sed '1s#out/pkcs.sig#out/pss.sig#' "$S/rsa6" > "$S/swapped"; expect_bad ts calls "$S" swapped "$S/rsa.pub.pem" rsa2048 6 # a signature of the other mechanism
sed 's/\tpss\t/\tpkcs\t/; s#in/dgst.bin#in/msg.bin#; s#out/pss.sig#out/pkcs.sig#' "$S/rsa6" > "$S/onemech"; expect_bad ts calls "$S" onemech "$S/rsa.pub.pem" rsa2048 6 # no PSS in the mix
head -n 1 "$S/rsa6" > "$S/rsa1"; expect_ok ts calls "$S" rsa1 "$S/rsa.pub.pem" rsa2048 1
: > "$S/empty"; expect_bad ts calls "$S" empty "$S/rsa.pub.pem" rsa2048 1
head -c 70 /dev/urandom > "$S/out/garbage.sig"; sed '2s#out/pss.sig#out/garbage.sig#' "$S/rsa6" > "$S/garbage"; expect_bad ts calls "$S" garbage "$S/rsa.pub.pem" rsa2048 6
: > "$S/out/zero.sig"; sed '1s#out/pkcs.sig#out/zero.sig#' "$S/rsa6" > "$S/zero"; expect_bad ts calls "$S" zero "$S/rsa.pub.pem" rsa2048 6

# imports
imp() { local i; : > "$1"; for i in $(seq "$2"); do printf '%s\tts-imp-%s\t0\n' "$i" "$i" >> "$1"; done; }
imp "$tmp/imp6" 6; imp "$tmp/imp5" 5
expect_ok ts imports "$tmp/imp6" 6
expect_bad ts imports "$tmp/imp5" 6
expect_bad ts imports "$tmp/imp6" 0
expect_bad ts imports "$tmp/missing" 6
sed '2s/\t0$/\t1/' "$tmp/imp6" > "$tmp/imp-failed"; expect_bad ts imports "$tmp/imp-failed" 6
sed '2d' "$tmp/imp6" > "$tmp/imp-gap"; expect_bad ts imports "$tmp/imp-gap" 5
sed '2s/ts-imp-2/ts-imp-1/' "$tmp/imp6" > "$tmp/imp-dup"; expect_bad ts imports "$tmp/imp-dup" 6

# lists
printf 'ts-rsa\trsa2048\ttpm\nts-ec\tecdsa-p256\ttpm\nts-imp-1\trsa2048\ttpm\nts-imp-2\trsa2048\ttpm\nother\trsa2048\ttpm\n' > "$tmp/list"
specs="ts-rsa:rsa2048 ts-ec:ecdsa-p256 ts-imp-1:rsa2048 ts-imp-2:rsa2048"
expect_ok ts listed "$tmp/list" $specs
expect_bad ts listed "$tmp/list" $specs ts-imp-3:rsa2048                            # a missing key
expect_bad ts listed "$tmp/list" ts-imp-1:ecdsa-p256                                # a wrong type
sed 's/^ts-ec\(.*\)tpm$/ts-ec\1encrypted-host/' "$tmp/list" > "$tmp/list-kind"; expect_bad ts listed "$tmp/list-kind" $specs # a wrong kind
cat "$tmp/list" <(printf 'ts-rsa\trsa2048\ttpm\n') > "$tmp/list-twice"; expect_bad ts listed "$tmp/list-twice" $specs
expect_bad ts listed "$tmp/missing" $specs
expect_ok ts gone "$tmp/list" ts-imp-3 ts-imp-4
expect_bad ts gone "$tmp/list" ts-imp-3 ts-imp-1
expect_bad ts gone "$tmp/missing" ts-imp-3

# handles
printf -- '- 0x80000001\n' > "$tmp/h1"
printf -- '- 0x80000001\n- 0x80000002\n' > "$tmp/h12"
printf -- '- 0x80000002\n' > "$tmp/h2"
: > "$tmp/h0"
printf 'ERROR: Could not connect\n' > "$tmp/h-err"
expect_ok ts handles "$tmp/h0" "$tmp/h0"
expect_ok ts handles "$tmp/h1" "$tmp/h1"
expect_ok ts handles "$tmp/h12" "$tmp/h1"       # fewer is not a leak
expect_bad ts handles "$tmp/h0" "$tmp/h1"       # a handle left after the run
expect_bad ts handles "$tmp/h1" "$tmp/h12"
expect_bad ts handles "$tmp/h1" "$tmp/h2"
expect_bad ts handles "$tmp/h0" "$tmp/h-err"    # an error is not an empty list
expect_bad ts handles "$tmp/h-err" "$tmp/h0"
expect_bad ts handles "$tmp/h0" "$tmp/missing"
expect_ok ts leaked "$tmp/h0" "$tmp/h1"         # the control: the judgement reports the loaded object
expect_ok ts leaked "$tmp/h1" "$tmp/h12"
expect_bad ts leaked "$tmp/h1" "$tmp/h1"        # nothing left loaded: the control proves nothing
expect_bad ts leaked "$tmp/h0" "$tmp/h-err"
expect_bad ts leaked "$tmp/h0" "$tmp/missing"

for f in tpmslots-run.sh tpmslots-user.sh tpmslots-cases.sh; do bash -n "$ROOT/e2e/$f" || bad "$f does not parse"; done
exit "$fail"
