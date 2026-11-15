#!/usr/bin/env bash
# F136: container-free checks of the tpm-dup-* cases: the judgements on good and bad evidence, and the reading of records (a synthetic one here; the agreement with the real `Record` encoder is the test `checks_every_stored_key` of
# `cargo test -p custodiod --test it tpm_duplicate::`). NOT checked here: a real run (`just e2e-cases debian13 'tpm-dup-*'` in swtpm, lacking and none).
# shellcheck disable=SC2086 # the ids are words
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-tpmdup: $*" >&2; fail=1; }
td() { python3 -I "$ROOT/e2e/tpmdup.py" "$@"; }

# judgements: good evidence passes, each bad one is named
expect_ok() { local out; out=$("$@") || { bad "failed to run: $*"; return; }; [ -z "$out" ] || bad "good evidence rejected ($*): $out"; }
expect_bad() { local out; out=$("$@" 2>&1) || true; [ -n "$out" ] || bad "bad evidence accepted ($*)"; }
cat > "$tmp/pub-good" <<'X'
name: 000b1234abcd
qualified name: 000b99
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: userwithauth|adminwithpolicy|sign
  raw: 0x40060
type:
  value: ecc
  raw: 0x23
curve-id:
  value: NIST p256
  raw: 0x3
x: 0123
y: 4567
X
{ cat "$tmp/pub-good"; echo "authorization policy: 1122334455667788990011223344556677889900112233445566778899001122"; } > "$tmp/pub-pol"
printf 'ERROR: Unable to run tpm2_readpublic\n' > "$tmp/pub-error"
expect_ok td authpolicy "$tmp/pub-good"
expect_bad td authpolicy "$tmp/pub-pol"
expect_bad td authpolicy "$tmp/pub-error"
: > "$tmp/pub-empty"; expect_bad td authpolicy "$tmp/pub-empty"
printf 'ERROR: Esys_Duplicate(0x99D) - tpm:session(1):a policy check failed\n' > "$tmp/dup-policy"
printf 'ERROR: Esys_Duplicate(0x124) - tpm:session(1):authorization type does not match\n' > "$tmp/dup-authtype"
printf 'ERROR: Unable to run tpm2_duplicate\n' > "$tmp/dup-other"
expect_ok td duplicate 1 "$tmp/dup-policy"
expect_bad td duplicate 0 "$tmp/dup-policy"
expect_bad td duplicate 1 "$tmp/dup-authtype"
expect_bad td duplicate 1 "$tmp/dup-other"
printf 'ERROR: Esys_Load(0x1DF) - tpm:parameter(1):integrity check failed\n' > "$tmp/load-integrity"
printf 'ERROR: Could not open path "k.pub": No such file or directory\n' > "$tmp/load-path"
printf 'ERROR: Esys_Load(0x2C4) - tpm:parameter(2):value is out of range or is not correct for the context\n' > "$tmp/load-template"
expect_ok td other-tpm 1 "$tmp/load-integrity"
expect_bad td other-tpm 0 "$tmp/load-integrity"
expect_bad td other-tpm 1 "$tmp/load-path"
expect_bad td other-tpm 1 "$tmp/load-template"
expect_ok td succeeded "the control" 0 "$tmp/load-path"
expect_bad td succeeded "the control" 1 "$tmp/load-path"
# the parent: the name made here is the stored one
printf '\x00\x0b\xaa\xbb' > "$tmp/name"
expect_ok td parent 000baabb "$tmp/name"
expect_bad td parent 000baabc "$tmp/name"
expect_bad td parent "" "$tmp/name"
# one template on both TPMs: the name, the x/y values differ, nothing else may
sed 's/^name: .*/name: 000bffff/; s/^x: .*/x: 9999/; s/^y: .*/y: 8888/' "$tmp/pub-good" > "$tmp/pub-other"
sed 's/userwithauth|adminwithpolicy|sign/userwithauth|sign/' "$tmp/pub-good" > "$tmp/pub-attrs"
expect_ok td samepub "$tmp/pub-good" "$tmp/pub-other"
expect_bad td samepub "$tmp/pub-good" "$tmp/pub-attrs"
expect_bad td samepub "$tmp/pub-good" "$tmp/pub-error"

# records: a synthetic record in the layout of record.rs
mkrec() { # OUT KIND-TAG ID NAME-HEX [pub-hex priv-hex]
    python3 -I - "$@" <<'PY'
import sys
out, tag, rid, name = sys.argv[1], int(sys.argv[2]), sys.argv[3], bytes.fromhex(sys.argv[4])
pub = bytes.fromhex(sys.argv[5]) if len(sys.argv) > 5 else b"\x00\x03abc"
priv = bytes.fromhex(sys.argv[6]) if len(sys.argv) > 6 else b"\x00\x02de"
prot = len(name).to_bytes(2, "big") + name + pub + priv if tag == 1 else b"credential"
data = b"CUSTODIO" + bytes([1, tag]) + (1000).to_bytes(4, "big") + bytes([len(rid)]) + rid.encode() + (4).to_bytes(4, "big") + b"cert" + len(prot).to_bytes(4, "big") + prot
open(out, "wb").write(data)
PY
}
S=$tmp/state; mkdir -p "$S/1000" "$S/1001"
mkrec "$S/1000/a" 1 a 000baabb
mkrec "$S/1000/b" 1 b 000bccdd 0002aabb 0003010203
mkrec "$S/1001/h" 3 h ""
printf 'plain' > "$S/1000/not-a-record"
td scan "$S" "$tmp/out" > "$tmp/scan.tsv" || bad "scan failed on good records"
[ "$(sort "$tmp/scan.tsv")" = "$(printf '1000\ta\ttpm\t000baabb\n1000\tb\ttpm\t000bccdd\n1001\th\tencrypted-host\t' | sort)" ] || bad "scan rows differ: $(cat "$tmp/scan.tsv")"
[ "$(od -An -tx1 -v "$tmp/out/1000-b/k.pub" | tr -d " \n")" = 0002aabb ] && [ "$(od -An -tx1 -v "$tmp/out/1000-b/k.priv" | tr -d " \n")" = 0003010203 ] || bad "scan wrote other public/private areas than the record holds"
[ "$(od -An -tx1 -v "$tmp/out/1000-a/k.pub" | tr -d " \n")" = 0003616263 ] || bad "scan wrote another public area for the first key"
! [ -e "$tmp/out/1001-h" ] || bad "scan wrote files for a key that is not a TPM key"
expect_ok td inventory "$tmp/scan.tsv" swtpm a b
expect_ok td inventory "$tmp/scan.tsv" lacking a b
expect_bad td inventory "$tmp/scan.tsv" swtpm a h # h is not a tpm key
expect_bad td inventory "$tmp/scan.tsv" swtpm a missing
grep -v $'\ta\t' "$tmp/scan.tsv" > "$tmp/scan-fewer.tsv"
expect_bad td inventory "$tmp/scan-fewer.tsv" swtpm a b
printf '1000\ta\ttpm\t00\n1000\ta\ttpm\t00\n1000\tb\ttpm\t00\n' > "$tmp/scan-twice.tsv"
expect_bad td inventory "$tmp/scan-twice.tsv" swtpm a b
# a record that does not parse is an error, not a silent skip
head -c 30 "$S/1000/a" > "$S/1000/trunc"
if td scan "$S" "$tmp/out2" > /dev/null 2>&1; then bad "scan accepted a truncated record"; fi
exit "$fail"
