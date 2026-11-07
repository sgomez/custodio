#!/usr/bin/env bash
# F136: container-free checks of the tpm-dup-* cases: the placement (debian13 list and skip list, group), the accounting (a skip refused in swtpm and lacking, accepted in none), the
# judgements on good and bad evidence, and the reading of records (a synthetic one here; the agreement with the real `Record` encoder is the test `checks_every_stored_key` of
# `cargo test -p custodiod --test tpm_duplicate`). NOT checked here: a real run (`just e2e-cases debian13 'tpm-dup-*'` in swtpm, lacking and none).
# shellcheck disable=SC2086 # the ids are words
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-tpmdup: $*" >&2; fail=1; }
D=$ROOT/e2e/targets/debian13
ids="tpm-dup-authpolicy-empty tpm-dup-duplicate-fails tpm-dup-other-tpm"
td() { python3 -I "$ROOT/e2e/tpmdup.py" "$@"; }

# placement
for id in $ids; do
    grep -qx "$id" "$D/cases.list" || bad "$id is not in $D/cases.list"
    grep -q "^$id:" "$D/skip.list" || bad "$id is not on the skip list of debian13"
    ! grep -qx "$id" "$ROOT/e2e/cases.list" || bad "$id is in e2e/cases.list (every target)"
    ! grep -rlx "$id" "$ROOT"/e2e/targets/*/cases.list | grep -qv debian13 || bad "$id is listed by another target"
done
[ "$(grep -c '^tpm-dup-' "$D/cases.list")" = 3 ] || bad "debian13 cases.list lists other tpm-dup cases than the three"
# shellcheck source=e2e/select.sh
source "$ROOT/e2e/select.sh"
for id in $ids tpm-dup-x; do [ "$(case_group "$id")" = tpmdup ] || bad "case_group $id is '$(case_group "$id")', expected tpmdup"; done
[ "$(case_group tpm-installed-unit-clean)" = tpm ] || bad "tpm-installed-unit-clean left its group"
# shellcheck source=e2e/tpmdup-cases.sh
source "$ROOT/e2e/tpmdup-cases.sh"
[ "$(printf '%s\n' $TPMDUP_CASES | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "TPMDUP_CASES differ from the listed cases"

# accounting: the guest's own skips in mode none are accepted; in swtpm and lacking a skip is refused, even when a skip list names it
printf '%s\n' $ids > "$tmp/cases"
( E2E_SELECT_FILE=$tmp/cases; export E2E_SELECT_FILE; tpmdup_skip_all none ) > "$tmp/out-all"
[ "$(grep -c '^E2E-CASE skipped tpm-dup-' "$tmp/out-all")" = 3 ] || bad "the guest does not report three skips"
grep -q 'E2E_TPM=none' "$tmp/out-all" || bad "the skip reason does not name the mode"
sed 's/^E2E-CASE skipped /E2E-CASE run /' "$tmp/out-all" > "$tmp/out-run"
awk '/^E2E-CASE run / && !done { sub(/run/, "skipped"); done = 1 } { print }' "$tmp/out-run" > "$tmp/out-one"
sed -n 's/^E2E-CASE skipped \(.*\)/\1: not applicable/p' "$tmp/out-all" > "$tmp/skip-all"
check() { CHECK_TPM_MODE=$1 bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$2" "$3" > /dev/null 2>&1; }
check none "$D/skip.list" "$tmp/out-all" || bad "mode none: the skips are refused"
check none "$D/skip.list" "$tmp/out-run" || bad "mode none: run cases are refused"
echo "# none" > "$tmp/skip-empty"
! check none "$tmp/skip-empty" "$tmp/out-all" || bad "mode none: skips are accepted with no skip list"
for m in swtpm lacking; do
    check $m "$D/skip.list" "$tmp/out-run" || bad "mode $m: run cases are refused"
    ! check $m "$D/skip.list" "$tmp/out-all" || bad "mode $m: skipped cases are accepted"
    ! check $m "$D/skip.list" "$tmp/out-one" || bad "mode $m: one skipped case is accepted"
    ! check $m "$tmp/skip-all" "$tmp/out-all" || bad "mode $m: a skip list naming the cases lets the skips through"
done

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
