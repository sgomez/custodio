#!/usr/bin/env bash
# F137: container-free checks of the pcr-* cases: the placement (debian13 list and skip list, group), the accounting (a skip refused in swtpm and lacking, accepted in none), the
# judgements of e2e/pcr.py on good and bad evidence (PCRs not changed by the extension, PCRs not reset by the restart, an unchanged service pid, a signature that does not verify,
# a signing refusal, a kind that changed, a missing key, fewer than two tpm keys, a control that proves nothing), and the restart helper's mode check. NOT checked here: a real
# run (`just e2e-cases debian13 'pcr-*'` in swtpm, lacking and none).
# shellcheck disable=SC2086,SC2015,SC2016 # SC2086: the ids are words; SC2015: A && B || bad is the check; SC2016: stub text and sed programs in single quotes
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
# shellcheck disable=SC2034 # fail is read by the sourced VM section
bad() { echo "test-e2e-pcr: $*" >&2; fail=1; }
D=$ROOT/e2e/targets/debian13
ids="pcr-extended-signs pcr-restarted-signs pcr-signs-every-key"
pc() { python3 -I "$ROOT/e2e/pcr.py" "$@"; }

# placement
for id in $ids; do
    grep -qx "$id" "$D/cases.list" || bad "$id is not in $D/cases.list"
    grep -q "^$id:" "$D/skip.list" || bad "$id is not on the skip list of debian13"
    ! grep -qx "$id" "$ROOT/e2e/cases.list" || bad "$id is in e2e/cases.list (every target)"
    ! grep -rlx "$id" "$ROOT"/e2e/targets/*/cases.list | grep -qv debian13 || bad "$id is listed by another target"
done
[ "$(grep -c '^pcr-' "$D/cases.list")" = 3 ] || bad "debian13 cases.list lists other pcr cases than the three"
# shellcheck source=e2e/select.sh
source "$ROOT/e2e/select.sh"
for id in $ids pcr-x; do [ "$(case_group "$id")" = pcr ] || bad "case_group $id is '$(case_group "$id")', expected pcr"; done
# shellcheck source=e2e/pcr-cases.sh
source "$ROOT/e2e/pcr-cases.sh"
[ "$(printf '%s\n' $PCR_CASES | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "PCR_CASES differ from the listed cases"
[ "$(pc cases | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "pcr.py cases differ from the listed cases"

# accounting
printf '%s\n' $ids > "$tmp/cases"
( E2E_SELECT_FILE=$tmp/cases; export E2E_SELECT_FILE; pcr_skip_all none ) > "$tmp/out-all"
[ "$(grep -c '^E2E-CASE skipped pcr-' "$tmp/out-all")" = 3 ] || bad "the guest does not report three skips"
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

expect_ok() { local out; out=$("$@") || { bad "failed to run: $*"; return; }; [ -z "$out" ] || bad "good evidence rejected ($*): $out"; }
expect_bad() { local out; out=$("$@" 2>&1) || true; [ -n "$out" ] || bad "bad evidence accepted ($*)"; }

# PCR readings (tpm2_pcrread output)
h() { printf '%064d' "$1"; }
reading() { # FILE V0 V7 V11
    printf 'sha256:\n  0 : 0x%s\n  7 : 0x%s\n  11: 0x%s\n' "$(h "$2")" "$(h "$3")" "$(h "$4")" > "$1"
}
reading "$tmp/first" 0 0 0
reading "$tmp/ext" 1 2 3
reading "$tmp/ext-no7" 1 0 3
reading "$tmp/ext-no0" 0 2 3
reading "$tmp/ext-no11" 1 2 0
reading "$tmp/again" 9 9 9
reading "$tmp/after-ext2" 4 5 6
reading "$tmp/after-7" 0 2 0
reading "$tmp/after-0" 1 0 0
printf 'sha256:\n  7 : 0x%s\n' "$(h 0)" > "$tmp/only7"
printf 'ERROR: no tpm\n' > "$tmp/pcr-error"
expect_ok pc extended "$tmp/first" "$tmp/ext"
expect_bad pc extended "$tmp/first" "$tmp/ext-no7"
expect_bad pc extended "$tmp/first" "$tmp/ext-no0"
expect_bad pc extended "$tmp/first" "$tmp/ext-no11"
expect_bad pc extended "$tmp/first" "$tmp/first"
expect_bad pc extended "$tmp/first" "$tmp/only7"
expect_bad pc extended "$tmp/first" "$tmp/pcr-error"
expect_bad pc extended "$tmp/first" "$tmp/missing"
expect_ok pc restarted "$tmp/first" "$tmp/ext" "$tmp/first"
expect_bad pc restarted "$tmp/first" "$tmp/ext" "$tmp/ext"        # not reset
expect_bad pc restarted "$tmp/first" "$tmp/ext" "$tmp/after-7"    # PCR 7 still extended
expect_bad pc restarted "$tmp/first" "$tmp/ext" "$tmp/after-ext2" # extended again, different from the extended ones but not the first reading
expect_bad pc restarted "$tmp/first" "$tmp/ext" "$tmp/again"
expect_bad pc restarted "$tmp/first" "$tmp/ext" "$tmp/pcr-error"
# pids
echo 100 > "$tmp/p100"; echo 200 > "$tmp/p200"; echo 0 > "$tmp/p0"; echo abc > "$tmp/pabc"
expect_ok pc pid "$tmp/p100" "$tmp/p200"
expect_bad pc pid "$tmp/p100" "$tmp/p100"
expect_bad pc pid "$tmp/p100" "$tmp/p0"
expect_bad pc pid "$tmp/p0" "$tmp/p200"
expect_bad pc pid "$tmp/p100" "$tmp/pabc"
expect_bad pc pid "$tmp/p100" "$tmp/missing"
# lists
printf 'pr-rsa\trsa2048\ttpm\npr-ec\tecdsa-p256\ttpm\nrsa1\trsa2048\ttpm\n' > "$tmp/list"
printf 'pr-rsa\trsa2048\ttpm\npr-ec\tecdsa-p256\ttpm\n' > "$tmp/list2"
printf 'pr-rsa\trsa2048\ttpm\npr-ec\tecdsa-p256\tencrypted-host\n' > "$tmp/list-kind"
printf 'pr-rsa\trsa2048\ttpm\n' > "$tmp/list-one"
printf 'pr-rsa\trsa2048\ttpm\nother\tecdsa-p256\ttpm\n' > "$tmp/list-missing"
printf 'pr-rsa\trsa2048\ttpm\npr-ec\tecdsa-p256\ttpm\nrsa1\trsa2048\tencrypted-host\n' > "$tmp/list-changed"
specs="pr-rsa:rsa2048 pr-ec:ecdsa-p256"
for m in swtpm lacking; do
    expect_ok pc keys "$tmp/list" "$tmp/list" $m $specs
    expect_ok pc keys "$tmp/list2" "$tmp/list2" $m $specs
    expect_bad pc keys "$tmp/list" "$tmp/list-kind" $m $specs   # a kind that changed
    expect_bad pc keys "$tmp/list" "$tmp/list-missing" $m $specs # a missing key
    expect_bad pc keys "$tmp/list" "$tmp/list-one" $m $specs     # fewer than two tpm keys, a missing key
    expect_bad pc keys "$tmp/list" "$tmp/list-changed" $m $specs # another key's kind changed
    expect_bad pc keys "$tmp/list" "$tmp/missing" $m $specs
done
expect_bad pc keys "$tmp/list" "$tmp/list" none $specs
[ "$(pc enumerate "$tmp/list" | wc -l)" = 3 ] || bad "enumerate does not list every tpm key"
[ "$(pc enumerate "$tmp/list-kind" | wc -l)" = 1 ] || bad "enumerate lists a key that is not of kind tpm"

# signatures, made by openssl
S=$tmp/s
mkdir -p "$S/in" "$S/out"
head -c 300 /dev/urandom > "$S/in/msg.bin"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/rsa.key" 2> /dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/ec.key" 2> /dev/null
openssl pkey -in "$tmp/rsa.key" -pubout -out "$S/in/pr-rsa.pub.pem"
openssl pkey -in "$tmp/ec.key" -pubout -out "$S/in/pr-ec.pub.pem"
openssl pkey -in "$tmp/rsa.key" -pubout -out "$S/in/rsa1.pub.pem"
mksigs() { # TAG
    openssl dgst -sha256 -sign "$tmp/rsa.key" -out "$S/out/$1-pr-rsa.sig" "$S/in/msg.bin"
    openssl dgst -sha256 -sign "$tmp/rsa.key" -out "$S/out/$1-rsa1.sig" "$S/in/msg.bin"
    openssl dgst -sha256 -sign "$tmp/ec.key" -out "$S/out/$1-pr-ec.sig" "$S/in/msg.bin"
    for k in pr-rsa rsa1 pr-ec; do echo 0 > "$S/out/$1-$k.rc"; done
}
mksigs g
expect_ok pc sigs "$S" g "$tmp/list"
cp -r "$S" "$tmp/S2"
echo 2 > "$tmp/S2/out/g-pr-ec.rc"; echo CKR_FUNCTION_FAILED > "$tmp/S2/out/g-pr-ec.log"
expect_bad pc sigs "$tmp/S2" g "$tmp/list" # a signing refusal
cp -r "$S" "$tmp/S3"
head -c 256 /dev/urandom > "$tmp/S3/out/g-pr-rsa.sig"
expect_bad pc sigs "$tmp/S3" g "$tmp/list" # a signature that does not verify
cp -r "$S" "$tmp/S4"
openssl dgst -sha256 -sign "$tmp/ec.key" -out "$tmp/S4/out/g-pr-rsa.sig" "$S/in/msg.bin"
expect_bad pc sigs "$tmp/S4" g "$tmp/list" # a signature of another key
cp -r "$S" "$tmp/S5"
head -c 70 /dev/urandom > "$tmp/S5/out/g-pr-ec.sig"
expect_bad pc sigs "$tmp/S5" g "$tmp/list" # garbage in place of a DER signature
cp -r "$S" "$tmp/S6"
rm "$tmp/S6/out/g-rsa1.sig"
expect_bad pc sigs "$tmp/S6" g "$tmp/list" # a listed tpm key that did not sign
: > "$tmp/S6/out/g-rsa1.sig"
expect_bad pc sigs "$tmp/S6" g "$tmp/list" # an empty signature
expect_bad pc sigs "$S" g "$tmp/list-one" # fewer than two tpm keys: nothing to prove
expect_bad pc sigs "$S" other "$tmp/list" # a round that did not happen

# the control
printf 'custodio-pcr-secret' > "$tmp/c-ok"
printf 'ERROR: Esys_Unseal(0x99D) - tpm:session(1):a policy check failed\n' > "$tmp/c-policy"
printf 'ERROR: Unable to run tpm2_unseal\n' > "$tmp/c-other"
expect_ok pc control 0 "$tmp/c-ok" 1 "$tmp/c-policy" custodio-pcr-secret
expect_bad pc control 1 "$tmp/c-policy" 1 "$tmp/c-policy" custodio-pcr-secret # never satisfied
expect_bad pc control 0 "$tmp/c-ok" 0 "$tmp/c-ok" custodio-pcr-secret        # still satisfied: the extension did nothing
expect_bad pc control 0 "$tmp/c-ok" 1 "$tmp/c-other" custodio-pcr-secret     # failed, not for the policy
expect_bad pc control 0 "$tmp/c-other" 1 "$tmp/c-policy" custodio-pcr-secret  # before: no secret
expect_bad pc control 0 "$tmp/c-ok" 1 "$tmp/missing" custodio-pcr-secret

# the restart helper refuses a mode with no TPM and the guest scripts parse
( source "$ROOT/e2e/tpm-lib.sh"; ! tpm_swtpm_restart none 2> /dev/null ) || bad "tpm_swtpm_restart accepts mode none"
for f in pcr-run.sh pcr-user.sh pcr-cases.sh; do bash -n "$ROOT/e2e/$f" || bad "$f does not parse"; done
# shellcheck disable=SC1091 # the section is a part of this script, linted on its own as shellcheck shell=bash
source "$ROOT/scripts/lib/e2e-pcr-vm-section.sh"
