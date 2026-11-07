#!/usr/bin/env bash
# F134: container-free checks of the sign-* cases: the judgements pass their self-test, the placement (debian13 list, not the every-target list, never on the skip list, group),
# that the guest's cases are the listed ones, and the accounting rejecting a sign-* skip in each TPM mode. NOT checked here: a real run
# (`just e2e-cases debian13 'sign-*'` in swtpm, none and lacking).
# shellcheck disable=SC2086 # the ids are words
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-sign: $*" >&2; fail=1; }
D=$ROOT/e2e/targets/debian13
ids="sign-kind-matches-mode sign-rsa-pkcs sign-rsa-pss-sha256 sign-rsa-pss-sha384 sign-rsa-pss-sha512 sign-rsa-composed sign-ec-ecdsa sign-ec-composed"

bash "$ROOT/e2e/sign-selftest.sh" > /dev/null || bad "the self-test of the sign judgements fails"

# placement
for id in $ids; do
    grep -qx "$id" "$D/cases.list" || bad "$id is not in $D/cases.list"
    ! grep -q "^$id:" "$D/skip.list" || bad "$id is on the skip list of debian13"
    ! grep -qx "$id" "$ROOT/e2e/cases.list" || bad "$id is in e2e/cases.list (every target)"
    ! grep -rlx "$id" "$ROOT"/e2e/targets/*/cases.list | grep -qv debian13 || bad "$id is listed by another target"
done
grep -rh '^sign-' "$ROOT"/e2e/targets/*/skip.list "$ROOT/e2e/cases.list" 2> /dev/null | grep -q . && bad "a sign-* case is on a skip list or in the every-target list"
[ "$(grep -c '^sign-' "$D/cases.list")" = 8 ] || bad "debian13 cases.list lists other sign cases than the eight"
# shellcheck source=e2e/select.sh
source "$ROOT/e2e/select.sh"
for id in $ids sign-x; do [ "$(case_group "$id")" = sign ] || bad "case_group $id is '$(case_group "$id")', expected sign"; done
# the cases sign-run.sh reports are the listed ones: the judgements' groups and the kind case
got=$( (echo sign-kind-matches-mode; python3 -I "$ROOT/e2e/sign.py" groups) | sort)
[ "$got" = "$(printf '%s\n' $ids | sort)" ] || bad "the cases of sign.py differ from the listed ones"

# accounting: as if the guest ran or skipped them, in each mode (run.sh sets CHECK_TPM_MODE)
printf '%s\n' $ids > "$tmp/cases"
sed 's/^/E2E-CASE run /' "$tmp/cases" > "$tmp/out-run"
sed 's/^E2E-CASE run /E2E-CASE skipped /' "$tmp/out-run" > "$tmp/out-all"
awk '/^E2E-CASE run / && !done { sub(/run/, "skipped"); done = 1 } { print }' "$tmp/out-run" > "$tmp/out-one"
sed 's/^E2E-CASE skipped \(.*\)/\1: not applicable/' "$tmp/out-all" > "$tmp/skip-all"
check() { CHECK_TPM_MODE=$1 bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$2" "$3" > /dev/null 2>&1; }
for m in swtpm none lacking; do
    check $m "$D/skip.list" "$tmp/out-run" || bad "mode $m: the run sign cases are refused"
    ! check $m "$D/skip.list" "$tmp/out-one" || bad "mode $m: one skipped sign case is accepted"
    ! check $m "$D/skip.list" "$tmp/out-all" || bad "mode $m: skipped sign cases are accepted"
    # even a skip list that names every case does not help
    ! check $m "$tmp/skip-all" "$tmp/out-all" || bad "mode $m: a skip list naming the cases lets the skips through"
    ! check $m "$tmp/skip-all" "$tmp/out-one" || bad "mode $m: a skip list naming the cases lets one skip through"
done
exit "$fail"
