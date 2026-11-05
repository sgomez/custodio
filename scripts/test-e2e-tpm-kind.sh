#!/usr/bin/env bash
# F133: container-free checks of the tpm-kind-* cases: the judgements pass their self-test and a weakened judgement is caught, the placement (debian13 list, skip list,
# shellcheck disable=SC2086,SC2016 # the ids are words; the sed expressions of the mutants hold literal $

# group), the accounting in each TPM mode, and the step in guest.sh. NOT checked here: a real run (`just e2e-cases debian13 'tpm-kind-*'`, swtpm and none).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-tpm-kind: $*" >&2; fail=1; }
D=$ROOT/e2e/targets/debian13
ids="tpm-kind-import-rsa tpm-kind-import-ec tpm-kind-api-list tpm-kind-cli-list tpm-kind-journal"

bash "$ROOT/e2e/tpmkind-selftest.sh" || bad "the self-test of the tpm-kind judgements fails"
mutant() { # NAME FILE SED-EXPRESSION: a weakened copy of the judgements must be caught by the self-test
    mkdir "$tmp/$1"
    cp "$ROOT"/e2e/tpmkind-selftest.sh "$ROOT"/e2e/tpmkind-lib.sh "$ROOT"/e2e/tpmkind.py "$tmp/$1/"
    sed "$3" "$ROOT/e2e/$2" > "$tmp/$1/$2"
    if cmp -s "$ROOT/e2e/$2" "$tmp/$1/$2"; then bad "mutant $1 changes nothing"; fi
    if bash "$tmp/$1/tpmkind-selftest.sh" > /dev/null 2>&1; then bad "mutant $1 was not caught"; fi
}
mutant kind-substring tpmkind.py 's/e.get("CUSTODIO_STORAGE_KIND") != TPM/"tpm" not in str(e.get("CUSTODIO_STORAGE_KIND"))/'
mutant api-kind-ignored tpmkind.py 's/if mine\[0\]\[2\] != TPM:/if False:/'
mutant cli-kind-ignored tpmkind.py 's/if mine\[0\].get("kind") != TPM:/if False:/'
mutant outcome-ignored tpmkind.py "s/e.get(\"CUSTODIO_OUTCOME\") != \"stored\"/False/"
mutant storage-prefix tpmkind.py 's/re.fullmatch(r"Storage: tpm.*, storage\[0\])/storage[0].startswith("Storage: tpm")/'
mutant fixture-size tpmkind-lib.sh 's/(2048 bit/(/'
mutant unit-ignored tpmkind.py 's/r.get("_SYSTEMD_UNIT") == UNIT and //'

# placement: the ids are on the debian13 list and its skip list, not on the every-target list; the group is not the one of tpm-*
for id in $ids; do
    grep -qx "$id" "$D/cases.list" || bad "$id is not in $D/cases.list"
    grep -q "^$id:" "$D/skip.list" || bad "$id is not on the skip list of debian13"
    ! grep -qx "$id" "$ROOT/e2e/cases.list" || bad "$id is in e2e/cases.list (every target)"
    grep -rlx "$id" "$ROOT"/e2e/targets/*/cases.list | grep -qv debian13 && bad "$id is listed by another target"
done
[ "$(grep -c '^tpm-kind-' "$D/cases.list")" = 5 ] || bad "debian13 cases.list lists other tpm-kind cases than the five"
# shellcheck source=e2e/select.sh
source "$ROOT/e2e/select.sh"
for id in $ids tpm-kind-x; do [ "$(case_group "$id")" = tpm-kind ] || bad "case_group $id is '$(case_group "$id")', expected tpm-kind"; done
[ "$(case_group tpm-installed-unit-clean)" = tpm ] || bad "tpm-installed-unit-clean left its group"
# the cases tpmkind-run.sh reports are the listed ones
# shellcheck source=e2e/tpmkind-cases.sh
source "$ROOT/e2e/tpmkind-cases.sh"
[ "$(printf '%s\n' $TPMKIND_CASES | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "TPMKIND_CASES differ from the listed cases"
for id in $ids; do grep -q "judge $id " "$ROOT/e2e/tpmkind-run.sh" || bad "tpmkind-run.sh does not report $id"; done

# accounting: the guest's own skip output in each mode, checked with check-cases.sh the way run.sh does (mode in CHECK_TPM_MODE)
printf '%s\n' $ids > "$tmp/cases"
skipped_out() { ( E2E_SELECT_FILE=$tmp/cases; export E2E_SELECT_FILE; tpmkind_skip_all "$1" ); }
for m in none lacking; do
    skipped_out $m > "$tmp/out-$m"
    [ "$(grep -c '^E2E-CASE skipped tpm-kind-' "$tmp/out-$m")" = 5 ] || bad "mode $m: the guest does not report five skips"
    grep -q "E2E_TPM=$m" "$tmp/out-$m" || bad "mode $m: the skip reason does not name the mode"
    CHECK_TPM_MODE=$m bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$D/skip.list" "$tmp/out-$m" > /dev/null 2>&1 || bad "mode $m: skips are refused"
done
# swtpm: the same skips (as if the guest skipped) are refused, run ones are accepted, and a skip list naming them does not help
CHECK_TPM_MODE=swtpm bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$D/skip.list" "$tmp/out-none" > /dev/null 2>&1 && bad "swtpm: skipped tpm-kind cases are accepted"
sed 's/^E2E-CASE skipped /E2E-CASE run /' "$tmp/out-none" > "$tmp/out-run"
CHECK_TPM_MODE=swtpm bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$D/skip.list" "$tmp/out-run" > /dev/null 2>&1 || bad "swtpm: run tpm-kind cases are refused"
awk '/^E2E-CASE run / && !done { sub(/run/, "skipped"); done = 1 } { print }' "$tmp/out-run" > "$tmp/out-one"
CHECK_TPM_MODE=swtpm bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$D/skip.list" "$tmp/out-one" > /dev/null 2>&1 && bad "swtpm: one skipped tpm-kind case is accepted"
grep -q 'CHECK_TPM_MODE=\$tpm bash e2e/check-cases.sh check' "$ROOT/e2e/run.sh" || bad "run.sh does not give the accounting the TPM mode"

# the step in guest.sh: after the cli step, before the upgrade, and it runs tpmkind-run.sh with the mode
g=$ROOT/e2e/guest.sh
line() { grep -n -m1 -E -e "$1" "$g" | cut -d: -f1; }
c=$(line 'phase_runs cli'); t=$(line 'phase_runs tpm-kind'); u=$(line 'phase_runs upgrade')
[ -n "$c" ] && [ -n "$t" ] && [ -n "$u" ] && [ "$c" -lt "$t" ] && [ "$t" -lt "$u" ] || bad "the tpm-kind step is not between the cli step and the upgrade ($c $t $u)"
grep -q 'E2E_TPM=\$tpm_mode bash /e2e/tpmkind-run.sh' "$g" || bad "guest.sh does not run tpmkind-run.sh with the mode"
grep -q '^    tpm-kind) selected_in tpm-kind' "$ROOT/e2e/select.sh" || bad "phase_runs has no tpm-kind phase"
exit "$fail"
