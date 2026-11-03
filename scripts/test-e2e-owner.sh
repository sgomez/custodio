#!/usr/bin/env bash
# F91: container-free checks of the owner-* cases: the self-test of the judgements (e2e/owner-selftest.sh) passes, a weakened judgement makes it fail,
# and guest.sh runs the step behind phase_runs, after the journal step and before the upgrade. NOT checked here: a real run (`just e2e-cases debian13 'owner-*'`).
# shellcheck disable=SC2016 # the sed expressions of the mutants hold literal $ on purpose
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-owner: $*" >&2; fail=1; }

bash "$ROOT/e2e/owner-selftest.sh" || bad "the self-test of the owner judgements fails"
# negative controls: a copy of owner-lib.sh whose judgement is weakened must be caught by the self-test
mutant() { # NAME SED-EXPRESSION
    mkdir "$tmp/$1"
    cp "$ROOT"/e2e/owner-selftest.sh "$ROOT"/e2e/owner-journal.py "$tmp/$1/"
    sed "$2" "$ROOT/e2e/owner-lib.sh" > "$tmp/$1/owner-lib.sh"
    if bash "$tmp/$1/owner-selftest.sh" > /dev/null 2>&1; then bad "mutant $1 was not caught"; fi
}
mutant any-error 's/\[ "\$got" = "\$NO_SUCH_KEY" \]/true/'
mutant count-ignored 's/\[ "\$before" -eq "\$after" \]/true/'
mutant list-foreign 's/\[ "\${spec%"\$id"}" = + \] || echo "\$file lists \$id"/true/'
mutant verify-always 's/|| echo "\$sig does not verify against \$cert"/|| true/'

g=$ROOT/e2e/guest.sh
line() { grep -n -m1 -E -e "$1" "$g" | cut -d: -f1; }
o=$(line 'phase_runs owner')
j=$(line 'phase_runs journal')
u=$(line 'phase_runs upgrade')
[ -n "$o" ] && [ -n "$j" ] && [ -n "$u" ] || bad "guest.sh lacks a step"
[ "${j:-0}" -lt "${o:-0}" ] && [ "${o:-0}" -lt "${u:-0}" ] || bad "the owner step is not between the journal step and the upgrade ($j $o $u)"
grep -q 'owner-run.sh' "$g" || bad "guest.sh does not run owner-run.sh"
# the cases of the list are the ones owner-run.sh reports
while IFS= read -r id; do
    grep -q "judge $id " "$ROOT/e2e/owner-run.sh" || bad "owner-run.sh does not report $id"
done < <(grep '^owner-' "$ROOT/e2e/cases.list")
exit "$fail"
