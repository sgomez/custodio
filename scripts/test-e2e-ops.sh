#!/usr/bin/env bash
# F92: container-free checks of the ops-polkit-* cases: the self-test of the judgements (e2e/ops-selftest.sh) passes, a weakened judgement makes it fail, and
# guest.sh runs the step behind phase_runs, after the owner step and before the upgrade. NOT checked here: a real run (`just e2e-cases debian13 'ops-polkit-*'`).
# shellcheck disable=SC2016 # the sed expressions of the mutants hold literal $ on purpose
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-ops: $*" >&2; fail=1; }

bash "$ROOT/e2e/ops-selftest.sh" || bad "the self-test of the ops judgements fails"
mutant() { # NAME SED-EXPRESSION: a copy of ops-lib.sh whose judgement is weakened must be caught by the self-test
    mkdir "$tmp/$1"
    cp "$ROOT/e2e/ops-selftest.sh" "$tmp/$1/"
    sed "$2" "$ROOT/e2e/ops-lib.sh" > "$tmp/$1/ops-lib.sh"
    if cmp -s "$ROOT/e2e/ops-lib.sh" "$tmp/$1/ops-lib.sh"; then bad "mutant $1 changes nothing"; fi
    if bash "$tmp/$1/ops-selftest.sh" > /dev/null 2>&1; then bad "mutant $1 was not caught"; fi
}
mutant result-ignored 's/\[ "\$result" = .\*. \] || \[ "\$got" = "\$result" \]/true/'
mutant log-ignored 's/\[ "\$got" = "\$logged" \]/true/'
mutant state-ignored 's/cmp -s "\$before" "\$after" ||/true ||/'
mutant listed-present 's/\[ "\${spec%"\$id"}" = + \] || echo "\$file lists \$id"/true/'
mutant differ-ignored 's/if cmp -s "\$2" "\$3"/if false/'

g=$ROOT/e2e/guest.sh
line() { grep -n -m1 -E -e "$1" "$g" | cut -d: -f1; }
o=$(line 'phase_runs owner')
p=$(line 'phase_runs ops-polkit')
u=$(line 'phase_runs upgrade')
[ -n "$o" ] && [ -n "$p" ] && [ -n "$u" ] || bad "guest.sh lacks a step"
[ "${o:-0}" -lt "${p:-0}" ] && [ "${p:-0}" -lt "${u:-0}" ] || bad "the ops-polkit step is not between the owner step and the upgrade ($o $p $u)"
grep -q 'ops-run.sh' "$g" || bad "guest.sh does not run ops-run.sh"
while IFS= read -r id; do
    grep -q "judge $id " "$ROOT/e2e/ops-run.sh" || bad "ops-run.sh does not report $id"
done < <(grep '^ops-polkit-' "$ROOT/e2e/cases.list")
exit "$fail"
