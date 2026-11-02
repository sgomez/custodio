#!/usr/bin/env bash
# F93: container-free checks of the replace-* and delete-* cases: the self-test of the judgements (e2e/rd-selftest.sh) passes, a weakened judgement makes it fail,
# guest.sh runs the two groups behind phase_runs after the ops-polkit step and before the upgrade, and rd-run.sh reports every id of the list.
# NOT checked here: a real run (`just e2e-cases debian13 'replace-*' 'delete-*'`).
# shellcheck disable=SC2016 # the sed expressions of the mutants hold literal $ on purpose
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-rd: $*" >&2; fail=1; }

bash "$ROOT/e2e/rd-selftest.sh" || bad "the self-test of the rd judgements fails"
mutant() { # NAME SED-EXPRESSION: a copy of rd-lib.sh whose judgement is weakened must be caught by the self-test
    mkdir "$tmp/$1"
    cp "$ROOT"/e2e/rd-selftest.sh "$ROOT"/e2e/ops-lib.sh "$ROOT"/e2e/owner-lib.sh "$ROOT"/e2e/same-file.sh "$tmp/$1/"
    sed "$2" "$ROOT/e2e/rd-lib.sh" > "$tmp/$1/rd-lib.sh"
    if cmp -s "$ROOT/e2e/rd-lib.sh" "$tmp/$1/rd-lib.sh"; then bad "mutant $1 changes nothing"; fi
    if bash "$tmp/$1/rd-selftest.sh" > /dev/null 2>&1; then bad "mutant $1 was not caught"; fi
}
mutant sha-ignored 's/same_file "\$2" "\$3" || echo/true || echo/'
mutant not-sha-ignored 's/if same_file "\$2" "\$3"; then echo/if false; then echo/'
mutant subject-want 's/\*"\$3"\*) ;; \*) echo/*"$3"*) ;; *) true/'
mutant subject-unwanted 's/\*"\$4"\*) echo/*"$4"*) true/'
mutant token-present 's/\[ "\${spec%"\$id"}" = + \] || echo "\$file has a token for \$id"/true/'
mutant token-absent 's/\[ "\${spec%"\$id"}" = - \] || echo "\$file has no token for \$id"/true/'
mutant token-no-control 's/\[ "\$any" -eq 1 \] ||/true ||/'

g=$ROOT/e2e/guest.sh
line() { grep -n -m1 -E -e "$1" "$g" | cut -d: -f1; }
p=$(line 'phase_runs ops-polkit')
r=$(line 'phase_runs replace')
d=$(line 'phase_runs delete')
u=$(line 'phase_runs upgrade')
[ -n "$p" ] && [ -n "$r" ] && [ -n "$d" ] && [ -n "$u" ] || bad "guest.sh lacks a step"
[ "${p:-0}" -lt "${r:-0}" ] && [ "${r:-0}" -lt "${d:-0}" ] && [ "${d:-0}" -lt "${u:-0}" ] || bad "the replace/delete steps are not between ops-polkit and the upgrade ($p $r $d $u)"
grep -q 'rd-run.sh replace' "$g" || bad "guest.sh does not run the replace group"
grep -q 'rd-run.sh delete' "$g" || bad "guest.sh does not run the delete group"
grep -q 'rd-run.sh' "$g" || bad "guest.sh does not run rd-run.sh"
while IFS= read -r id; do
    grep -q "judge $id " "$ROOT/e2e/rd-run.sh" || bad "rd-run.sh does not report $id"
done < <(grep -E '^(replace|delete)-' "$ROOT/e2e/cases.list")
exit "$fail"
