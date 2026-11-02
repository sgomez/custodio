#!/usr/bin/env bash
# F94: container-free checks of the journal-ops-* cases: the self-test of the judgements (e2e/jo-selftest.sh) passes, a weakened judgement makes it fail,
# guest.sh runs the step behind phase_runs after the delete step and before the upgrade, jo-run.sh reports every id of the list, and every call of the
# ledger plan is made by jo-user.sh.
# NOT checked here: a real run (`just e2e-cases debian13 'journal-ops-*'`).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-jo: $*" >&2; fail=1; }

bash "$ROOT/e2e/jo-selftest.sh" || bad "the self-test of the jo judgements fails"
mutant() { # NAME FILE SED-EXPRESSION...: a copy of the judgements with one weakened must be caught by the self-test
    local name=$1 file=$2 expr
    shift 2
    mkdir -p "$tmp/$name/docs"
    cp "$ROOT"/e2e/jo.py "$ROOT"/e2e/journal.py "$ROOT"/e2e/jo-selftest.py "$ROOT"/e2e/jo-selftest.sh "$tmp/$name/"
    cp "$ROOT/docs/audit.md" "$tmp/$name/docs/"
    cp "$tmp/$name/$file" "$tmp/$name/$file.orig"
    for expr in "$@"; do sed -i "$expr" "$tmp/$name/$file"; done
    if cmp -s "$tmp/$name/$file.orig" "$tmp/$name/$file"; then bad "mutant $name changes nothing"; fi
    if python3 -I "$tmp/$name/jo-selftest.py" "$tmp/$name" "$tmp/$name/docs/audit.md" > /dev/null 2>&1; then bad "mutant $name was not caught"; fi
}
# shellcheck disable=SC2016 # the sed expressions hold literal $ and quotes on purpose
{
    mutant pid-dropped jo.py 's/mine = \[e for e in audits if field(e, "CUSTODIO_PID") == line\["pid"\]\]/mine = list(audits)/'
    mutant uid-dropped jo.py '/"CUSTODIO_UID": line\["uid"\],/d'
    mutant at-least-one jo.py 's/if len(mine) != 1:/if len(mine) < 1:/'
    mutant unexplained-ignored jo.py 's/if id(entry) in matched or/if True or/'
    mutant key-type-dropped jo.py '/"CUSTODIO_KEY_TYPE": None if/d'
    mutant base64-left-out journal.py 's/std = base64.b64encode(data)/std = b"-"/' 's/url = base64.urlsafe_b64encode(data)/url = b"-"/' 's/out.update(b64_substrings(data))/pass/'
    mutant unknown-query-ignored jo.py 's/raise ValueError(f"the documented query .{raw}. has .{token}., which this step does not know how to judge")/continue/'
    mutant superset-accepted jo.py 's/if predicted.count(t) != got.count(t):/if predicted.count(t) > got.count(t):/'
    mutant window-ignored jo.py 's/if field(row, "__CURSOR") in cursors:/if True:/'
}

g=$ROOT/e2e/guest.sh
line() { grep -n -m1 -E -e "$1" "$g" | cut -d: -f1; }
d=$(line 'phase_runs delete')
j=$(line 'phase_runs journal-ops')
u=$(line 'phase_runs upgrade')
[ -n "$d" ] && [ -n "$j" ] && [ -n "$u" ] || bad "guest.sh lacks a step"
[ "${d:-0}" -lt "${j:-0}" ] && [ "${j:-0}" -lt "${u:-0}" ] || bad "the journal-ops step is not between delete and the upgrade ($d $j $u)"
grep -q 'jo-run.sh' "$g" || bad "guest.sh does not run jo-run.sh"
n=0
while IFS= read -r id; do
    n=$((n + 1))
    grep -q "judge $id " "$ROOT/e2e/jo-run.sh" || bad "jo-run.sh does not report $id"
done < <(grep -E '^journal-ops-' "$ROOT/e2e/cases.list")
[ "$n" -ge 7 ] || bad "cases.list has $n journal-ops cases, expected 7"
while read -r label _; do
    case $label in "" | "#"*) continue ;; esac
    grep -qE "^(dbus|cli|p11sign) $label( |\$)" "$ROOT/e2e/jo-user.sh" || bad "jo-user.sh does not make the call $label"
done < "$ROOT/e2e/jo-ledger.txt"
# shellcheck disable=SC2016 # the text searched for holds a literal $PWD
grep -q -- '-v "$PWD/docs/audit.md:/e2e-docs/audit.md:ro"' "$ROOT/e2e/run.sh" || bad "run.sh does not mount docs/audit.md for the guest (jo-run.sh extracts the queries from it)"
exit "$fail"
