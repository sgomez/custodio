#!/usr/bin/env bash
# F95: container-free checks of the appid-* cases: the self-test of the judgements (e2e/appid-selftest.sh) passes, a weakened judgement makes it fail, guest.sh
# runs the step behind phase_runs after journal-ops and before the upgrade, appid-run.sh reports every id of the list, and appid-user.sh makes every kind of
# caller and operation that the plan holds.
# NOT checked here: a real run (`just e2e-cases debian13 'appid-*'`).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-appid: $*" >&2; fail=1; }

bash "$ROOT/e2e/appid-selftest.sh" || bad "the self-test of the appid judgements fails"
mutant() { # NAME FILE SED-EXPRESSION...: a copy of the judgements with one weakened must be caught by the self-test
    local name=$1 file=$2 expr
    shift 2
    mkdir -p "$tmp/$name/docs"
    cp "$ROOT"/e2e/appid*.py "$ROOT"/e2e/jo.py "$ROOT"/e2e/appid-ledger.txt "$tmp/$name/"
    cp "$ROOT/docs/audit.md" "$tmp/$name/docs/"
    cp "$tmp/$name/$file" "$tmp/$name/$file.orig"
    for expr in "$@"; do sed -i "$expr" "$tmp/$name/$file"; done
    if cmp -s "$tmp/$name/$file.orig" "$tmp/$name/$file"; then bad "mutant $name changes nothing"; fi
    if python3 -I "$tmp/$name/appid-selftest-rules.py" "$tmp/$name" > /dev/null 2>&1 \
        && python3 -I "$tmp/$name/appid-selftest.py" "$tmp/$name" "$tmp/$name/docs/audit.md" > /dev/null 2>&1; then bad "mutant $name was not caught"; fi
}
# shellcheck disable=SC2016 # the sed expressions hold literal $ and quotes on purpose
{
    mutant state-loose appid.py 's/if state != row\["app_state"\]:/if state is None:/'
    mutant id-not-compared appid.py 's/if row\["app_state"\] == "read" and ident != row\["app_id"\]:/if False:/'
    mutant no-field-dropped appid.py 's/if row\["app_state"\] != "read" and "CUSTODIO_APP_ID" in entry:/if False:/'
    mutant sweep-some-fields appid_journal.py 's/for name, value in entry:/for name, value in [f for f in entry if f[0] == "MESSAGE"]:/'
    mutant duration-dropped appid_journal.py 's/if r\["dur"\] > limit:/if False:/'
    mutant slack-ceiling-dropped appid_journal.py 's/if slack > ABS_SLACK_CEILING:/if False:/'
    mutant unknown-app-query-ignored appid_journal.py 's/problems.append(f"the documented query .{raw}. names the app-id in a way this step does not judge")/pass/'
    mutant pid-dropped appid.py 's/mine = \[e for e in audits if jo.field(e, "CUSTODIO_PID") == row\["pid"\]\]/mine = list(audits)/'
    mutant unexplained-dropped appid.py 's/for e in audits if jo.field(e, "CUSTODIO_PID") not in pids\]/for e in audits if False]/'
    mutant request-count-dropped appid.py 's/if r\["nreq"\] != 1:/if False:/'
    mutant subject-dropped appid.py 's/if r\["subj"\] != f"{r\[.pid.\]}\/{r\[.uid.\]}":/if False:/'
    mutant signature-dropped appid.py 's/and not verify(label):/and False:/'
    mutant result-dropped appid.py 's/if r\["got"\] != r\["result"\]:/if False:/'
    mutant cap-margin-dropped appid_rules.py 's/if order.index(after) < cap + 2:/if order.index(after) < 0:/'
    mutant cap-inside-dropped appid_rules.py 's/if order.index(within) > cap - 3:/if False:/'
    mutant hostile-rules-dropped appid_rules.py 's/if reader_state(name) != (state, ident):/if False:/'
    mutant ledger-state-dropped appid.py 's/if named\["state"\] != p\["app_state"\] or named\["id"\] != resolved:/if False:/'
    mutant only-first-id-query appid_journal.py 's/for ident in app_ids:/for ident in app_ids[:1]:/'
    mutant window-ignored jo.py 's/if field(row, "__CURSOR") in cursors:/if True:/'
}

g=$ROOT/e2e/guest.sh
line() { grep -n -m1 -E -e "$1" "$g" | cut -d: -f1; }
j=$(line 'phase_runs journal-ops')
a=$(line 'phase_runs appid')
u=$(line 'phase_runs upgrade')
[ -n "$j" ] && [ -n "$a" ] && [ -n "$u" ] || bad "guest.sh lacks a step"
[ "${j:-0}" -lt "${a:-0}" ] && [ "${a:-0}" -lt "${u:-0}" ] || bad "the appid step is not between journal-ops and the upgrade ($j $a $u)"
grep -q 'appid-run.sh' "$g" || bad "guest.sh does not run appid-run.sh"
n=0
while IFS= read -r id; do
    n=$((n + 1))
    grep -q -- "$id" "$ROOT/e2e/appid-run.sh" || bad "appid-run.sh does not report $id"
done < <(grep -E '^appid-' "$ROOT/e2e/cases.list")
[ "$n" -ge 9 ] || bad "cases.list has $n appid cases, expected 9"
# every kind of caller and operation of the plan is one appid-user.sh can start, and every phase has a call
for phase in main cap end; do
    awk -v p="$phase" '$1 !~ /^#/ && $2 == p {found = 1} END {exit !found}' "$ROOT/e2e/appid-ledger.txt" || bad "the plan has no call in the phase $phase"
done
while read -r label _phase kind _cg op _rest; do
    case $label in "" | "#"*) continue ;; esac
    grep -qE "^ +$kind\\)" "$ROOT/e2e/appid-user.sh" || bad "appid-user.sh does not start a caller of kind $kind ($label)"
    grep -qE "^ +$op\\)" "$ROOT/e2e/appid-user.sh" || bad "appid-user.sh does not make the operation $op ($label)"
done < "$ROOT/e2e/appid-ledger.txt"
[ "$(grep -c 'ai cap-check' "$ROOT/e2e/appid-run.sh")" -ge 2 ] || bad "appid-run.sh does not check the place of the cap callers before and after their calls"
# shellcheck disable=SC2016 # the text searched for holds a literal $PWD
grep -q -- '-v "$PWD/crates/custodiod/src/app_id_source.rs:/e2e-src/app_id_source.rs:ro"' "$ROOT/e2e/run.sh" || bad "run.sh does not mount the source of the reader (appid-run.sh reads MAX_CHILDREN from it)"
# the hostile names are on no command line: the user script passes labels only
grep -q 'XDG_SESSION_CLASS=user' "$ROOT/e2e/appid-run.sh" || bad "appid-run.sh does not open alice's sessions with class user"
exit "$fail"
