#!/usr/bin/env bash
# F45: the skip list format and its enforcement (e2e/check-cases.sh), with no container engine. Where each behaviour is checked:
#   here            the format of skip.list; the case accounting (run, skipped, missing, unknown, duplicated); whole-name matching;
#                   unused entries; that the committed lists are well formed and the suite reports through one function
#   test-e2e-host.sh  that the host script runs the accounting on the guest's real output and fails the run on it (stub engine)
#   just e2e        the real distribution (the required real run; nothing here replaces it)
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHK="$ROOT/e2e/check-cases.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-skips: $*" >&2; fail=1; }

printf '%s\n' '# known' alpha beta 'gamma.1' 'alpha-2' > "$tmp/cases"
report() { # report FILE "run alpha" "skipped beta" ...: a guest output with noise around the lines
    local f=$1; shift
    { echo "some output"; for l in "$@"; do echo "E2E-CASE $l"; done; echo "e2e: all checks passed"; } > "$f"
}
all_run=("run alpha" "run beta" "run gamma.1" "run alpha-2")
printf '%s\n' '# comment' '' 'beta: no polkit agent here' > "$tmp/skip"
: > "$tmp/empty"

ok() { # ok NAME SKIPLIST REPORT-LINES...
    local n=$1 s=$2; shift 2
    report "$tmp/out" "$@"
    "$CHK" check "$tmp/cases" "$s" "$tmp/out" > "$tmp/stdout" 2> "$tmp/stderr" || { bad "$n: failed: $(cat "$tmp/stderr")"; return; }
}
nok() { # nok NAME SKIPLIST EXPECTED-MESSAGE REPORT-LINES...
    local n=$1 s=$2 msg=$3; shift 3
    report "$tmp/out" "$@"
    if "$CHK" check "$tmp/cases" "$s" "$tmp/out" > "$tmp/stdout" 2> "$tmp/stderr"; then bad "$n: passed"; return; fi
    grep -q -- "$msg" "$tmp/stderr" || bad "$n: the message lacks '$msg': $(cat "$tmp/stderr")"
}

# (a)-(e) enforcement
ok none-skipped "$tmp/empty" "${all_run[@]}"
ok skipped-on-list "$tmp/skip" "run alpha" "skipped beta" "run gamma.1" "run alpha-2"
nok skipped-not-on-list "$tmp/empty" "'beta' was skipped and is not on the skip list" "run alpha" "skipped beta" "run gamma.1" "run alpha-2"
printf 'alpha: reason\n' > "$tmp/other" # the list of another target
nok skipped-on-other-list "$tmp/other" "'beta' was skipped" "run alpha" "skipped beta" "run gamma.1" "run alpha-2"
printf 'alpha: reason\n' > "$tmp/prefix"
nok prefix-is-not-a-match "$tmp/prefix" "'alpha-2' was skipped" "run alpha" "run beta" "run gamma.1" "skipped alpha-2"
printf 'alpha-2: reason\n' > "$tmp/prefix2"
nok longer-name-is-not-a-match "$tmp/prefix2" "'alpha' was skipped" "skipped alpha" "run beta" "run gamma.1" "run alpha-2"
# case accounting
nok missing "$tmp/empty" "'beta' was not reported" "run alpha" "run gamma.1" "run alpha-2"
nok unknown "$tmp/empty" "unknown case 'delta'" "${all_run[@]}" "run delta"
nok duplicated "$tmp/empty" "'beta' reported twice" "${all_run[@]}" "run beta"
nok run-and-skipped "$tmp/skip" "'beta' reported twice" "${all_run[@]}" "skipped beta"
# a skip line that is not in the E2E-CASE form does not count as a report
printf 'alpha\nbeta\n' > "$tmp/two"
printf 'skipped: beta (no agent)\nE2E-CASE run alpha\nE2E-CASE  run beta\n' > "$tmp/out"
if "$CHK" check "$tmp/two" "$tmp/empty" "$tmp/out" > /dev/null 2>&1; then bad "malformed report lines were accepted"; fi
# unused entry: reported on stderr, exit 0
ok unused-entry "$tmp/skip" "${all_run[@]}"
grep -q "skip list entry 'beta' matches no skipped case" "$tmp/stderr" || bad "unused entry not reported on stderr"

# F63: a subset (`just e2e-cases`): check gets the selected ids as a fifth argument, a file
sub_ok() { # sub_ok NAME SKIPLIST "SELECTED IDS" REPORT-LINES...
    local n=$1 s=$2 sel=$3; shift 3
    report "$tmp/out" "$@"; tr ' ' '\n' <<< "$sel" > "$tmp/sel"
    "$CHK" check "$tmp/cases" "$s" "$tmp/out" "$tmp/sel" > "$tmp/stdout" 2> "$tmp/stderr" || bad "$n: failed: $(cat "$tmp/stderr")"
}
sub_nok() { # sub_nok NAME SKIPLIST "SELECTED IDS" EXPECTED-MESSAGE REPORT-LINES...
    local n=$1 s=$2 sel=$3 msg=$4; shift 4
    report "$tmp/out" "$@"; tr ' ' '\n' <<< "$sel" > "$tmp/sel"
    if "$CHK" check "$tmp/cases" "$s" "$tmp/out" "$tmp/sel" > "$tmp/stdout" 2> "$tmp/stderr"; then bad "$n: passed"; return; fi
    grep -q -- "$msg" "$tmp/stderr" || bad "$n: the message lacks '$msg': $(cat "$tmp/stderr")"
}
sub_ok subset-exact "$tmp/empty" "alpha gamma.1" "run alpha" "run gamma.1"
grep -q '2 cases accounted for' "$tmp/stdout" || bad "subset-exact: the count is not 2: $(cat "$tmp/stdout")"
sub_ok subset-single "$tmp/empty" "alpha-2" "run alpha-2"
sub_nok subset-omitted "$tmp/empty" "alpha gamma.1" "'gamma.1' was not reported" "run alpha"
sub_nok subset-twice "$tmp/empty" "alpha gamma.1" "'alpha' reported twice" "run alpha" "run alpha" "run gamma.1"
sub_nok subset-unselected-reported "$tmp/empty" "alpha gamma.1" "'beta' was reported and is not selected" "run alpha" "run beta" "run gamma.1"
sub_nok subset-unselected-skipped "$tmp/skip" "alpha gamma.1" "'beta' was reported and is not selected" "run alpha" "skipped beta" "run gamma.1"
sub_nok subset-unknown "$tmp/empty" "alpha" "unknown case 'delta'" "run alpha" "run delta"
sub_nok subset-skipped-unlisted "$tmp/empty" "alpha beta" "'beta' was skipped and is not on the skip list" "run alpha" "skipped beta"
sub_ok subset-skipped-listed "$tmp/skip" "alpha beta" "run alpha" "skipped beta"
sub_ok subset-unused-entry-quiet "$tmp/skip" "alpha" "run alpha"
grep -q "matches no skipped case" "$tmp/stderr" && bad "an entry of an unselected case was reported as unused"
# a selected id that is no case, an empty selection and a missing file are refused
printf 'alpha\ndelta\n' > "$tmp/sel"; report "$tmp/out" "run alpha"
if "$CHK" check "$tmp/cases" "$tmp/empty" "$tmp/out" "$tmp/sel" 2> "$tmp/stderr"; then bad "an unknown selected id was accepted"; fi
grep -q "selected case 'delta'" "$tmp/stderr" || bad "an unknown selected id is not named: $(cat "$tmp/stderr")"
: > "$tmp/sel"
if "$CHK" check "$tmp/cases" "$tmp/empty" "$tmp/out" "$tmp/sel" 2> /dev/null; then bad "an empty selection was accepted"; fi
if "$CHK" check "$tmp/cases" "$tmp/empty" "$tmp/out" "$tmp/nosel" 2> /dev/null; then bad "a missing selection file was accepted"; fi

# the format of the list
lint_ok() { printf '%b' "$2" > "$tmp/l"; "$CHK" lint "$tmp/l" 2> "$tmp/stderr" || bad "$1: rejected: $(cat "$tmp/stderr")"; }
lint_bad() { printf '%b' "$2" > "$tmp/l"; if "$CHK" lint "$tmp/l" 2> "$tmp/stderr"; then bad "$1: accepted"; elif ! grep -q -- "$3" "$tmp/stderr"; then bad "$1: message '$(cat "$tmp/stderr")'"; fi; }
lint_ok comments-blank '# c\n\nalpha: because\nbeta:   spaced reason  \n'
lint_ok no-trailing-newline 'alpha: because'
lint_ok empty-file ''
lint_bad no-reason 'alpha:\n' "expected 'case: reason'"
lint_bad blank-reason 'alpha:   \n' "expected 'case: reason'"
lint_bad no-colon 'alpha\n' "expected 'case: reason'"
lint_bad no-case ': a reason\n' "expected 'case: reason'"
lint_bad duplicate 'alpha: one\nalpha: two\n' "listed twice"
lint_bad space-in-case 'al pha: r\n' "expected 'case: reason'"
if "$CHK" lint "$tmp/missing" 2> /dev/null; then bad "a missing list was accepted"; fi
if "$CHK" check "$tmp/cases" "$tmp/missing" "$tmp/out" 2> /dev/null; then bad "check accepted a missing list"; fi

# the committed lists: every target has a well-formed one; cases.list has no duplicates
for d in "$ROOT"/e2e/targets/*/; do "$CHK" lint "$d/skip.list" || bad "$d: skip.list rejected"; done
[ -z "$(grep -v '^[[:space:]]*\(#\|$\)' "$ROOT/e2e/cases.list" | sort | uniq -d)" ] || bad "e2e/cases.list has a duplicate"
# every case a script reports is in cases.list, with the loop variables expanded by hand: the ids without a `$` must be listed
while read -r id; do
    grep -qx -- "$id" "$ROOT/e2e/cases.list" || bad "case '$id' of a script is not in e2e/cases.list"
done < <(grep -ho 'case_run "[^"$]*"' "$ROOT"/e2e/*.sh | sed 's/case_run "//;s/"$//')

# Secondary heuristic: cases are reported by case_run/case_skip only, and no suite script prints the report line by hand.
if grep -n 'echo.*E2E-CASE' "$ROOT"/e2e/*.sh | grep -v 'e2e/report.sh' | grep -q .; then bad "a script other than report.sh prints an E2E-CASE line"; fi

exit "$fail"
