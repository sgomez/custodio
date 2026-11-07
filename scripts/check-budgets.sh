#!/usr/bin/env bash
# The time budgets of budgets.tsv against measured times. A person sets the budgets (just milestone approve budgets).
# Usage: check-budgets.sh BUDGETS SUITE TIMES
#   e2e     TIMES is target/e2e/timings.tsv (target, mode, seconds, result); the budget is per target, for each mode
#   script  TIMES is target/script-tests/results (seconds, exit, command); the budget is per command
# A name with no budget takes the suite's `*` line; with neither it fails. Exit 1 over budget or no budget, 2 bad input.
set -euo pipefail
[ $# -eq 3 ] || { echo "usage: check-budgets.sh BUDGETS SUITE TIMES" >&2; exit 2; }
budgets=$1 suite=$2 times=$3
[ -f "$budgets" ] || { echo "check-budgets: no $budgets" >&2; exit 2; }
[ -f "$times" ] || { echo "check-budgets: no $times" >&2; exit 2; }
# every line after the header: suite, name, whole seconds, a reason; one line per suite and name
bad_lines=$(awk -F'\t' 'NR > 1 && (NF != 4 || $3 !~ /^[0-9]+$/ || $4 == "" || seen[$1 FS $2]++) { print NR ": " $0 }' "$budgets")
[ -z "$bad_lines" ] || { echo "check-budgets: bad lines in $budgets (suite, name, seconds, reason; each name once):" >&2; echo "$bad_lines" >&2; exit 2; }
case $suite in
e2e) measured=$(awk -F'\t' 'NR > 1 { print $1 "\t" $1 " (" $2 ")\t" $3 }' "$times") ;;
script) measured=$(awk '{ s = $1; $1 = ""; $2 = ""; sub(/^  /, ""); print $0 "\t" $0 "\t" s }' "$times") ;;
*) echo "check-budgets: unknown suite '$suite' (e2e, script)" >&2; exit 2 ;;
esac
budget_of() { awk -F'\t' -v s="$suite" -v n="$1" '$1 == s && $2 == n { print $3; exit }' "$budgets"; }
rc=0
while IFS=$'\t' read -r name label secs; do
    [ -n "$name" ] || continue
    max=$(budget_of "$name")
    [ -n "$max" ] || max=$(budget_of '*')
    if [ -z "$max" ]; then echo "budget: $suite $name: no budget in $budgets" >&2; rc=1; continue; fi
    [[ $secs =~ ^[0-9]+$ ]] || { echo "check-budgets: '$secs' for $suite $name in $times is not a number of seconds" >&2; exit 2; }
    if (( secs > max )); then echo "budget: $suite $label: ${secs}s, budget ${max}s" >&2; rc=1; fi
done <<< "$measured"
exit "$rc"
