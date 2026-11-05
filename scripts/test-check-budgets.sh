#!/usr/bin/env bash
# scripts/check-budgets.sh against made-up budgets and times: under, over, the default `*`, a name with no budget, and bad input.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-check-budgets: $*" >&2; fail=1; }
check() { "$ROOT/scripts/check-budgets.sh" "$tmp/b" "$@" > "$tmp/out" 2>&1; }

printf 'suite\tname\tseconds\treason\ne2e\tdebian13\t300\tmeasured 250\ne2e\tubuntu2404\t20\trefusal only\nscript\t*\t60\tdefault\nscript\tscripts/test-slow.sh\t200\tbuilds packages\n' > "$tmp/b"
printf 'target\tmode\tseconds\tresult\ndebian13\tswtpm\t250\tpassed\ndebian13\tnone\t300\tpassed\nubuntu2404\tswtpm\t5\tpassed\n' > "$tmp/e2e"
printf '50 0 scripts/test-a.sh\n190 0 scripts/test-slow.sh\n' > "$tmp/script"

check e2e "$tmp/e2e" || bad "within the budgets: failed: $(cat "$tmp/out")"
check script "$tmp/script" || bad "the default and a named budget: failed: $(cat "$tmp/out")"

printf 'target\tmode\tseconds\tresult\ndebian13\tnone\t301\tpassed\n' > "$tmp/e2e"
if check e2e "$tmp/e2e"; then bad "301s over a 300s budget passed"; fi
grep -q 'e2e debian13 (none): 301s, budget 300s' "$tmp/out" || bad "the over-budget run is not named: $(cat "$tmp/out")"

printf '61 0 scripts/test-b.sh\n' > "$tmp/script"
if check script "$tmp/script"; then bad "61s over the 60s default passed"; fi
grep -q 'script scripts/test-b.sh: 61s, budget 60s' "$tmp/out" || bad "the over-default script is not named: $(cat "$tmp/out")"

printf 'target\tmode\tseconds\tresult\nfedora44\tswtpm\t10\tpassed\n' > "$tmp/e2e"
if check e2e "$tmp/e2e"; then bad "a target with no budget and no default passed"; fi
grep -q 'e2e fedora44: no budget' "$tmp/out" || bad "the missing budget is not named: $(cat "$tmp/out")"

for args in "e2e" "e2e $tmp/none" "bogus $tmp/script"; do
    # shellcheck disable=SC2086 # the words are the arguments
    if check $args; then bad "bad input '$args' passed"; fi
done
printf 'target\tmode\tseconds\tresult\ndebian13\tswtpm\t1\tpassed\n' > "$tmp/e2e"
cp "$tmp/b" "$tmp/b.good"
for line in 'e2e\tarch\tlots\tx' 'e2e\tarch\t10' 'e2e\tarch\t10\t' 'e2e\tdebian13\t900\tagain'; do
    { cat "$tmp/b.good"; printf '%b\n' "$line"; } > "$tmp/b"
    if check e2e "$tmp/e2e"; then bad "the budget line '$line' was accepted"; fi
done

exit "$fail"
