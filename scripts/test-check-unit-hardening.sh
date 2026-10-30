#!/usr/bin/env bash
# Tests of scripts/check-unit-hardening.sh on fixture copies of data/custodio.service and the justfile.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-unit-hardening.sh
UNIT=$ROOT/data/custodio.service
JUST=$ROOT/justfile
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
fail=0
bad() { echo "test-check-unit-hardening: $*" >&2; fail=1; }

"$GATE" "$UNIT" "$JUST" >/dev/null 2>&1 || bad "the real files fail"
"$GATE" >/dev/null 2>&1 || bad "the defaults fail"

expect_fail() { # LABEL UNIT JUSTFILE
    if "$GATE" "$2" "$3" >/dev/null 2>&1; then bad "$1: the gate passed"; fi
}
unit_case() { # LABEL SED-EXPRESSION
    sed "$2" "$UNIT" > "$dir/u.service"
    expect_fail "$1" "$dir/u.service" "$JUST"
}
unit_case "spaced ProtectProc = default" 's/^ProtectProc=.*/ProtectProc = default/'
unit_case "ProtectProc=default" 's/^ProtectProc=.*/ProtectProc=default/'
unit_case "ProcSubset=all" 's/^ProcSubset=.*/ProcSubset=all/'
unit_case "PrivateUsers=no" 's/^PrivateUsers=.*/PrivateUsers=no/'
for key in ProtectProc ProcSubset PrivateUsers; do
    unit_case "$key missing" "/^$key=/d"
done
for dup in ProtectProc=default ProcSubset=all PrivateUsers=no ProtectProc=invisible \
    "ProtectProc = default" "ProcSubset = all" "PrivateUsers = no" "ProtectProc = invisible"; do
    sed "/^\[Install\]/i $dup" "$UNIT" > "$dir/u.service"
    grep -qxF "$dup" "$dir/u.service" || bad "fixture for '$dup' was not written"
    expect_fail "duplicate $dup" "$dir/u.service" "$JUST"
done

sed 's/^security-score threshold="10":/security-score threshold="11":/' "$JUST" > "$dir/justfile"
expect_fail "threshold 11" "$UNIT" "$dir/justfile"
sed '/^security-score threshold=/d' "$JUST" > "$dir/justfile"
expect_fail "threshold unreadable" "$UNIT" "$dir/justfile"
expect_fail "missing unit file" "$dir/none.service" "$JUST"
exit "$fail"
