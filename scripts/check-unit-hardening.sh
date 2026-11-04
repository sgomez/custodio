#!/usr/bin/env bash
# The gate of `just unit-hardening`: custodio.service keeps the three settings the pidfd cross-check
# relies on (docs/findings/F30.md, M1.2), each exactly once, and the security-score threshold in the justfile
# is still 10. Arguments: UNIT (default data/custodio.service) and JUSTFILE (default justfile).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
unit=${1:-$ROOT/data/custodio.service}
justfile=${2:-$ROOT/justfile}
fail=0

for want in ProtectProc=invisible ProcSubset=pid PrivateUsers=yes; do
    key=${want%%=*}
    total=$(grep -c "^[[:space:]]*${key}[[:space:]]*=" "$unit" || true)
    # Strip whitespace around '=' and at the line ends before the exact comparison.
    exact=$(sed 's/^[[:space:]]*\([A-Za-z]*\)[[:space:]]*=[[:space:]]*/\1=/; s/[[:space:]]*$//' "$unit" | grep -cx "$want" || true)
    if [ "$total" != 1 ] || [ "$exact" != 1 ]; then
        echo "unit-hardening: $unit must have '$want' exactly once and no other $key= line" >&2
        fail=1
    fi
done

threshold=$(sed -n 's/^security-score threshold="\([^"]*\)":.*/\1/p' "$justfile")
if [ "$threshold" != 10 ]; then
    echo "unit-hardening: the security-score threshold in $justfile is '${threshold:-unreadable}', not 10" >&2
    fail=1
fi
exit "$fail"
