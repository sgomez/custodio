#!/usr/bin/env bash
# The gate of `just unit-hardening`: custodio.service keeps the three settings the pidfd cross-check
# relies on (docs/findings/F30.md, M1.2), PrivateDevices=yes and the TPM access F109 decided
# (DeviceAllow=/dev/tpmrm0 rw, BindPaths=-/dev/tpmrm0, SupplementaryGroups=tss), each exactly once, and the
# security-score threshold in the justfile is still 10. It also refuses any line that opens the raw TPM node
# (named, wildcarded, as char-misc / 10:224 or by binding /dev) and any TCTI override or a way to hide one
# (EnvironmentFile=, PassEnvironment=). The credential service (F110) needs no directive. Arguments: UNIT (default data/custodio.service) and JUSTFILE (default justfile).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
unit=${1:-$ROOT/data/custodio.service}
justfile=${2:-$ROOT/justfile}
fail=0

for want in ProtectProc=invisible ProcSubset=pid PrivateUsers=yes PrivateDevices=yes \
    DeviceAllow=/dev/tpmrm0\ rw BindPaths=-/dev/tpmrm0 SupplementaryGroups=tss; do
    key=${want%%=*}
    total=$(grep -c "^[[:space:]]*${key}[[:space:]]*=" "$unit" || true)
    # Strip whitespace around '=' and at the line ends before the exact comparison.
    exact=$(sed 's/^[[:space:]]*\([A-Za-z]*\)[[:space:]]*=[[:space:]]*/\1=/; s/[[:space:]]*$//' "$unit" | grep -cx "$want" || true)
    if [ "$total" != 1 ] || [ "$exact" != 1 ]; then
        echo "unit-hardening: $unit must have '$want' exactly once and no other $key= line" >&2
        fail=1
    fi
done

# Directive lines with whitespace around '=' and at the ends stripped.
norm=$(sed 's/^[[:space:]]*\([A-Za-z0-9]*\)[[:space:]]*=[[:space:]]*/\1=/; s/[[:space:]]*$//' "$unit")

# Nothing may open the raw TPM node: tpm0 or a wildcard over it, the misc class or 10:224 it lives in, or all of /dev.
raw=$(printf '%s\n' "$norm" | grep -E '^(DeviceAllow|BindPaths|BindReadOnlyPaths)=' \
    | grep -E 'tpm[0-9*?[]|tpm\*|char-tpm|char-misc|10:224|char-\*|=(-)?/dev/?([[:space:]]|$)|[[:space:]](-)?/dev/?([[:space:]]|:|$)|/dev/\*|/dev/char/?([[:space:]]|$)' || true)
if [ -n "$raw" ]; then
    echo "unit-hardening: $unit allows the raw TPM device: $raw" >&2
    fail=1
fi

# No TCTI override, and no file or pass-through an override could come from.
tcti=$(printf '%s\n' "$norm" | grep -iE '^(Environment|EnvironmentFile|PassEnvironment)=.*TCTI' || true)
hidden=$(printf '%s\n' "$norm" | grep -E '^(EnvironmentFile|PassEnvironment)=' || true)
if [ -n "$tcti$hidden" ]; then
    echo "unit-hardening: $unit must have no TCTI override, EnvironmentFile= or PassEnvironment=: $tcti$hidden" >&2
    fail=1
fi

threshold=$(sed -n 's/^security-score threshold="\([^"]*\)":.*/\1/p' "$justfile")
if [ "$threshold" != 10 ]; then
    echo "unit-hardening: the security-score threshold in $justfile is '${threshold:-unreadable}', not 10" >&2
    fail=1
fi
exit "$fail"
