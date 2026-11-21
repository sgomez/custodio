#!/usr/bin/env bash
# Tests of scripts/check-unit-hardening.sh on fixture copies of data/custodio.service.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-unit-hardening.sh
UNIT=$ROOT/data/custodio.service
JUST=$ROOT/justfile
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
fail=0
bad() { echo "test-check-unit-hardening: $*" >&2; fail=1; }

expect_fail() { # LABEL UNIT
    if "$GATE" "$2" >/dev/null 2>&1; then bad "$1: the gate passed"; fi
}
unit_case() { # LABEL SED-EXPRESSION
    sed "$2" "$UNIT" > "$dir/u.service"
    expect_fail "$1" "$dir/u.service"
}
unit_case "ProtectProc=default" 's/^ProtectProc=.*/ProtectProc=default/'
unit_case "MemorySwapMax=0 removed" '/^MemorySwapMax=/d'
unit_case "LimitCORE=infinity (the line replaced)" 's/^LimitCORE=.*/LimitCORE=infinity/'
add_case() { # LABEL LINE (inserted before [Install])
    sed "/^\[Install\]/i $2" "$UNIT" > "$dir/u.service"
    grep -qxF -- "$2" "$dir/u.service" || bad "fixture for '$1' was not written"
    expect_fail "$1" "$dir/u.service"
}
add_case "duplicate ProtectProc=invisible" "ProtectProc=invisible"
# The raw node is never named; no TCTI override, no file or pass-through that could hide one.
add_case "raw node" "DeviceAllow=/dev/tpm0 rw"
add_case "TCTI override" "Environment=TSS2_TCTI=device:/dev/tpm0"
add_case "pass-through" "PassEnvironment=FOO"

# The exposure ceiling (F173, `just security-ceiling`): the shipped unit is at or below 0.7, `PrivateUsers=no` (0.8) is above.
just --justfile "$JUST" security-ceiling "$UNIT" >/dev/null 2>&1 || bad "the shipped unit is above the exposure ceiling"
sed 's/^PrivateUsers=.*/PrivateUsers=no/' "$UNIT" > "$dir/u.service"
if just --justfile "$JUST" security-ceiling "$dir/u.service" >/dev/null 2>&1; then bad "PrivateUsers=no (0.8) passed the ceiling"; fi
exit "$fail"
