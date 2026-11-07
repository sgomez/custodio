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

# F124: PrivateDevices and the TPM access of docs/findings/F109.md, exactly.
unit_case "PrivateDevices missing" "/^PrivateDevices=/d"
unit_case "PrivateDevices=no" 's/^PrivateDevices=.*/PrivateDevices=no/'
unit_case "DeviceAllow missing" "/^DeviceAllow=/d"
unit_case "BindPaths missing" "/^BindPaths=/d"
unit_case "SupplementaryGroups missing" "/^SupplementaryGroups=/d"
unit_case "DeviceAllow r" 's|^DeviceAllow=.*|DeviceAllow=/dev/tpmrm0 r|'
unit_case "BindPaths without dash" 's|^BindPaths=.*|BindPaths=/dev/tpmrm0|'
unit_case "SupplementaryGroups=wheel" 's/^SupplementaryGroups=.*/SupplementaryGroups=wheel/'
add_case() { # LABEL LINE (inserted before [Install])
    sed "/^\[Install\]/i $2" "$UNIT" > "$dir/u.service"
    grep -qxF -- "$2" "$dir/u.service" || bad "fixture for '$1' was not written"
    expect_fail "$1" "$dir/u.service" "$JUST"
}
for dup in "PrivateDevices=yes" "PrivateDevices = yes" "PrivateDevices=no" \
    "DeviceAllow=/dev/tpmrm0 rw" "DeviceAllow = /dev/tpmrm0 rw" "BindPaths=-/dev/tpmrm0" "BindPaths = -/dev/tpmrm0" \
    "SupplementaryGroups=tss" "SupplementaryGroups = tss"; do
    add_case "duplicate $dup" "$dup"
done
# The raw node is never named, nor covered: beside the good lines and in place of them.
for raw in "DeviceAllow=/dev/tpm0 rw" "DeviceAllow=/dev/tpm* rw" "DeviceAllow=char-tpm rw" "DeviceAllow=char-misc rw" \
    "DeviceAllow=/dev/char/10:224 rw" "BindPaths=-/dev/tpm0" "BindPaths=/dev" "BindPaths=-/dev/" \
    "BindReadOnlyPaths=/dev/tpm0" "BindReadOnlyPaths=/dev" "BindPaths = -/dev/tpm0"; do
    add_case "beside: $raw" "$raw"
    key=${raw%%=*}; key=${key% }
    sed "s|^$key=.*|$raw|" "$UNIT" > "$dir/u.service"
    if grep -q "^$key=" "$UNIT"; then expect_fail "instead: $raw" "$dir/u.service" "$JUST"; fi
done
# No TCTI override, the one the daemon reads included; no file or pass-through that could hide one.
for env in "Environment=TSS2_TCTI=device:/dev/tpm0" "Environment=TPM2TOOLS_TCTI=device:/dev/tpm0" \
    'Environment="TSS2_TCTI=device:/dev/tpm0"' "Environment=CUSTODIOD_TEST_SWTPM_TCTI=swtpm:path=/run/x.sock" \
    'Environment="CUSTODIOD_TEST_SWTPM_TCTI=swtpm:path=/run/x.sock"' "Environment = TSS2_TCTI=mssim" \
    "Environment=FOO=1 TSS2_TCTI=mssim" "EnvironmentFile=/etc/custodio/env" "EnvironmentFile=-/etc/custodio/env" \
    "PassEnvironment=TSS2_TCTI" "PassEnvironment=FOO"; do
    add_case "$env" "$env"
done

sed 's/^security-score threshold="10":/security-score threshold="11":/' "$JUST" > "$dir/justfile"
expect_fail "threshold 11" "$UNIT" "$dir/justfile"
sed '/^security-score threshold=/d' "$JUST" > "$dir/justfile"
expect_fail "threshold unreadable" "$UNIT" "$dir/justfile"
expect_fail "missing unit file" "$dir/none.service" "$JUST"
exit "$fail"
