#!/usr/bin/env bash
# F131: the check that the installed unit has no test drop-in must find one. Plants drop-ins of the kinds it looks for (any file in a drop-in
# directory, the TPM drop-in itself) and expects tpm_unit_problems to say so; the clean unit must give no output first. Run in the guest before the TPM setup.
set -euo pipefail
# shellcheck source=e2e/tpm-lib.sh
source /e2e/tpm-lib.sh
fail() { echo "e2e: FAIL: tpm self-test: $*" >&2; exit 1; }
[ -z "$TPM_SETUP_DONE" ] || fail "run before the TPM setup"
p=$(tpm_unit_problems)
[ -z "$p" ] || fail "the clean installed unit was flagged: $p"
planted=''
cleanup() { rm -f "${planted:-/nonexistent}"; rmdir "$TPM_DROPIN_DIR" 2> /dev/null || true; systemctl daemon-reload; }
trap cleanup EXIT
for f in "$TPM_DROPIN_DIR/other.conf" "$TPM_DROPIN"; do
    mkdir -p "$TPM_DROPIN_DIR"
    printf '[Service]\nEnvironment=X=1\n' > "$f"
    planted=$f
    systemctl daemon-reload
    p=$(tpm_unit_problems)
    [ -n "$p" ] || fail "a drop-in at $f was not found"
    grep -q 'DropInPaths' <<< "$p" || fail "the planted drop-in at $f was found, but not through DropInPaths: $p"
    rm -f "$f"
    systemctl daemon-reload
done
planted=''
p=$(tpm_unit_problems)
[ -z "$p" ] || fail "the unit is flagged after the planted drop-ins were removed: $p"
echo "e2e: tpm self-test passed"
