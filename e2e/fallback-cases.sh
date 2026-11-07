# shellcheck shell=bash
# Sourced by fallback-run.sh and its host test (F138): the cases of the step and how each mode reports them.
# shellcheck source=e2e/report.sh
source "$(dirname "${BASH_SOURCE[0]}")/report.sh"
FALLBACK_HOST_CASES="fallback-host-import-rsa fallback-host-import-ec fallback-host-says-weaker-why fallback-host-cli-list"
FALLBACK_TPMBOUND_CASES="fallback-tpmbound-import fallback-tpmbound-cli-list"
# fallback_skip MODE: the tpmbound cases are skipped in every mode (SPEC_DEVIATIONS.md, F134); the host cases too unless MODE is none
fallback_skip() {
    local c
    for c in $FALLBACK_TPMBOUND_CASES; do case_skip "$c" "E2E_TPM=$1: the kind encrypted-tpm cannot be made in the container (SPEC_DEVIATIONS.md F134); storage_kind and kinds_suite cover it"; done
    [ "$1" = none ] && return 0
    for c in $FALLBACK_HOST_CASES; do case_skip "$c" "E2E_TPM=$1: the key gets the kind tpm, not encrypted-host"; done
}
