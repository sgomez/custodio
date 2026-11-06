# shellcheck shell=bash
# Sourced by tpmdup-run.sh and its host test (F136): the cases of the step and how the mode without a TPM key reports them.
# shellcheck source=e2e/report.sh
source "$(dirname "${BASH_SOURCE[0]}")/report.sh"
TPMDUP_CASES="tpm-dup-authpolicy-empty tpm-dup-duplicate-fails tpm-dup-other-tpm"
# tpmdup_skip_all MODE: every case skipped, with a reason that names the mode
tpmdup_skip_all() {
    local c
    for c in $TPMDUP_CASES; do case_skip "$c" "E2E_TPM=$1: no key is of kind tpm, so there is no TPM blob to duplicate"; done
}
