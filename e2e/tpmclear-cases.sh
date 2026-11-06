# shellcheck shell=bash
# Sourced by tpmclear-run.sh and its host test (F140): the cases of the step and how mode none, which has no TPM to clear, reports them.
# shellcheck source=e2e/report.sh
source "$(dirname "${BASH_SOURCE[0]}")/report.sh"
TPMCLEAR_CASES="tpm-clear-sign-fails tpm-clear-keys-listed tpm-clear-delete"
# tpmclear_skip_all MODE: every case skipped, with a reason that names the mode
tpmclear_skip_all() {
    local c
    for c in $TPMCLEAR_CASES; do case_skip "$c" "E2E_TPM=$1: there is no TPM to clear, and the keys are encrypted-host, which a TPM clear does not touch"; done
}
