# shellcheck shell=bash
# Sourced by tpmslots-run.sh and its host test (F143): the cases of the step and how the mode without a TPM reports them.
# shellcheck source=e2e/report.sh
source "$(dirname "${BASH_SOURCE[0]}")/report.sh"
TPMSLOTS_CASES="tpm-slots-sign-rsa tpm-slots-sign-ec tpm-slots-import tpm-slots-no-leak"
# tpmslots_skip_all MODE: every case skipped, with a reason that names the mode
tpmslots_skip_all() {
    local c
    for c in $TPMSLOTS_CASES; do case_skip "$c" "E2E_TPM=$1: there is no TPM, so no object slots to use up"; done
}
