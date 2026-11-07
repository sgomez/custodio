# shellcheck shell=bash
# Sourced by pcr-run.sh and its host test (F137): the cases of the step and how the mode without a TPM reports them.
# shellcheck source=e2e/report.sh
source "$(dirname "${BASH_SOURCE[0]}")/report.sh"
PCR_CASES="pcr-extended-signs pcr-restarted-signs pcr-signs-every-key"
# pcr_skip_all MODE: every case skipped, with a reason that names the mode
pcr_skip_all() {
    local c
    for c in $PCR_CASES; do case_skip "$c" "E2E_TPM=$1: there is no TPM, so no PCR to extend and no swtpm to restart"; done
}
