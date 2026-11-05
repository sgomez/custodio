# shellcheck shell=bash
# Sourced by tpmkind-run.sh and its host test (F133): the cases of the step and how a mode that is not swtpm reports them.
# shellcheck source=e2e/report.sh
source "$(dirname "${BASH_SOURCE[0]}")/report.sh"
TPMKIND_CASES="tpm-kind-import-rsa tpm-kind-import-ec tpm-kind-api-list tpm-kind-cli-list tpm-kind-journal"
# tpmkind_skip_all MODE: every case skipped, with a reason that names the mode
tpmkind_skip_all() {
    local c
    for c in $TPMKIND_CASES; do case_skip "$c" "E2E_TPM=$1: the key gets the kind of that mode, not tpm"; done
}
