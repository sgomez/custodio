# shellcheck shell=bash
# Sourced by tpmfail-run.sh and its host test (F139): the cases of the step and how the modes without the swtpm TPM report them.
# shellcheck source=e2e/report.sh
source "$(dirname "${BASH_SOURCE[0]}")/report.sh"
TPMFAIL_CASES="tpmfail-device-unopenable tpmfail-tpm-error tpmfail-credentials-down-tpm-lacking tpmfail-credentials-down-host"
# tpmfail_skip_all MODE: every case skipped, with a reason that names the mode
tpmfail_skip_all() {
    local c
    for c in $TPMFAIL_CASES; do case_skip "$c" "E2E_TPM=$1: the cases replace the TPM of the run with their own failing ones, and restore the TPM of swtpm; they run in swtpm"; done
}
