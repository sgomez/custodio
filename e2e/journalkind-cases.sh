# shellcheck shell=bash
# Sourced by journalkind-run.sh and its host test (F144): the cases of the step.
# shellcheck source=e2e/report.sh
source "$(dirname "${BASH_SOURCE[0]}")/report.sh"
# shellcheck disable=SC2034 # read by the host test that sources this file
JOURNALKIND_CASES="journal-kind-import journal-kind-purge journal-kind-owner journal-kind-key-lost journal-kind-temporarily-unavailable"
