#!/usr/bin/env bash
# Fails unless harness/Containerfile and every job of the workflows that builds or tests the workspace install the TPM
# packages (F104), each install preceded by a comment that mentions the TPM. Usage: check-tpm-install-sync.sh [ROOT]
# ROOT holds harness/Containerfile and .github/workflows/ (default: this repository). The logic is in install-sync-lib.sh.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=${1:-$(dirname "$HERE")}
NAME=check-tpm-install-sync
KEYWORD=tpm
# libtss2-dev is what tss-esapi builds against; the others give the software TPM and its tools.
PACKAGES=(swtpm swtpm-tools tpm2-tools libtss2-dev)
WORKFLOWS=(ci.yml e2e.yml mutants.yml mutants-diff.yml)
# Jobs that never compile, by workflow file: job id. Every other job must install the packages.
EXEMPT=(
    "ci.yml:commits"  # commitlint only (node)
    "ci.yml:ci"       # aggregator of the other jobs' results
    "ci.yml:signoff"  # reads a commit status
    "mutants.yml:report" # files a GitHub issue from the artifacts
    "e2e.yml:result"  # aggregator of the e2e results
    "e2e.yml:changes" # reads the list of files of the PR
)
# shellcheck source=scripts/install-sync-lib.sh
. "$HERE/install-sync-lib.sh"
run_install_sync
