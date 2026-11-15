#!/usr/bin/env bash
# Fails unless harness/Containerfile and every job that runs the CLI's cargo tests install bash-completion, zsh and fish (F192),
# each install preceded by a comment that says why (the completion test drives the real shells). Usage: check-shell-install-sync.sh [ROOT]
# ROOT holds harness/Containerfile and .github/workflows/ (default: this repository). The logic is in install-sync-lib.sh.
# Reads ci.yml, mutants.yml and mutants-diff.yml. e2e.yml and e2e-vm.yml are not read: they run the CLI inside targets, not the
# cargo tests. A job that is neither checked nor in EXEMPT fails, so a new test job cannot slip past.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=${1:-$(dirname "$HERE")}
NAME=check-shell-install-sync
KEYWORD=completion
PACKAGES=(bash-completion zsh fish)
WORKFLOWS=(ci.yml mutants.yml mutants-diff.yml)
EXEMPT=(
    "ci.yml:commits"       # commitlint only (node)
    "ci.yml:signoff"       # reads a commit status
    "ci.yml:lint"          # lints and script tests, no cargo test of the CLI
    "ci.yml:memory-safety" # miri and asan on custodio-pkcs11 and custodio-peer only
    "ci.yml:package"       # builds and inspects packages, runs no cargo test
    "ci.yml:ci"            # aggregator of the other jobs' results
    "mutants.yml:report"   # files a GitHub issue from the artifacts
)
# shellcheck source=scripts/install-sync-lib.sh
. "$HERE/install-sync-lib.sh"
run_install_sync
