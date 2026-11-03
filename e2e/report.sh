# shellcheck shell=bash
# Sourced by every script of the suite that finishes a case. The one way a case is reported: the host reads these lines from the
# guest's output and compares them with e2e/cases.list and the target's skip.list (check-cases.sh). When the run was asked for a subset of the
# cases (select.sh, `just e2e-cases`), a case that is not selected prints nothing, not even as skipped.
# shellcheck source=e2e/select.sh
source "$(dirname "${BASH_SOURCE[0]}")/select.sh"
case_run() { if selected "$1"; then echo "ok: $1"; echo "E2E-CASE run $1"; fi; }
# case_skip ID REASON: the case was not run on this target. Allowed only if the target's skip.list names it.
case_skip() { if selected "$1"; then echo "skipped: $1 ($2)"; echo "E2E-CASE skipped $1"; fi; }
