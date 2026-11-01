# shellcheck shell=bash
# Sourced by every script of the suite that finishes a case. The one way a case is reported: the host reads these lines from the
# guest's output and compares them with e2e/cases.list and the target's skip.list (check-cases.sh).
case_run() { echo "ok: $1"; echo "E2E-CASE run $1"; }
# case_skip ID REASON: the case was not run on this target. Allowed only if the target's skip.list names it.
case_skip() { echo "skipped: $1 ($2)"; echo "E2E-CASE skipped $1"; }
