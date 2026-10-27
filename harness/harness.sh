#!/usr/bin/env bash
# The agents.
#   harness/harness.sh run       # run or continue in the dev container (plan, split, build)
#   harness/harness.sh try       # same, at most 3 Claude sessions
#   harness/harness.sh stop      # stop after the current tool call
#   harness/harness.sh resume    # continue after stop
#   harness/harness.sh unblock   # after deciding what BLOCKED.md asks: commit and continue
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

case "${1:-run}" in
  run) exec harness/run.sh ;;
  try) MAX_SESSIONS=3 exec harness/run.sh ;;
  stop) touch AGENT_STOP; log "Stopping after the current tool call. Continue with: just harness resume" ;;
  resume) rm -f AGENT_STOP; exec harness/run.sh ;;
  unblock)
    [ -e BLOCKED.md ] || die "There is no BLOCKED.md."
    git rm -q --cached --ignore-unmatch BLOCKED.md
    rm -f BLOCKED.md
    git add -u
    git commit -q -m "docs: answer the blocked question"
    log "Unblocked."
    exec harness/run.sh
    ;;
  *) die "Usage: just harness [run|try|stop|resume|unblock]" ;;
esac
