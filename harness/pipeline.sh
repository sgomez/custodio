#!/usr/bin/env bash
# The whole flow, from idea to built milestone. Run it again after each stop; it picks up where
# it left off.
#
#   IDEA.md ──planner──▶ SPEC.md ──(you approve)──▶ initializer ──▶ features.json
#           ──(you approve)──▶ loop.sh: per feature, contract ▶ build ▶ verify ▶ evaluate
#
# AUTO_APPROVE=1 skips both human gates: fully autonomous, as in Anthropic's harness articles.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

[ "$(uname -s)" = Linux ] || die "Run this inside the dev container: harness/run.sh"
LOG_DIR=.harness/logs
mkdir -p "$LOG_DIR"
tracked_changes && die "Uncommitted changes to tracked files; commit or stash them first."

gate() {
  approved "$1" && return 0
  log "Stopped for review: read $2, edit it if needed, then run on your machine:"
  log "  harness/approve.sh $1 && harness/run.sh"
  exit 3
}

# 1. Planner: IDEA.md → SPEC.md
if [ ! -f SPEC.md ]; then
  [ -s IDEA.md ] || die "Write IDEA.md (a few sentences: what, for whom, why) and run again."
  log "Planner: writing SPEC.md from IDEA.md"
  HARNESS_ROLE=planner claude -p --dangerously-skip-permissions --agent planner \
    "Write SPEC.md from IDEA.md." >"$LOG_DIR/$(date +%Y%m%d-%H%M%S)-planner.log" 2>&1 || true
  [ -s SPEC.md ] || die "The planner did not write SPEC.md; see $LOG_DIR."
  commit "Add spec drafted by the planner" SPEC.md
fi
gate spec SPEC.md

# 2. Initializer: SPEC.md → features.json
if [ ! -f features.json ]; then
  log "Initializer: splitting SPEC.md into features.json"
  HARNESS_ROLE=initializer claude -p --dangerously-skip-permissions --agent initializer \
    "Split SPEC.md into features.json." >"$LOG_DIR/$(date +%Y%m%d-%H%M%S)-initializer.log" 2>&1 || true
  [ -f features.json ] || die "The initializer did not write features.json; see $LOG_DIR."
  harness/validate-features.sh
  jq -e 'all(.features[]; .passes == false)' features.json >/dev/null \
    || die "The initializer marked features as passing."
  commit "Add feature list drafted by the initializer" features.json
fi
harness/validate-features.sh
gate features features.json

# 3. Build loop
exec harness/loop.sh
