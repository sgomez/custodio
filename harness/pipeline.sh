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
ensure_node_tools
# After a stop, loop.sh decides what to do with the leftovers of the session it cut short.
if [ ! -f .harness/state/interrupted ] && tracked_changes; then
  die "Uncommitted changes to tracked files; commit or stash them first."
fi

gate() {
  approved "$1" && return 0
  log "Stopped for review: read $2, edit it if needed, then run on your machine:"
  log "  just milestone approve $1 && just harness run"
  exit 3
}

# 1. Planner: IDEA.md → SPEC.md
if [ ! -f SPEC.md ]; then
  [ -s IDEA.md ] || die "No IDEA.md. Start a milestone with: just milestone open"
  grep -q '^TODO:' IDEA.md && die "IDEA.md still has its TODO line; write the idea first."
  log "Planner: writing SPEC.md from IDEA.md"
  claude_session planner "$LOG_DIR/$(date +%Y%m%d-%H%M%S)-planner.log" --agent planner \
    "Write SPEC.md from IDEA.md." || true
  [ -s SPEC.md ] || die "The planner did not write SPEC.md; see $LOG_DIR."
  commit "docs: add spec drafted by the planner" SPEC.md
fi
gate spec SPEC.md

# 2. Initializer: SPEC.md → features.json
if [ ! -f features.json ]; then
  log "Initializer: splitting SPEC.md into features.json"
  claude_session initializer "$LOG_DIR/$(date +%Y%m%d-%H%M%S)-initializer.log" --agent initializer \
    "Split SPEC.md into features.json." || true
  [ -f features.json ] || die "The initializer did not write features.json; see $LOG_DIR."
  harness/validate-features.sh
  jq -e 'all(.features[]; .passes == false)' features.json >/dev/null \
    || die "The initializer marked features as passing."
  commit "chore: add feature list drafted by the initializer" features.json
fi
harness/validate-features.sh
gate features features.json

# 3. Build loop
exec harness/loop.sh
