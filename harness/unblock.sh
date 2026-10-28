#!/usr/bin/env bash
# Apply a person's answer to BLOCKED.md in an agent session, then continue the pipeline.
# Runs in the dev container; `just harness unblock "<answer>"` starts it.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

answer=${1:?Usage: harness/unblock.sh \"<answer>\"}
[ "$(uname -s)" = Linux ] || die "Run this inside the dev container: harness/run.sh"
[ -e BLOCKED.md ] || die "There is no BLOCKED.md."
tracked_changes && die "Uncommitted changes to tracked files; commit or stash them first."
ensure_node_tools
LOG_DIR=.harness/logs
STATE=.harness/state
mkdir -p "$LOG_DIR"
before=$(git rev-parse HEAD)
question=$(sha < BLOCKED.md)
logfile="$LOG_DIR/$(date +%Y%m%d-%H%M%S)-unblock.log"

log "Unblocker: applying your answer"
HARNESS_ROLE=unblocker claude -p --dangerously-skip-permissions "$(cat harness/unblock-prompt.md)

BLOCKED.md:
$(cat BLOCKED.md)

The person's answer:
$answer" >"$logfile" 2>&1 || log "unblocker session exited non-zero, see $logfile"

if [ -e BLOCKED.md ] && [ "$(sha < BLOCKED.md)" != "$question" ]; then
  cat BLOCKED.md
  die "The session could not apply the answer and rewrote BLOCKED.md (above); see $logfile." 2
fi
tracked_changes && die "The session left uncommitted changes; see $logfile."
git diff --quiet "$before" HEAD -- SPEC.md features.json APPROVALS \
  || die "The session changed SPEC.md, features.json or APPROVALS; review git log $before..HEAD."
if [ "$before" != "$(git rev-parse HEAD)" ]; then
  npx --no-install commitlint --from "$before" --to HEAD \
    || die "The session's commit messages break the convention; rewrite them, then run this again."
fi

# The answer approves the contract text it changed; without this the loop rejects the change.
for c in $(git diff --name-only "$before" HEAD -- 'contracts/*.md'); do
  id=$(basename "$c" .md)
  [ -f "$c" ] && [ -f "$STATE/$id.contract" ] || continue
  contract_hash "$c" > "$STATE/$id.contract"
  log "$id: contract re-approved by your answer. Review it: git diff $before HEAD -- $c"
done

git rm -q --cached --ignore-unmatch BLOCKED.md
rm -f BLOCKED.md
printf 'docs: answer the blocked question\n\n%s\n' "$(printf 'Answer: %s' "$answer" | fold -s -w 100)" \
  | git commit -q --allow-empty -F -
log "Unblocked:"
git log --oneline "$before..HEAD"
exec harness/pipeline.sh
