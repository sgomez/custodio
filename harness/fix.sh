#!/usr/bin/env bash
# An interactive session with an agent to fix what stopped the loop on a feature.
# Runs in the dev container; `just harness fix <id>` starts it. On exit the pipeline continues.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

id=${1:?Usage: harness/fix.sh <feature id>}
[ "$(uname -s)" = Linux ] || die "Run this inside the dev container: harness/run.sh"
feature=$(jq -c --arg id "$id" '.features[] | select(.id == $id)' features.json)
[ -n "$feature" ] || die "There is no feature $id in features.json."
tracked_changes && die "Uncommitted changes to tracked files; commit or stash them first."
ensure_node_tools
STATE=.harness/state
c="contracts/$id.md"
before=$(git rev-parse HEAD)

prompt="$(cat harness/fix-prompt.md)

Feature:
$feature"
[ -f "$STATE/$id.contract-review" ] && prompt="$prompt

The evaluator's last review of $c:
$(cat "$STATE/$id.contract-review")"
[ -f NEXT_FINDINGS.md ] && prompt="$prompt

NEXT_FINDINGS.md:
$(cat NEXT_FINDINGS.md)"

# The container starts with no Claude config; skip the first-run onboarding and trust prompts.
jq -n --arg dir "$PWD" '{hasCompletedOnboarding: true, bypassPermissionsModeAccepted: true,
  projects: {($dir): {hasTrustDialogAccepted: true}}}' > "$HOME/.claude.json"
mkdir -p "$HOME/.claude"
echo '{"skipDangerousModePermissionPrompt": true}' > "$HOME/.claude/settings.json"

HARNESS_ROLE=fixer claude --dangerously-skip-permissions "$prompt" || true

tracked_changes && die "The session left uncommitted changes; commit or stash them."
git diff --quiet "$before" HEAD -- SPEC.md features.json APPROVALS \
  || die "The session changed SPEC.md, features.json or APPROVALS; review git log $before..HEAD."
if [ "$before" != "$(git rev-parse HEAD)" ]; then
  npx --no-install commitlint --from "$before" --to HEAD \
    || die "The session's commit messages break the convention; rewrite them, then run this again."
fi

# A changed approved contract goes back to the evaluator instead of failing the loop's check.
if [ -f "$STATE/$id.contract" ] && [ -f "$c" ] && [ "$(contract_hash "$c")" != "$(cat "$STATE/$id.contract")" ]; then
  rm -f "$STATE/$id.contract" "$STATE/$id.contract-head"
  log "$id: contract changed; the evaluator reviews it again."
fi
log "Done:"
git log --oneline "$before..HEAD"
exec harness/pipeline.sh
