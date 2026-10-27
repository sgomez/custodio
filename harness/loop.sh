#!/usr/bin/env bash
# Outer loop: one fresh `claude -p` per attempt, a deterministic gate, then an independent evaluator.
# Run it inside the dev container (harness/run.sh). Stop it any time with `touch AGENT_STOP`.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

MAX_SESSIONS=${MAX_SESSIONS:-40}   # total builder sessions for this run: your budget
MAX_ATTEMPTS=${MAX_ATTEMPTS:-3}    # rejected attempts per feature before asking a human
LOG_DIR=.harness/logs
STATE_DIR=.harness/attempts
mkdir -p "$LOG_DIR" "$STATE_DIR"

if [ "$(uname -s)" != Linux ]; then
  echo "Run this inside the dev container: harness/run.sh" >&2
  exit 1
fi

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

next_feature() {
  jq -r '
    .features as $all
    | [ .features[]
        | select(.passes == false and (.manual // false) == false)
        | select(all(.depends_on[]?; . as $d | any($all[]; .id == $d and .passes))) ]
    | first | .id // empty' features.json
}

for ((session = 1; session <= MAX_SESSIONS; session++)); do
  if [ -e AGENT_STOP ]; then log "AGENT_STOP found, stopping."; exit 0; fi
  if [ -e BLOCKED.md ]; then log "BLOCKED.md found, a human is needed:"; cat BLOCKED.md; exit 2; fi
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    log "Uncommitted changes to tracked files; commit or stash them first."; exit 1
  fi

  id=$(next_feature)
  if [ -z "$id" ]; then
    log "No buildable features left. Remaining:"
    jq -r '.features[] | select(.passes == false) | "  \(.id) \(.title)"' features.json
    exit 0
  fi

  attempts=$(( $(cat "$STATE_DIR/$id" 2>/dev/null || echo 0) + 1 ))
  if (( attempts > MAX_ATTEMPTS )); then
    log "$id was rejected $MAX_ATTEMPTS times; see NEXT_FINDINGS.md. Stopping for a human."; exit 2
  fi
  echo "$attempts" > "$STATE_DIR/$id"

  feature=$(jq -c --arg id "$id" '.features[] | select(.id == $id)' features.json)
  verify=$(jq -r '.verify' <<<"$feature")
  base=$(git rev-parse HEAD)
  stamp="$(date +%Y%m%d-%H%M%S)-$id-a$attempts"

  log "Session $session/$MAX_SESSIONS: building $id (attempt $attempts)"
  prompt="$(cat harness/builder-prompt.md)

Feature to build (attempt $attempts of $MAX_ATTEMPTS):
$feature"
  claude -p --dangerously-skip-permissions "$prompt" >"$LOG_DIR/$stamp-build.log" 2>&1 \
    || log "builder exited non-zero, see $LOG_DIR/$stamp-build.log"

  if [ -e BLOCKED.md ]; then continue; fi
  if [ "$(git rev-parse HEAD)" = "$base" ]; then
    printf '# Findings for %s\n\nThe previous session made no commit. Commit your work at the end of the session.\n' "$id" > NEXT_FINDINGS.md
    log "$id: no commit"; continue
  fi
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    git stash push -m "loop: uncommitted leftovers from $stamp" >/dev/null
    log "$id: stashed uncommitted leftovers"
  fi

  log "$id: running verify: $verify"
  if ! bash -c "$verify" >"$LOG_DIR/$stamp-verify.log" 2>&1; then
    # shellcheck disable=SC2016 # the backticks are Markdown, not command substitution
    { printf '# Findings for %s\n\nThe verify command failed: `%s`\n\nLast lines of output:\n\n```\n' "$id" "$verify"
      tail -n 60 "$LOG_DIR/$stamp-verify.log"
      printf '```\n'; } > NEXT_FINDINGS.md
    log "$id: verify failed"; continue
  fi

  log "$id: evaluating"
  verdict=$(claude -p --agent evaluator --dangerously-skip-permissions \
    "Review feature $id: the changes are \`git diff $base..HEAD\`. Feature: $feature" \
    2>&1 | tee "$LOG_DIR/$stamp-eval.log") || true
  first=$(grep -m1 -v '^[[:space:]]*$' <<<"$verdict" | tr -d '[:space:]`*')

  if [ "$first" = PASS ] && [ -z "$(git status --porcelain --untracked-files=no)" ]; then
    tmp=$(mktemp)
    jq --arg id "$id" '(.features[] | select(.id == $id) | .passes) = true' features.json >"$tmp"
    mv "$tmp" features.json
    git add features.json
    git commit -q -m "$id: mark as passing (verify + evaluator)"
    rm -f NEXT_FINDINGS.md "$STATE_DIR/$id"
    log "$id: PASS"
  else
    { printf '# Findings for %s (evaluator)\n\n' "$id"; printf '%s\n' "$verdict"; } > NEXT_FINDINGS.md
    log "$id: NEEDS_WORK"
  fi
done
log "Reached MAX_SESSIONS=$MAX_SESSIONS."
