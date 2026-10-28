#!/usr/bin/env bash
# Build loop. For each feature whose dependencies pass:
#   1. contract: the builder writes contracts/<id>.md, the evaluator approves or sends it back;
#   2. build: fresh builder sessions tick the contract's steps, as many sessions as it takes;
#   3. gate: the feature's verify command, then the evaluator against the contract;
#   4. only then the loop marks the feature as passing.
# Every claude call is a fresh context. Stop it any time with `touch AGENT_STOP`.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

MAX_SESSIONS=${MAX_SESSIONS:-40}                # claude sessions in this run, all roles: the budget
MAX_ATTEMPTS=${MAX_ATTEMPTS:-3}                 # rejected implementations per feature
MAX_CONTRACT_ROUNDS=${MAX_CONTRACT_ROUNDS:-3}   # contract drafts per feature
MAX_FEATURE_SESSIONS=${MAX_FEATURE_SESSIONS:-8} # builder sessions per feature
LOG_DIR=.harness/logs
STATE=.harness/state
mkdir -p "$LOG_DIR" "$STATE" contracts
ensure_node_tools

[ "$(uname -s)" = Linux ] || die "Run this inside the dev container: harness/run.sh"
if ! approved spec || ! approved features; then
  die "SPEC.md and features.json must be approved first: harness/pipeline.sh"
fi

sessions=0

# run_claude <role> <log> <claude args...>
run_claude() {
  local role=$1 logfile=$2
  shift 2
  if (( sessions >= MAX_SESSIONS )); then die "Reached MAX_SESSIONS=$MAX_SESSIONS." 0; fi
  sessions=$((sessions + 1))
  HARNESS_ROLE=$role claude -p --dangerously-skip-permissions "$@" >"$logfile" 2>&1 \
    || log "$role session exited non-zero, see $logfile"
}

verdict() { grep -m1 -v '^[[:space:]]*$' "$1" | tr -d '[:space:]`*'; }
bump() { local n; n=$(( $(cat "$STATE/$1" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$STATE/$1"; echo "$n"; }
open_steps() { grep -cE '^[[:space:]]*- \[ \]' "$1" || true; }

stash_leftovers() {
  if tracked_changes; then
    git stash push -q -m "loop: uncommitted leftovers from $1"
    log "Stashed uncommitted leftovers from $1"
  fi
}

# bad_commits <id>: prints commitlint's report on the feature's commits that break the convention,
# and how to fix them. Returns 1 when every commit is fine.
bad_commits() {
  local base squash_to out
  base=$(cat "$STATE/$1.base")
  squash_to=$(cat "$STATE/$1.contract-head" 2>/dev/null || echo "$base")
  out=$(npx --no-install commitlint --from "$base" --to HEAD 2>&1) && return 1
  # shellcheck disable=SC2016 # the backticks are Markdown, not command substitution
  printf '```\n%s\n```\n\nRewrite them, e.g. as one commit: `git reset --soft %s && git commit -m "feat(%s): ..."`.\n' \
    "$out" "$squash_to" "$1"
}

findings() { { printf '# Findings for %s\n\n' "$1"; cat; } > NEXT_FINDINGS.md; log "$1: $2"; }

next_feature() {
  jq -r '
    .features as $all
    | [ .features[]
        | select(.passes == false and (.manual // false) == false)
        | select(all(.depends_on[]?; . as $d | any($all[]; .id == $d and .passes))) ]
    | first | .id // empty' features.json
}

negotiate_contract() {
  local id=$1 feature=$2 c="contracts/$1.md" round stamp prompt
  [ -f "$STATE/$id.base" ] || git rev-parse HEAD > "$STATE/$id.base"
  for ((round = 1; round <= MAX_CONTRACT_ROUNDS; round++)); do
    stamp="$(date +%Y%m%d-%H%M%S)-$id-contract$round"
    prompt="$(cat harness/contract-prompt.md)

Feature:
$feature"
    if [ -f "$STATE/$id.contract-review" ]; then
      prompt="$prompt

The evaluator sent your previous draft back. Revise contracts/$id.md to address this:
$(cat "$STATE/$id.contract-review")"
    fi
    log "$id: drafting contract (round $round)"
    run_claude builder "$LOG_DIR/$stamp.log" "$prompt"
    stash_leftovers "$stamp"
    if [ ! -f "$c" ] || tracked_changes; then
      echo "The previous session did not commit contracts/$id.md." > "$STATE/$id.contract-review"
      continue
    fi
    if bad_commits "$id" > "$STATE/$id.commits"; then
      mv "$STATE/$id.commits" "$STATE/$id.contract-review"
      continue
    fi
    run_claude evaluator "$LOG_DIR/$stamp-review.log" --agent evaluator \
      "Mode: contract. Review contracts/$id.md for this feature: $feature"
    if [ "$(verdict "$LOG_DIR/$stamp-review.log")" = APPROVED ]; then
      contract_hash "$c" > "$STATE/$id.contract"
      git rev-parse HEAD > "$STATE/$id.contract-head"
      rm -f "$STATE/$id.contract-review"
      log "$id: contract approved"
      return 0
    fi
    cp "$LOG_DIR/$stamp-review.log" "$STATE/$id.contract-review"
  done
  die "$id: contract not approved after $MAX_CONTRACT_ROUNDS rounds; see $STATE/$id.contract-review" 2
}

while true; do
  [ -e AGENT_STOP ] && die "AGENT_STOP found, stopping." 0
  if [ -e BLOCKED.md ]; then cat BLOCKED.md; die "BLOCKED.md found: a human is needed." 2; fi
  tracked_changes && die "Uncommitted changes to tracked files; commit or stash them first."

  id=$(next_feature)
  if [ -z "$id" ]; then
    log "No buildable features left. Not passing yet:"
    jq -r '.features[] | select(.passes == false) | "  \(.id) \(.title)\(if .manual then " (manual)" else "" end)"' features.json
    exit 0
  fi
  feature=$(jq -c --arg id "$id" '.features[] | select(.id == $id)' features.json)
  verify=$(jq -r '.verify' <<<"$feature")
  c="contracts/$id.md"

  # 1. Contract
  if [ ! -f "$STATE/$id.contract" ] || [ ! -f "$c" ]; then negotiate_contract "$id" "$feature"; fi

  # 2. Build
  n=$(bump "$id.sessions")
  (( n <= MAX_FEATURE_SESSIONS )) || die "$id used $MAX_FEATURE_SESSIONS builder sessions without passing. Stopping for a human." 2
  stamp="$(date +%Y%m%d-%H%M%S)-$id-s$n"
  head_before=$(git rev-parse HEAD)
  log "$id: builder session $n"
  run_claude builder "$LOG_DIR/$stamp-build.log" "$(cat harness/builder-prompt.md)

Feature:
$feature

Approved contract: $c"
  [ -e BLOCKED.md ] && continue
  stash_leftovers "$stamp"
  if [ "$(git rev-parse HEAD)" = "$head_before" ]; then
    echo "The previous session made no commit. Commit your work at the end of every session." \
      | findings "$id" "no commit"
    continue
  fi
  if bad_commits "$id" > "$STATE/$id.commits"; then
    findings "$id" "commit messages" < "$STATE/$id.commits"
    continue
  fi

  if [ "$(contract_hash "$c")" != "$(cat "$STATE/$id.contract")" ]; then
    bump "$id.attempts" >/dev/null
    echo "contracts/$id.md changed beyond ticking checkboxes. Restore the approved text (\`git log -p $c\`) and only tick steps." \
      | findings "$id" "contract text changed"
    continue
  fi
  left=$(open_steps "$c")
  if (( left > 0 )); then
    rm -f NEXT_FINDINGS.md
    log "$id: in progress, $left contract steps left"
    continue
  fi

  # 3. Gate: verify, then evaluator
  attempts=$(bump "$id.attempts")
  (( attempts <= MAX_ATTEMPTS )) || die "$id was rejected $MAX_ATTEMPTS times; see NEXT_FINDINGS.md. Stopping for a human." 2
  log "$id: verify ($verify)"
  if ! bash -c "$verify" >"$LOG_DIR/$stamp-verify.log" 2>&1; then
    # shellcheck disable=SC2016 # the backticks are Markdown, not command substitution
    { printf 'The verify command failed: `%s`\n\nLast lines of output:\n\n```\n' "$verify"
      tail -n 60 "$LOG_DIR/$stamp-verify.log"
      printf '```\n'; } | findings "$id" "verify failed"
    continue
  fi
  log "$id: evaluating"
  run_claude evaluator "$LOG_DIR/$stamp-eval.log" --agent evaluator \
    "Mode: implementation. Feature: $feature. Contract: $c. Changes: git diff $(cat "$STATE/$id.base")..HEAD. Verify log: $LOG_DIR/$stamp-verify.log"

  stash_leftovers "$stamp-eval"

  # 4. Mark as passing
  if [ "$(verdict "$LOG_DIR/$stamp-eval.log")" = PASS ]; then
    jq --arg id "$id" '(.features[] | select(.id == $id) | .passes) = true' features.json > features.json.tmp
    mv features.json.tmp features.json
    commit "chore($id): mark as passing (verify + evaluator)" features.json
    rm -f NEXT_FINDINGS.md "$STATE/$id".*
    log "$id: PASS"
  else
    findings "$id" "NEEDS_WORK" < "$LOG_DIR/$stamp-eval.log"
  fi
done
