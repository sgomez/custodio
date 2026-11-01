#!/usr/bin/env bash
# Build loop. For each feature whose dependencies pass:
#   1. contract: the builder writes contracts/<id>.md, the evaluator approves or sends it back;
#   2. build: fresh builder sessions tick the contract's steps, as many sessions as it takes;
#      a builder may amend the contract, and the evaluator approves the amendment first;
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
MAX_AMENDMENTS=${MAX_AMENDMENTS:-3}             # contract amendments per feature
LOG_DIR=.harness/logs
STATE=.harness/state
mkdir -p "$LOG_DIR" "$STATE" contracts
rm -f "$STATE/stopped"
ensure_node_tools

[ "$(uname -s)" = Linux ] || die "Run this inside the dev container: harness/run.sh"
if ! approved spec || ! approved features; then
  die "SPEC.md and features.json must be approved first: harness/pipeline.sh"
fi

sessions=0
last_rc=0

# run_claude <role> <log> <claude args...>
run_claude() {
  local role=$1 logfile=$2
  shift 2
  if (( sessions >= MAX_SESSIONS )); then die "Reached MAX_SESSIONS=$MAX_SESSIONS." 0; fi
  sessions=$((sessions + 1))
  stop_if_asked
  last_rc=0
  claude_session "$role" "$logfile" "$@" || last_rc=$?
  if [ "$last_rc" = 124 ]; then log "$role session ran past SESSION_TIMEOUT, cut; see $logfile"
  elif [ "$last_rc" != 0 ]; then log "$role session exited non-zero, see $logfile"; fi
  stop_if_asked "$logfile" # the kill-switch hook cut this session short: its output is no verdict
}

# stop_if_asked [<log of the session just cut short>]: the log goes to $STATE/interrupted for the resume.
stop_if_asked() {
  [ -e AGENT_STOP ] || return 0
  [ -z "${1:-}" ] || basename "$1" > "$STATE/interrupted"
  die "AGENT_STOP found, stopping." 0
}

# halt <reason> <what to do>: a stop that needs a person; just status shows both.
halt() { printf '%s\n%s\n' "$1" "$2" > "$STATE/stopped"; die "$1" 2; }
# verdict <log> <ok> <bad>: <ok> or <bad>, or nothing when the reply does not say which.
verdict() {
  local first lines
  first=$(grep -m1 -v '^[[:space:]]*$' "$1" | tr -d '[:space:]`*' || true)
  if [ "$first" = "$2" ] || [ "$first" = "$3" ]; then echo "$first"; return; fi
  # A verdict line further down counts only if no line names the other verdict.
  lines=$(grep -xE "[[:space:]\`*]*($2|$3)[[:space:]\`*]*" "$1" | tr -d ' \t\r`*' | sort -u || true)
  if [ -n "$lines" ] && [ "$(wc -l <<<"$lines")" = 1 ]; then echo "$lines"; fi
}

# evaluate <log> <ok> <bad> <prompt>: runs the evaluator, once more if its verdict is unclear, and
# sets $got. Two unclear replies stop the loop: a broken format must not pass nor count as a rejection.
evaluate() {
  local logfile=$1 ok=$2 bad=$3 prompt=$4 unclear
  run_claude evaluator "$logfile" --agent evaluator "$prompt"
  got=$(verdict "$logfile" "$ok" "$bad")
  [ -n "$got" ] && return 0
  unclear="${logfile%.log}-unclear.log"
  mv "$logfile" "$unclear" && mv "$logfile.jsonl" "$unclear.jsonl" 2>/dev/null || true
  log "No clear verdict in $unclear; asking the evaluator again"
  stash_leftovers "$(basename "${unclear%.log}")"
  run_claude evaluator "$logfile" --agent evaluator "$prompt

Your previous reply ($unclear) did not start with a line that is exactly \`$ok\` or \`$bad\`. Reply
again in the required format; you may reuse that review."
  got=$(verdict "$logfile" "$ok" "$bad")
  [ -n "$got" ] || halt "The evaluator gave no clear verdict twice; see $unclear and $logfile." \
    "read both logs; then just harness run to evaluate again"
}
bump() { local n; n=$(( $(cat "$STATE/$1" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$STATE/$1"; echo "$n"; }
gated() { bump "$1.attempts" >/dev/null; git rev-parse HEAD > "$STATE/$1.evaluated"; }
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
    prompt="Mode: contract. Review contracts/$id.md for this feature: $feature"
    if [ -f "$STATE/$id.contract-eval" ]; then
      prompt="$prompt

Your previous review:
$(cat "$STATE/$id.contract-eval")"
    fi
    evaluate "$LOG_DIR/$stamp-review.log" APPROVED REVISE "$prompt"
    cp "$LOG_DIR/$stamp-review.log" "$STATE/$id.contract-eval"
    if [ "$got" = APPROVED ]; then
      contract_hash "$c" > "$STATE/$id.contract"
      git rev-parse HEAD > "$STATE/$id.contract-head"
      rm -f "$STATE/$id.contract-review"
      log "$id: contract approved"
      return 0
    fi
    cp "$LOG_DIR/$stamp-review.log" "$STATE/$id.contract-review"
  done
  halt "$id: contract not approved after $MAX_CONTRACT_ROUNDS rounds; see $STATE/$id.contract-review" \
    "just harness fix $id"
}

# A stop skips the stash after a session. A builder's leftovers stay for the next builder; any other
# role's are stashed, as the loop would have done.
resumed=
if [ -f "$STATE/interrupted" ]; then
  cut=$(cat "$STATE/interrupted")
  if [[ $cut == *-build.log ]]; then
    resumed=$cut
  else
    stash_leftovers "${cut%.log}"
    rm "$STATE/interrupted"
  fi
fi

while true; do
  [ -e AGENT_STOP ] && die "AGENT_STOP found, stopping." 0
  if [ -e BLOCKED.md ]; then cat BLOCKED.md; die "BLOCKED.md found: a human is needed." 2; fi
  if [ -z "$resumed" ] && tracked_changes; then
    die "Uncommitted changes to tracked files; commit or stash them first."
  fi

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

  # After the last rejection a builder session would only make work no evaluator reviews.
  (( $(cat "$STATE/$id.attempts" 2>/dev/null || echo 0) < MAX_ATTEMPTS )) \
    || halt "$id was rejected $MAX_ATTEMPTS times; see NEXT_FINDINGS.md. Stopping for a human." \
      "read NEXT_FINDINGS.md; if $id is badly defined, fix features.json and just milestone approve features; then: rm -f $STATE/$id.attempts && just harness run"

  # 2. Build
  n=$(bump "$id.sessions")
  (( n <= MAX_FEATURE_SESSIONS )) \
    || halt "$id used $MAX_FEATURE_SESSIONS builder sessions without passing. Stopping for a human." \
      "split $id in features.json and just milestone approve features, or: rm -f $STATE/$id.sessions && just harness run"
  stamp="$(date +%Y%m%d-%H%M%S)-$id-s$n"
  head_before=$(git rev-parse HEAD)
  log "$id: builder session $n"
  run_claude builder "$LOG_DIR/$stamp-build.log" "$(cat harness/builder-prompt.md)

Feature:
$feature

Approved contract: $c

The evaluator's notes on the contract:
$(tail -n +2 "$STATE/$id.contract-eval" 2>/dev/null)${resumed:+

The operator stopped the previous builder session ($LOG_DIR/$resumed) before it committed. Its
uncommitted work is in the working tree: check it with git status and git diff, keep what holds,
and continue from it.}"
  resumed= && rm -f "$STATE/interrupted"
  [ -e BLOCKED.md ] && continue
  # A builder cut by the timeout keeps its uncommitted work for the next builder, as after a stop.
  if [ "$last_rc" = 124 ] && tracked_changes; then resumed="$stamp-build.log"; continue; fi
  stash_leftovers "$stamp"
  if [ "$(git rev-parse HEAD)" = "$head_before" ]; then
    # Every step ticked and this HEAD never evaluated: nothing for a builder to do, go to the gate.
    if (( $(open_steps "$c") > 0 )) || [ "$(cat "$STATE/$id.evaluated" 2>/dev/null)" = "$head_before" ]; then
      # A second idle session in a row will not do better: stop instead of burning the budget.
      (( $(bump "$id.idle") < 2 )) \
        || halt "$id: two builder sessions in a row made no commit. Stopping for a human." \
          "read the last $id-*-build.log in $LOG_DIR; then just harness fix $id, or: rm -f $STATE/$id.idle && just harness run"
      no_commit="The previous session made no commit. Commit your work at the end of every session."
      # Keep the evaluator's findings; replacing them leaves the next builder nothing to fix.
      prev=$(tail -n +3 NEXT_FINDINGS.md 2>/dev/null | grep -vxF "$no_commit" | sed "/./,\$!d" || true)
      printf '%s\n\n%s\n' "$no_commit" "$prev" | findings "$id" "no commit"
      continue
    fi
    log "$id: no commit and no open steps; going to the gate"
  else
    rm -f "$STATE/$id.idle"
    if bad_commits "$id" > "$STATE/$id.commits"; then
      findings "$id" "commit messages" < "$STATE/$id.commits"
      continue
    fi
  fi

  if [ "$(contract_hash "$c")" != "$(cat "$STATE/$id.contract")" ]; then
    n=$(bump "$id.amendments")
    (( n <= MAX_AMENDMENTS )) \
      || halt "$id: more than $MAX_AMENDMENTS contract amendments. Stopping for a human." \
        "just harness fix $id, or: rm -f $STATE/$id.amendments && just harness run"
    approved_head=$(cat "$STATE/$id.contract-head")
    log "$id: contract amended, evaluating the amendment"
    evaluate "$LOG_DIR/$stamp-amend.log" APPROVED REVISE \
      "Mode: amendment. Feature: $feature. Contract: $c. Amendment: git diff $approved_head..HEAD -- $c"
    stash_leftovers "$stamp-amend"
    if [ "$got" != APPROVED ]; then
      # shellcheck disable=SC2016 # the backticks are Markdown, not command substitution
      { printf 'The evaluator rejected the amendment to %s. Revise it, or restore the approved text (`git show %s:%s`).\n\n' \
          "$c" "$approved_head" "$c"
        cat "$LOG_DIR/$stamp-amend.log"; } | findings "$id" "amendment rejected"
      continue
    fi
    contract_hash "$c" > "$STATE/$id.contract"
    git rev-parse HEAD > "$STATE/$id.contract-head"
    log "$id: amendment approved"
  fi
  left=$(open_steps "$c")
  if (( left > 0 )); then
    rm -f NEXT_FINDINGS.md
    log "$id: in progress, $left contract steps left"
    continue
  fi

  # 3. Gate: verify, then evaluator
  # An attempt counts only once it has a result, so a stop mid-gate costs none.
  log "$id: verify ($verify)"
  if ! bash -c "$verify" >"$LOG_DIR/$stamp-verify.log" 2>&1; then
    gated "$id"
    # shellcheck disable=SC2016 # the backticks are Markdown, not command substitution
    { printf 'The verify command failed: `%s`\n\nLast lines of output:\n\n```\n' "$verify"
      tail -n 60 "$LOG_DIR/$stamp-verify.log"
      printf '```\n'; } | findings "$id" "verify failed"
    continue
  fi
  log "$id: evaluating"
  evaluate "$LOG_DIR/$stamp-eval.log" PASS NEEDS_WORK \
    "Mode: implementation. Feature: $feature. Contract: $c. Changes: git diff $(cat "$STATE/$id.base")..HEAD. Verify log: $LOG_DIR/$stamp-verify.log"

  gated "$id"
  stash_leftovers "$stamp-eval"

  # 4. Mark as passing
  if [ "$got" = PASS ]; then
    jq --arg id "$id" '(.features[] | select(.id == $id) | .passes) = true' features.json > features.json.tmp
    mv features.json.tmp features.json
    commit "chore($id): mark as passing (verify + evaluator)" features.json
    rm -f NEXT_FINDINGS.md "$STATE/$id".*
    log "$id: PASS"
  else
    findings "$id" "NEEDS_WORK" < "$LOG_DIR/$stamp-eval.log"
  fi
done
