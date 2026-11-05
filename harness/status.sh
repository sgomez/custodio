#!/usr/bin/env bash
# Where the harness is and the one command to run next. Safe to run any time; changes nothing.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

next() { printf '\nNext: %s\n' "$1"; exit 0; }

# why_unapproved <spec|features|budgets> <file>: says why the file counts as not approved.
why_unapproved() {
  if [ ! -f APPROVALS ]; then
    echo "No approval of $2 is recorded: APPROVALS does not exist (it predates approvals, or nobody ran just milestone approve)."
  elif grep -q "^$1 " APPROVALS; then
    echo "$2 changed after you approved it."
  else
    echo "$2 has no approval recorded in APPROVALS."
  fi
}

# feature_list: the features and how many pass, approved or not.
feature_list() {
  [ -f features.json ] || return 0
  jq -r '.features[] | "  \(if .passes then "[x]" else "[ ]" end) \(.id) \(.title)\(if .manual then " (manual)" else "" end)"' features.json
  total=$(jq '[.features[] | select((.manual // false) | not)] | length' features.json)
  done_=$(jq '[.features[] | select((.manual // false) | not) | select(.passes)] | length' features.json)
  printf '\n%s of %s automatic features pass.\n' "$done_" "$total"
}

# unapproved_notes: one line per file that needs an approval before the loop goes on.
unapproved_notes() {
  local kind file
  for kind in spec:SPEC.md features:features.json budgets:budgets.tsv; do
    file=${kind#*:} kind=${kind%%:*}
    [ ! -f "$file" ] || approved "$kind" || echo "$(why_unapproved "$kind" "$file") Approve it with: just milestone approve $kind"
  done
}

if [ -e AGENT_STOP ]; then
  feature_list
  printf '\nStopped by you (AGENT_STOP exists).\n'
  notes=$(unapproved_notes)
  [ -z "$notes" ] || printf '\nBefore you resume:\n%s\n' "$notes"
  next "just harness resume"
fi
if [ -e BLOCKED.md ]; then
  echo "A session needs a decision from you:"; echo; cat BLOCKED.md
  next "just harness unblock \"<your answer>\" (an agent applies it), or apply it yourself, then: just harness unblock"
fi
if [ ! -f SPEC.md ]; then
  [ -f IDEA.md ] || next "just milestone open"
  grep -q '^TODO:' IDEA.md && next "write IDEA.md (replace the TODO line), then: just harness run"
  next "just harness run   (the planner writes SPEC.md)"
fi
if ! approved spec; then
  feature_list; echo
  why_unapproved spec SPEC.md
  next "if SPEC.md is the spec you want: just milestone approve spec"
fi
if [ ! -f features.json ]; then
  next "just harness run   (the initializer writes features.json)"
fi
if ! approved features; then
  feature_list; echo
  why_unapproved features features.json
  next "if features.json is the list you want: just milestone approve features"
fi
if [ -f budgets.tsv ] && ! approved budgets; then
  feature_list; echo
  why_unapproved budgets budgets.tsv
  next "if budgets.tsv has the time budgets you want: just milestone approve budgets"
fi

feature_list

current=$(jq -r '[.features[] | select((.manual // false) | not) | select(.passes | not)] | first | .id // empty' features.json)
if [ -f NEXT_FINDINGS.md ]; then
  printf '\nLast rejection (NEXT_FINDINGS.md):\n'; head -n 15 NEXT_FINDINGS.md
  evaluated=$(cat ".harness/state/$current.evaluated" 2>/dev/null || true)
  unevaluated=$(git log --format=%s "$evaluated..HEAD" 2>/dev/null | grep -cF "($current)" || true)
  if [ -n "$evaluated" ] && (( unevaluated > 0 )); then
    printf '\nThese findings may be fixed already: the builder has made %s commit(s) since, and no evaluator has reviewed them.\n' "$unevaluated"
  fi
fi

if [ -f .harness/state/stopped ]; then
  printf '\nThe loop stopped for you: %s\n' "$(head -n 1 .harness/state/stopped)"
  next "$(sed -n 2p .harness/state/stopped)"
fi
if [ -n "$current" ] && [ -f ".harness/state/$current.contract-review" ]; then
  printf '\nThe evaluator sent contracts/%s.md back (.harness/state/%s.contract-review):\n' "$current" "$current"
  head -n 15 ".harness/state/$current.contract-review"
  next "just harness fix $current   (an agent fixes it with you, then the loop continues)"
fi

if [ "$done_" = "$total" ]; then
  manual=$(jq -r '[.features[] | select(.manual and (.passes | not)) | .id] | join(", ")' features.json)
  if [ -n "$manual" ]; then
    echo "Check these by hand: $manual"
    next "check them by hand, then for each: just milestone pass <id>"
  fi
  # Released when a tag contains the last change to features.json (the last feature marked).
  last=$(git log -1 --format=%H -- features.json)
  [ -n "$(git tag --contains "$last")" ] || next "just release"
  next "just milestone close"
fi
next "just harness run   (or: just harness try, to spend at most 3 sessions)"
