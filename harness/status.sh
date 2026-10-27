#!/usr/bin/env bash
# Where the harness is and the one command to run next. Safe to run any time; changes nothing.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

next() { printf '\nNext: %s\n' "$1"; exit 0; }

# why_unapproved <spec|features> <file>: says why the file counts as not approved.
why_unapproved() {
  if [ ! -f APPROVALS ]; then
    echo "No approval of $2 is recorded: APPROVALS does not exist (it predates approvals, or nobody ran just approve)."
  elif grep -q "^$1 " APPROVALS; then
    echo "$2 changed after you approved it."
  else
    echo "$2 has no approval recorded in APPROVALS."
  fi
}

if [ -e AGENT_STOP ]; then
  echo "Stopped by you (AGENT_STOP exists)."
  next "just harness-resume"
fi
if [ -e BLOCKED.md ]; then
  echo "A session needs a decision from you:"; echo; cat BLOCKED.md
  next "decide, then: rm BLOCKED.md && git commit -am 'docs: answer blocked question' && just harness"
fi
if [ ! -f SPEC.md ]; then
  [ -f IDEA.md ] || next "just milestone open"
  grep -q '^TODO:' IDEA.md && next "write IDEA.md (replace the TODO line), then: just harness"
  next "just harness   (the planner writes SPEC.md)"
fi
if ! approved spec; then
  why_unapproved spec SPEC.md
  next "if SPEC.md is the spec you want: just approve spec"
fi
if [ ! -f features.json ]; then
  next "just harness   (the initializer writes features.json)"
fi
if ! approved features; then
  why_unapproved features features.json
  next "if features.json is the list you want: just approve features"
fi

jq -r '.features[] | "  \(if .passes then "[x]" else "[ ]" end) \(.id) \(.title)\(if .manual then " (manual)" else "" end)"' features.json
total=$(jq '[.features[] | select((.manual // false) | not)] | length' features.json)
done_=$(jq '[.features[] | select((.manual // false) | not) | select(.passes)] | length' features.json)
printf '\n%s of %s automatic features pass.\n' "$done_" "$total"

if [ -f NEXT_FINDINGS.md ]; then
  printf '\nLast rejection (NEXT_FINDINGS.md):\n'; head -n 15 NEXT_FINDINGS.md
fi

if [ "$done_" = "$total" ]; then
  manual=$(jq -r '[.features[] | select(.manual and (.passes | not)) | .id] | join(", ")' features.json)
  if [ -n "$manual" ]; then
    echo "Check these by hand: $manual"
    next "check them, set \"passes\": true for each in features.json, and commit"
  fi
  git describe --tags --exact-match HEAD >/dev/null 2>&1 || next "just release"
  next "just milestone close"
fi
next "just harness   (or: just harness-try, to spend at most 3 sessions)"
