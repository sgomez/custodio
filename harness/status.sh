#!/usr/bin/env bash
# Where the harness is and the one command to run next. Safe to run any time; changes nothing.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

next() { printf '\nNext: %s\n' "$1"; exit 0; }

if [ -e AGENT_STOP ]; then
  echo "Stopped by you (AGENT_STOP exists)."
  next "just harness-resume"
fi
if [ -e BLOCKED.md ]; then
  echo "A session needs a decision from you:"; echo; cat BLOCKED.md
  next "decide, then: rm BLOCKED.md && git commit -am 'docs: answer blocked question' && just harness"
fi
if [ ! -f SPEC.md ]; then
  [ -s IDEA.md ] || next "write IDEA.md (3-4 sentences: what, for whom, why), then: just harness"
  next "just harness   (the planner writes SPEC.md)"
fi
if ! approved spec; then
  echo "SPEC.md is waiting for your review."
  next "read and edit SPEC.md, then: just approve spec"
fi
if [ ! -f features.json ]; then
  next "just harness   (the initializer writes features.json)"
fi
if ! approved features; then
  echo "features.json is waiting for your review."
  next "read and edit features.json, then: just approve features"
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
  [ -n "$manual" ] && echo "Check these by hand: $manual"
  next "review git log, push, open the PR. For more work: add features to features.json, or just new-milestone <name>"
fi
next "just harness   (or: just harness-try, to spend at most 3 sessions)"
