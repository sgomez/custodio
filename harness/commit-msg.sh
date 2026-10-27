#!/usr/bin/env bash
# Check commit subjects against Conventional Commits: `type(scope)!: description`.
#   harness/commit-msg.sh <message-file>   # lefthook commit-msg hook
#   harness/commit-msg.sh --range A..B     # every non-merge commit in a range
set -euo pipefail

types='feat|fix|docs|test|refactor|perf|build|ci|chore|style|revert'
pattern="^($types)(\([A-Za-z0-9._/-]+\))?!?: [^ ].*$"

check() {
  [[ $1 =~ $pattern ]] && return 0
  # Git writes these for `commit --fixup/--squash`; they are squashed away before merging.
  [[ $1 =~ ^(fixup|squash|amend)!\  ]] && return 0
  printf 'Not a Conventional Commit: %s\n' "$1" >&2
  return 1
}

hint() { echo "Expected: <$types>(<scope>)!: <description>, e.g. feat(F05): add key store" >&2; }

if [ "${1:-}" = --range ]; then
  bad=0
  while IFS= read -r subject; do check "$subject" || bad=1; done \
    < <(git log --no-merges --format=%s "$2")
  (( bad )) && hint
  exit "$bad"
fi

subject=$(grep -v '^#' "$1" | head -n1)
check "$subject" || { hint; exit 1; }
