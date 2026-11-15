#!/usr/bin/env bash
# Prints the git tree hash of the working tree: tracked files as they are on disk, and untracked files that
# are not ignored. The index is not touched; the stamp of `just check` (target/check-ok) is this hash.
# PROGRESS.md is left out: no check reads it, and the hand-off entry written after `just check` must not void the stamp.
# Arguments are further paths to leave out, for a stamp of gates that do not read them.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
index=$(mktemp)
trap 'rm -f "$index"' EXIT
cp "$(git rev-parse --git-path index)" "$index"
GIT_INDEX_FILE=$index git add -A
GIT_INDEX_FILE=$index git rm -q --cached --ignore-unmatch -- PROGRESS.md >/dev/null
[ $# = 0 ] || GIT_INDEX_FILE=$index git rm -q -r --cached --ignore-unmatch -- "$@" >/dev/null
GIT_INDEX_FILE=$index git write-tree
