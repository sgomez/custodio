#!/usr/bin/env bash
# Prints the git tree hash of the working tree: tracked files as they are on disk, and untracked files that
# are not ignored. The index is not touched; the stamp of `just check` (target/check-ok) is this hash.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
index=$(mktemp)
trap 'rm -f "$index"' EXIT
cp "$(git rev-parse --git-path index)" "$index"
GIT_INDEX_FILE=$index git add -A
GIT_INDEX_FILE=$index git write-tree
