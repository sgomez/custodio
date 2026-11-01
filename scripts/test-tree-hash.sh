#!/usr/bin/env bash
# scripts/tree-hash.sh, the stamp of `just check`: on a scratch repository, the hash follows edits and untracked
# files, ignores ignored ones and the session handoff (PROGRESS.md), and leaves the index alone.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-tree-hash: $*" >&2; fail=1; }

git -C "$tmp" init -q
mkdir -p "$tmp/scripts"
cp "$ROOT/scripts/tree-hash.sh" "$tmp/scripts/"
printf 'ignored/\n' > "$tmp/.gitignore"
echo a > "$tmp/a"
git -C "$tmp" add -A
git -C "$tmp" -c user.name=t -c user.email=t@t commit -qm init
h() { "$tmp/scripts/tree-hash.sh"; }

base=$(h)
[ "$base" = "$(git -C "$tmp" rev-parse 'HEAD^{tree}')" ] || bad "a clean tree is not HEAD's tree"
echo b > "$tmp/a"
edited=$(h)
[ "$edited" != "$base" ] || bad "an unstaged edit does not change the hash"
[ -z "$(git -C "$tmp" diff --cached --name-only)" ] || bad "the index was changed"
echo a > "$tmp/a"
echo new > "$tmp/new"
[ "$(h)" != "$base" ] || bad "an untracked file does not change the hash"
rm "$tmp/new"
mkdir -p "$tmp/ignored" && echo x > "$tmp/ignored/x"
[ "$(h)" = "$base" ] || bad "an ignored file changes the hash"
echo entry > "$tmp/PROGRESS.md"
[ "$(h)" = "$base" ] || bad "a new PROGRESS.md changes the hash"
mkdir -p "$tmp/sub" && echo entry > "$tmp/sub/PROGRESS.md"
[ "$(h)" != "$base" ] || bad "a PROGRESS.md outside the root does not change the hash"

exit "$fail"
