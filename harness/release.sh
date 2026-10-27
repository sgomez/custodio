#!/usr/bin/env bash
# Release: the next version from the Conventional Commits since the last tag (git-cliff),
# CHANGELOG.md updated, a release commit, an annotated tag, and a push.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

tracked_changes && die "Uncommitted changes to tracked files; commit or stash them first."
if git describe --tags --exact-match HEAD >/dev/null 2>&1; then
  die "HEAD is already released as $(git describe --tags --exact-match HEAD)."
fi

version=$(git cliff --bumped-version 2>/dev/null)
[ -n "$version" ] || die "git-cliff could not work out the next version."
git rev-parse -q --verify "refs/tags/$version" >/dev/null && die "Tag $version already exists."

git cliff --tag "$version" -o CHANGELOG.md 2>/dev/null
commit "chore(release): prepare for $version" CHANGELOG.md
git tag -a "$version" -m "$version"
log "Tagged $version. Pushing..."
git push --follow-tags
log "Released $version."
