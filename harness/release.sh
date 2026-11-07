#!/usr/bin/env bash
# Release of a closed milestone, from its branch: CHANGELOG.md and release commit, `just check-slow`, push,
# the signoff/check-slow and signoff/mutants statuses on that commit (gh-signoff), the PR, CI, the merge, and the version tag
# on the merge in main. Run it again after a fix or a stop: it picks up where it was.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

branch=$(git branch --show-current)
[[ $branch == milestone/m* ]] || die "Run it on the milestone branch (milestone/mN), not $branch."
[ -f features.json ] && die "Close the milestone first: just milestone close"
tracked_changes && die "Uncommitted changes to tracked files; commit or stash them first."
gh signoff --help >/dev/null 2>&1 || die "Needs gh-signoff: gh extension install basecamp/gh-signoff"
name="M${branch#milestone/m}"

pr_state() { gh pr view "$branch" --json state --jq .state 2>/dev/null || true; }

if [ "$(pr_state)" != MERGED ]; then
  version=$(git cliff --bumped-version 2>/dev/null)
  [ -n "$version" ] || die "git-cliff could not work out the next version."
  git rev-parse -q --verify "refs/tags/$version" >/dev/null && die "Tag $version already exists."
  # Again after a fix: the changelog lists it.
  git cliff --tag "$version" -o CHANGELOG.md 2>/dev/null
  if tracked_changes; then commit "chore(release): prepare for $version" CHANGELOG.md; fi

  sha=$(git rev-parse HEAD)
  signed=$(gh api "repos/{owner}/{repo}/commits/$sha/status" \
    --jq "[.statuses[] | select(.context == \"signoff/check-slow\")][0].state // \"\"" 2>/dev/null || true)
  if [ "$signed" != success ]; then
    log "Running just check-slow..."
    if [ -e /run/.containerenv ]; then just check-slow; else harness/run.sh just check-slow; fi \
      || die "just check-slow failed; fix it, commit, and run just release again."
    git push -q -u origin HEAD
    # check-slow covers ci.yml (but commitlint) and every mutant (mutants-diff.yml).
    gh signoff check-slow mutants
  else
    git push -q -u origin HEAD
  fi

  if [ -z "$(pr_state)" ]; then
    title=$(sed -n "s/^## $name — \(.*\)/\1/p" docs/milestones.md | sed 's/ (done)$//' | tr '[:upper:]' '[:lower:]')
    [ -n "$title" ] || die "No '## $name — <title>' heading in docs/milestones.md."
    gh pr create --base main --head "$branch" --title "feat: $title (milestone $name)" \
      --body "Milestone $name (docs/milestones.md), released as $version. \`just check-slow\` passed on the head commit: signoff/check-slow and signoff/mutants."
  fi
  log "Waiting for CI..."
  sleep 20 # the checks of a push take a moment to appear
  gh pr checks "$branch" --watch --interval 30 >/dev/null \
    || die "CI failed: gh pr checks $branch. Fix it, commit, and run just release again."
  gh pr merge "$branch" --merge
fi

version=$(git log -1 --format=%s "$branch" -- CHANGELOG.md | sed -n 's/^chore(release): prepare for //p')
[ -n "$version" ] || die "No release commit on $branch."
head=$(git rev-parse "$branch")
git switch -q main
git pull -q --ff-only
merge=$(git log --merges --format='%H %P' main | awk -v h="$head" '$3 == h {print $1; exit}')
[ -n "$merge" ] || die "No merge of $branch ($head) in main."
git tag -a "$version" -m "$version" "$merge"
git push -q origin "$version"
log "Released $version."
