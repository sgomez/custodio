#!/usr/bin/env bash
# Archive the current milestone and start the next one from a new IDEA.md.
#   harness/new-milestone.sh M0     # name of the milestone being archived
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

name=${1:-}
[ -n "$name" ] || die "Usage: just new-milestone <name of the finished milestone, e.g. M0>"
dest="docs/milestones/$name"
[ -e "$dest" ] && die "$dest already exists."
tracked_changes && die "Uncommitted changes to tracked files; commit or stash them first."
[ -f features.json ] || die "No features.json to archive."

last=$(jq -r '[.features[].id | select(test("^F[0-9]+$")) | ltrimstr("F") | tonumber] | max // 0' features.json)
mkdir -p "$dest"
for f in SPEC.md features.json APPROVALS contracts IDEA.md; do
  [ -e "$f" ] && git mv "$f" "$dest/"
done
cat > IDEA.md <<EOF
<!-- 3-4 sentences: what this milestone adds, for whom, why. -->

The previous milestone is archived in $dest; build on the code that already exists.
Continue feature numbering at F$(printf '%02d' $((last + 1))).
EOF
git add IDEA.md
commit "docs: archive milestone $name and start the next one" "$dest" IDEA.md
log "Archived $name in $dest. Edit IDEA.md, then: just harness"
