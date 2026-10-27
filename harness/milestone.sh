#!/usr/bin/env bash
# Milestones: the unit of work the harness plans and builds.
#   harness/milestone.sh list    # closed milestones and the open one
#   harness/milestone.sh close   # archive the finished milestone in docs/milestones/<name>
#   harness/milestone.sh open    # start the next one from a new IDEA.md
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

archive=docs/milestones

# The open milestone's name: from features.json, else from the "Milestone:" line of IDEA.md.
current() {
  if [ -f features.json ]; then
    jq -r '.milestone // "M?"' features.json
  elif [ -f IDEA.md ]; then
    sed -n 's/^Milestone: *//p' IDEA.md | head -n1
  fi
}

# Highest number in the closed milestones' names (M0 → 0), or -1 when there are none.
last_closed() {
  local n=-1 d m
  for d in "$archive"/M*/; do
    [ -d "$d" ] || continue
    m=$(basename "$d"); m=${m#M}
    [[ $m =~ ^[0-9]+$ ]] && (( m > n )) && n=$m
  done
  echo "$n"
}

# Highest feature number used so far, open milestone included.
last_feature() {
  local files=()
  [ -f features.json ] && files+=(features.json)
  for f in "$archive"/*/features.json; do [ -f "$f" ] && files+=("$f"); done
  (( ${#files[@]} )) || { echo 0; return; }
  jq -s '[.[].features[].id | select(test("^F[0-9]+$")) | ltrimstr("F") | tonumber] | max // 0' "${files[@]}"
}

list() {
  local d found=0
  for d in "$archive"/*/; do
    [ -d "$d" ] || continue
    found=1
    printf '%s closed (%s features)\n' "$(basename "$d")" "$(jq '.features | length' "$d/features.json" 2>/dev/null || echo '?')"
  done
  if [ -f features.json ]; then
    printf '%s open: %s of %s features pass\n' "$(current)" \
      "$(jq '[.features[] | select(.passes)] | length' features.json)" "$(jq '.features | length' features.json)"
  elif [ -n "$(current)" ]; then
    printf '%s open: planning (IDEA.md)\n' "$(current)"
  else
    (( found )) || echo "No milestones yet."
    echo "No open milestone. Next: just milestone open"
  fi
}

close() {
  local name dest pending
  [ -f features.json ] || die "No open milestone to close (no features.json)."
  tracked_changes && die "Uncommitted changes to tracked files; commit or stash them first."
  pending=$(jq -r '[.features[] | select(.passes | not) | .id] | join(", ")' features.json)
  [ -z "$pending" ] || die "Not every feature passes yet: $pending. See: just status"
  name=$(current)
  dest="$archive/$name"
  [ -e "$dest" ] && die "$dest already exists."
  mkdir -p "$dest"
  for f in SPEC.md features.json APPROVALS contracts IDEA.md; do
    if [ -e "$f" ]; then git mv "$f" "$dest/"; fi
  done
  git commit -q -m "docs: close milestone $name"
  log "Closed $name, archived in $dest. Next: just milestone open"
}

open() {
  local name first
  [ -f features.json ] || [ -f SPEC.md ] || [ -f IDEA.md ] \
    && die "Milestone $(current) is still open. Finish it and run: just milestone close"
  tracked_changes && die "Uncommitted changes to tracked files; commit or stash them first."
  name="M$(( $(last_closed) + 1 ))"
  first=$(printf 'F%02d' $(( $(last_feature) + 1 )))
  cat > IDEA.md <<EOF
Milestone: $name

TODO: replace this line with 3-4 sentences: what this milestone adds, for whom, and why.

Earlier milestones are archived in $archive/; build on the code that already exists.
Number this milestone's features from $first.
EOF
  commit "docs: open milestone $name" IDEA.md
  log "Opened $name. Write IDEA.md, then: just harness"
}

case "${1:-list}" in
  list) list ;;
  close) close ;;
  open) open ;;
  *) die "Usage: just milestone [list|close|open]" ;;
esac
