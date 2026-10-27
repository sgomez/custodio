#!/usr/bin/env bash
# Record that a person reviewed and approved the spec or the feature list.
#   harness/approve.sh spec
#   harness/approve.sh features
# The approval is the file's hash: if the file changes afterwards, it needs approving again.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

what=${1:-}
case "$what" in
  spec) [ -f SPEC.md ] || die "No SPEC.md to approve." ;;
  features) [ -f features.json ] || die "No features.json to approve."; harness/validate-features.sh ;;
  *) die "Usage: harness/approve.sh spec|features" ;;
esac

line="$what $("hash_$what")"
touch APPROVALS
grep -v "^$what " APPROVALS > APPROVALS.tmp || true
echo "$line" >> APPROVALS.tmp
mv APPROVALS.tmp APPROVALS
commit "chore: approve $what" APPROVALS
log "Approved $what."
