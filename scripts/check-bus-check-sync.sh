#!/usr/bin/env bash
# Fails when a pre-install script of the packages (deb preinst, rpm pre, Arch pre_install, pre_upgrade and the hook script) is not what
# scripts/embed-bus-check.sh writes from packaging/bus-check.sh: the three formats must run the same check (F42).
# usage: check-bus-check-sync.sh [ROOT]
set -euo pipefail
ROOT=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
OUT=$tmp "$(dirname "${BASH_SOURCE[0]}")/embed-bus-check.sh" "$ROOT"
status=0
for f in packaging/deb/preinst packaging/rpm/pre packaging/arch/pre_install packaging/arch/pre_upgrade packaging/arch/custodio-bus-check; do
    if ! cmp -s "$tmp/$f" "$ROOT/$f"; then
        echo "check-bus-check-sync: $f differs from packaging/bus-check.sh; run scripts/embed-bus-check.sh" >&2
        status=1
    fi
done
exit "$status"
