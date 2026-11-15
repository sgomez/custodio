#!/usr/bin/env bash
# Test of scripts/check-bus-check-sync.sh (F42): it passes on a copy of the tree and fails, naming the file, when one embedded copy of
# the check is edited by one byte.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-bus-check-sync.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-bus-check-sync: $*" >&2; fail=1; }

# fresh: a copy of the files the gate reads.
fresh() {
    rm -rf "$tmp/tree"
    mkdir -p "$tmp/tree/packaging"
    cp -r "$ROOT/packaging/deb" "$ROOT/packaging/rpm" "$ROOT/packaging/arch" "$ROOT/packaging/bus-check.sh" "$tmp/tree/packaging/"
}
gate() { "$GATE" "$tmp/tree" > "$tmp/out" 2>&1; }

fresh
gate || bad "the gate fails on a copy of the tree: $(cat "$tmp/out")"

# One byte: the first "ProcessFD" in the embedded block becomes "ProcessFE".
f=packaging/deb/preinst
fresh
sed -i '0,/ProcessFD/s//ProcessFE/' "$tmp/tree/$f"
if gate; then bad "$f edited by one byte: the gate passed"; fi
grep -q "$f" "$tmp/out" || bad "$f edited: the output does not name it: $(cat "$tmp/out")"
[ "$(grep -c 'differs from' "$tmp/out")" -eq 1 ] || bad "$f edited: more than that file is reported: $(cat "$tmp/out")"

exit "$fail"
