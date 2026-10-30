#!/usr/bin/env bash
# Tests of scripts/check-bus-check-sync.sh (F42): it passes on the tree and fails when one embedded copy of the check is edited by one
# byte, when the source block is edited, when a script is missing, and when the markers are gone.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-bus-check-sync.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-bus-check-sync: $*" >&2; fail=1; }
FILES=(packaging/deb/preinst packaging/rpm/pre packaging/arch/pre_install packaging/arch/pre_upgrade packaging/arch/custodio-bus-check)

# fresh: a copy of the files the gate reads.
fresh() {
    rm -rf "$tmp/tree"
    mkdir -p "$tmp/tree/packaging"
    cp -r "$ROOT/packaging/deb" "$ROOT/packaging/rpm" "$ROOT/packaging/arch" "$ROOT/packaging/bus-check.sh" "$tmp/tree/packaging/"
}
gate() { "$GATE" "$tmp/tree" > "$tmp/out" 2>&1; }

"$GATE" > /dev/null 2>&1 || bad "the gate fails on the tree"
fresh
gate || bad "the gate fails on a copy of the tree: $(cat "$tmp/out")"

for f in "${FILES[@]}"; do
    fresh
    # One byte: the first "ProcessFD" in the embedded block becomes "ProcessFE".
    sed -i '0,/ProcessFD/s//ProcessFE/' "$tmp/tree/$f"
    if gate; then bad "$f edited by one byte: the gate passed"; continue; fi
    grep -q "$f" "$tmp/out" || bad "$f edited: the output does not name it: $(cat "$tmp/out")"
    [ "$(grep -c 'differs from' "$tmp/out")" -eq 1 ] || bad "$f edited: more than that file is reported: $(cat "$tmp/out")"
    # A byte appended after the block.
    fresh
    echo "# x" >> "$tmp/tree/$f"
    if gate; then bad "$f with a line appended: the gate passed"; fi
    fresh
    rm "$tmp/tree/$f"
    if gate; then bad "$f missing: the gate passed"; fi
done

fresh
sed -i 's/ProcessFD/ProcessFE/' "$tmp/tree/packaging/bus-check.sh"
if gate; then bad "source block edited: the gate passed"; fi
[ "$(grep -c 'differs from' "$tmp/out")" -eq ${#FILES[@]} ] || bad "source block edited: not every copy is reported: $(cat "$tmp/out")"

# Text outside the markers of the source is not part of the check.
fresh
echo "# a remark outside the block" >> "$tmp/tree/packaging/bus-check.sh"
gate || bad "a remark after the block of the source failed the gate: $(cat "$tmp/out")"

fresh
sed -i '/^# >>> custodio-bus-check$/d' "$tmp/tree/packaging/bus-check.sh"
if gate; then bad "start marker removed: the gate passed"; fi

exit "$fail"
