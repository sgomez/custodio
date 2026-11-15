#!/usr/bin/env bash
# Test of scripts/check-sysusers-sync.sh (F43, F44): it passes on a copy of the tree and fails when the text embedded in a maintainer
# script is edited and when the conf has no entry.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-sysusers-sync.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-sysusers-sync: $*" >&2; fail=1; }

fresh() {
    rm -rf "$tmp/tree"
    mkdir -p "$tmp/tree/packaging" "$tmp/tree/data"
    cp -r "$ROOT/packaging/deb" "$ROOT/packaging/rpm" "$ROOT/packaging/arch" "$tmp/tree/packaging/"
    cp -r "$ROOT/data/sysusers.d" "$tmp/tree/data/"
}
gate() { "$GATE" "$tmp/tree" > "$tmp/out" 2>&1; }
expect_fail() { # LABEL
    if gate; then bad "$1: the gate passed"; return; fi
    grep -q 'sysusers' "$tmp/out" || bad "$1: the output does not say what differs: $(cat "$tmp/out")"
}

fresh
gate || bad "the gate fails on a copy of the tree: $(cat "$tmp/out")"

fresh
sed -i 's/^u custodio/u custodiX/' "$tmp/tree/packaging/deb/preinst"
expect_fail "embedded account name edited"
fresh
grep -v '^u ' "$tmp/tree/data/sysusers.d/custodio.conf" > "$tmp/conf"
cp "$tmp/conf" "$tmp/tree/data/sysusers.d/custodio.conf"
expect_fail "conf without entry"

exit "$fail"
