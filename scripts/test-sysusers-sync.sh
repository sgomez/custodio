#!/usr/bin/env bash
# Tests of scripts/check-sysusers-sync.sh (F43, F44): it passes on the tree, ignores comments in the conf, and fails when the text
# embedded in the deb preinst, the rpm %pre or the Arch pre_install and pre_upgrade, or the conf, is edited, when the embedded text is gone, and when the conf has no entry.
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

"$GATE" > /dev/null 2>&1 || bad "the gate fails on the tree"
fresh
gate || bad "the gate fails on a copy of the tree: $(cat "$tmp/out")"

fresh
sed -i 's/^u custodio/u custodiX/' "$tmp/tree/packaging/deb/preinst"
expect_fail "embedded account name edited"
fresh
sed -i 's/Custodio signing service/Custodio signing servicf/' "$tmp/tree/packaging/deb/preinst"
expect_fail "embedded description edited"
fresh
sed -i 's/^u custodio/u custodiX/' "$tmp/tree/packaging/rpm/pre"
expect_fail "rpm: embedded account name edited"
fresh
sed -i 's/Custodio signing service/Custodio signing servicf/' "$tmp/tree/packaging/rpm/pre"
expect_fail "rpm: embedded description edited"
for f in pre_install pre_upgrade; do
    fresh
    sed -i 's/^u custodio/u custodiX/' "$tmp/tree/packaging/arch/$f"
    expect_fail "arch $f: embedded account name edited"
    fresh
    sed -i 's/Custodio signing service/Custodio signing servicf/' "$tmp/tree/packaging/arch/$f"
    expect_fail "arch $f: embedded description edited"
    fresh
    sed -i '/^u custodio/d' "$tmp/tree/packaging/arch/$f"
    expect_fail "arch $f: embedded text removed"
done
fresh
sed -i "/<<'CUSTODIO_SYSUSERS'\$/,/^CUSTODIO_SYSUSERS\$/d" "$tmp/tree/packaging/rpm/pre"
expect_fail "rpm: embedded text removed"
fresh
sed -i 's/^u custodio - /u custodio 995 /' "$tmp/tree/data/sysusers.d/custodio.conf"
expect_fail "conf edited"
fresh
echo 'g extra -' >> "$tmp/tree/data/sysusers.d/custodio.conf"
expect_fail "conf with an added line"
fresh
sed -i "/<<'CUSTODIO_SYSUSERS'\$/,/^CUSTODIO_SYSUSERS\$/d" "$tmp/tree/packaging/deb/preinst"
expect_fail "embedded text removed"
fresh
echo '# another comment' >> "$tmp/tree/data/sysusers.d/custodio.conf"
gate || bad "a comment added to the conf failed the gate: $(cat "$tmp/out")"
fresh
grep -v '^u ' "$tmp/tree/data/sysusers.d/custodio.conf" > "$tmp/conf"
cp "$tmp/conf" "$tmp/tree/data/sysusers.d/custodio.conf"
expect_fail "conf without entry"

exit "$fail"
