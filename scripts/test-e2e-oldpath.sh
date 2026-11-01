#!/usr/bin/env bash
# F61: scripts/package-oldpath.sh (the old-path fixture of the e2e upgrade case) on a fixture tree: the .deb and the .rpm have the daemon at
# /usr/lib/custodio/custodiod and a unit that starts it there, the version is N's, nothing else of the layout moves, no Arch package is built, and
# the output never goes to the directories of N and N+1. Fails closed without package N or binaries.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
fx_init
trap fx_cleanup EXIT
fail=0
bad() { echo "test-e2e-oldpath: $*" >&2; fail=1; }

fx_build cur 0.1.0 '' none
cur=$FX_DIR/cur
mkdir -p "$cur" "$FX_DIR/next" "$FX_DIR/empty"
cp "$(fx_file cur deb)" "$cur/"
out=$FX_DIR/oldpath-out
run() { OLDPATH_ROOT=$FX_DIR PACKAGES=$cur OLDPATH_OUT=$out "$ROOT/scripts/package-oldpath.sh" > "$FX_DIR/run.out" 2>&1; }

run || bad "the script failed: $(cat "$FX_DIR/run.out")"
deb=$(ls "$out"/*.deb 2> /dev/null || true)
rpm=$(ls "$out"/*.rpm 2> /dev/null || true)
if [ -z "$deb" ] || [ -z "$rpm" ]; then bad "the .deb or the .rpm is missing from $out"; fi
[ -z "$(ls "$out"/*.pkg.tar.zst 2> /dev/null || true)" ] || bad "an Arch package was built; Arch has no old path"
[ "$(dpkg-deb -f "$deb" Version)" = "$(dpkg-deb -f "$(fx_file cur deb)" Version)" ] || bad "the version of the .deb is not N's"
deb_list=$(dpkg-deb -c "$deb")
grep -q ' ./usr/lib/custodio/custodiod$' <<< "$deb_list" || bad "the .deb has no daemon at /usr/lib/custodio"
! grep -q 'libexec' <<< "$deb_list" || bad "the .deb has a libexec path"
grep -q ' ./usr/lib/custodio/libcustodio_pkcs11.so$' <<< "$deb_list" || bad "the module moved in the .deb"
unit=$(dpkg-deb --fsys-tarfile "$deb" | bsdtar -xOf - usr/lib/systemd/system/custodio.service)
grep -qx 'ExecStart=/usr/lib/custodio/custodiod' <<< "$unit" || bad "the unit of the .deb does not start /usr/lib/custodio/custodiod"
rpm_list=$(fx_rpm -qlp "$rpm")
grep -qx '/usr/lib/custodio/custodiod' <<< "$rpm_list" || bad "the .rpm has no daemon at /usr/lib/custodio"
! grep -q libexec <<< "$rpm_list" || bad "the .rpm has a libexec path"
rpm_unit=$(bsdtar -xOf "$rpm" ./usr/lib/systemd/system/custodio.service)
grep -qx 'ExecStart=/usr/lib/custodio/custodiod' <<< "$rpm_unit" || bad "the unit of the .rpm does not start /usr/lib/custodio/custodiod"
# the packages of the new tree are not touched, and the fixture differs from N in content
[ "$(ls "$cur")" = "$(basename "$(fx_file cur deb)")" ] || bad "the directory of N changed"
! cmp -s "$deb" "$(fx_file cur deb)" || bad "the fixture .deb is the same as N"

# fails closed
if OLDPATH_ROOT=$FX_DIR PACKAGES=$FX_DIR/empty OLDPATH_OUT=$FX_DIR/o2 "$ROOT/scripts/package-oldpath.sh" > "$FX_DIR/run.out" 2>&1; then bad "passed without package N"; fi
grep -q 'no package N' "$FX_DIR/run.out" || bad "a missing N was not named: $(cat "$FX_DIR/run.out")"
mv "$FX_DIR/target/release/custodiod" "$FX_DIR/custodiod.away"
if run; then bad "passed without the daemon binary"; fi
grep -q 'custodiod is missing' "$FX_DIR/run.out" || bad "a missing binary was not named: $(cat "$FX_DIR/run.out")"
mv "$FX_DIR/custodiod.away" "$FX_DIR/target/release/custodiod"
# a pre-release N gets a fixture with the same pre-release
fx_build pre 0.2.0 rc.1 none
mkdir -p "$FX_DIR/prepkg"
cp "$(fx_file pre deb)" "$FX_DIR/prepkg/"
OLDPATH_ROOT=$FX_DIR PACKAGES=$FX_DIR/prepkg OLDPATH_OUT=$FX_DIR/o3 "$ROOT/scripts/package-oldpath.sh" > "$FX_DIR/run.out" 2>&1 || bad "a pre-release N is not built: $(cat "$FX_DIR/run.out")"
[ -n "$(ls "$FX_DIR/o3"/*.deb 2> /dev/null || true)" ] || bad "no .deb for a pre-release N"
exit "$fail"
