#!/usr/bin/env bash
# The gate of `just snap-base-fit` (F184): the module that `custodio register` copies into the Firefox snap must run on the snap's base
# (packaging/snap-bases.txt): no GLIBC_x.y above its glibc, and only libraries it is recorded to provide.
# usage: scripts/check-snap-base.sh [ELF | PACKAGE_DIR [BASES_FILE]]
#   ELF: the library itself. PACKAGE_DIR (default target/packages): its .deb; the module is the same file in all three packages
#   (scripts/check-parity.sh proves it). Needs dpkg-deb, readelf and python3.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MODULE=usr/lib/custodio/libcustodio_pkcs11.so
target=${1:-$ROOT/target/packages}
bases=${2:-$ROOT/packaging/snap-bases.txt}
for tool in readelf python3; do
    command -v "$tool" > /dev/null || { echo "check-snap-base: required tool '$tool' is not installed" >&2; exit 2; }
done
if [ -d "$target" ]; then
    command -v dpkg-deb > /dev/null || { echo "check-snap-base: required tool 'dpkg-deb' is not installed" >&2; exit 2; }
    shopt -s nullglob
    debs=("$target"/*.deb)
    [ "${#debs[@]}" -eq 1 ] || { echo "check-snap-base: expected one .deb in $target, found ${#debs[@]}" >&2; exit 2; }
    tmp=$(mktemp -d)
    trap 'rm -rf "${tmp:?}"' EXIT
    dpkg-deb --fsys-tarfile "${debs[0]}" | tar -x -C "$tmp" "./$MODULE" || { echo "check-snap-base: ${debs[0]} has no /$MODULE" >&2; exit 2; }
    target=$tmp/$MODULE
fi
python3 -I -B "$ROOT/scripts/check_snap_base.py" "$target" "$bases"
