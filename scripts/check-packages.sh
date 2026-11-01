#!/usr/bin/env bash
# The gate of `just package`: checks the three packages in DIR (default target/packages) against the nfpm
# configuration CONFIG (default packaging/nfpm.yaml). Extracts each package, then calls check_packages.py.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIR=${1:-$ROOT/target/packages}
CONFIG=${2:-$ROOT/packaging/nfpm.yaml}

# CHECK_PACKAGES_SKIP_TOOL_CHECK=1 skips this loop, so the tests can reach the helper's own missing-tool message.
for tool in dpkg-deb rpm bsdtar readelf python3; do
    [ -z "${CHECK_PACKAGES_SKIP_TOOL_CHECK:-}" ] || break
    command -v "$tool" >/dev/null || { echo "check-packages: required tool '$tool' is not installed" >&2; exit 1; }
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/deb" "$tmp/rpm" "$tmp/arch" "$tmp/rpmdb"

# A missing or duplicated package is reported by the helper; only extract what is there.
extract() { # LABEL GLOB
    local pkgs
    pkgs=$(compgen -G "$DIR/$2" || true)
    [ "$(printf '%s\n' "$pkgs" | grep -c .)" -eq 1 ] || return 0
    if [ "$1" = deb ]; then dpkg-deb -x "$pkgs" "$tmp/$1" && dpkg-deb -e "$pkgs" "$tmp/deb-control"; else bsdtar -xf "$pkgs" -C "$tmp/$1"; fi
}
extract deb '*.deb'
extract rpm '*.rpm'
extract arch '*.pkg.tar.zst'

exec python3 -I -B "$ROOT/scripts/check_packages.py" "$DIR" "$CONFIG" "$tmp"
