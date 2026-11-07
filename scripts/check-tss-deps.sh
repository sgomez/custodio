#!/usr/bin/env bash
# Every libtss2 soname BINARY needs is a declared dependency of the deb, the rpm and the Arch package in NFPM_YAML, by the names of
# scripts/package_expected.py (the table check-packages.sh reads too). Fails when the binary needs no libtss2 soname at all (exit 3).
# usage: scripts/check-tss-deps.sh BINARY NFPM_YAML
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[ $# -eq 2 ] || { echo "usage: check-tss-deps.sh BINARY NFPM_YAML" >&2; exit 2; }
for tool in readelf python3; do
    command -v "$tool" >/dev/null || { echo "check-tss-deps: required tool '$tool' is not installed" >&2; exit 2; }
done
exec python3 -I -B "$ROOT/scripts/check_tss_deps.py" "$1" "$2"
