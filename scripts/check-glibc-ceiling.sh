#!/usr/bin/env bash
# The gate of `just glibc-ceiling`: no ELF file in the three packages of DIR (default target/packages) may need a glibc
# symbol version above the ceiling in CEILING_FILE (default packaging/glibc-ceiling.txt). Needs dpkg-deb, bsdtar, readelf and
# python3.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 -I -B "$ROOT/scripts/check_glibc_ceiling.py" "${1:-$ROOT/target/packages}" "${2:-$ROOT/packaging/glibc-ceiling.txt}"
