#!/usr/bin/env bash
# The gate of `just package-parity`: the three packages of DIR (default target/packages) install the same paths with the same
# modes, owners and symlink targets, apart from the entries of EXCEPTIONS (default packaging/parity-exceptions.txt). Needs
# dpkg-deb, rpm, bsdtar and python3.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 -I -B "$ROOT/scripts/check_parity.py" "${1:-$ROOT/target/packages}" "${2:-$ROOT/packaging/parity-exceptions.txt}"
