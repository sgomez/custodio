#!/usr/bin/env bash
# The modutil package of each format (MODUTIL in scripts/package_expected.py, F172) is a run-time dependency of that format in NFPM_YAML
# (default packaging/nfpm.yaml), under its name. `custodio register` runs modutil (F183).
# usage: scripts/check-register-deps.sh [NFPM_YAML]
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
command -v python3 >/dev/null || { echo "check-register-deps: required tool 'python3' is not installed" >&2; exit 2; }
exec python3 -I -B "$ROOT/scripts/check_register_deps.py" "${1:-$ROOT/packaging/nfpm.yaml}"
