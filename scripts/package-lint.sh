#!/usr/bin/env bash
# The gate of `just package-lint`: lintian on the .deb, rpmlint on the .rpm and namcap on the Arch package of DIR (default
# target/packages), with the pins and exception lists of LISTDIR (default packaging/lint). A linter runs on the host when its version
# is the pinned one and otherwise in a container (podman or docker); PACKAGE_LINT_FORCE_CONTAINER=1 always uses the container.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 -I -B "$ROOT/scripts/package_lint.py" "${1:-$ROOT/target/packages}" "${2:-$ROOT/packaging/lint}"
