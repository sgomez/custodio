#!/usr/bin/env bash
# Sets the workspace version (a leading v is dropped) in ROOT: [workspace.package], the version of every internal path
# dependency, and the workspace packages of every Cargo.lock. Prints the files it changed. Used by harness/release.sh.
set -euo pipefail
[ $# = 2 ] || { echo "usage: set-version.sh ROOT VERSION" >&2; exit 2; }
exec python3 -I -B "$(dirname "${BASH_SOURCE[0]}")/set_version.py" "$1" "$2"
