#!/usr/bin/env bash
# Builds package N+1 for the upgrade case of the e2e suite: the same tree as N (target/packages, built by `just package`) with only
# the version raised (the patch number plus one), into target/packages-next. `just package` empties target/packages, so N is put
# aside while N+1 is built and then put back. Run from the `e2e` recipe after `just package`.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
cur=target/packages
next=target/packages-next
aside=target/packages-current
deb=$(find "$cur" -name 'custodio_*.deb' | head -n 1)
[ -n "$deb" ] || { echo "package-next: no package N in $cur (run just package first)" >&2; exit 1; }
v=$(dpkg-deb -f "$deb" Version)
[[ $v =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(~[0-9A-Za-z.]+)?-1$ ]] || { echo "package-next: unexpected version '$v' of N" >&2; exit 1; }
if [ -n "${BASH_REMATCH[4]}" ]; then echo "package-next: N is a pre-release ($v); the upgrade case needs a plain version" >&2; exit 1; fi
new="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$((BASH_REMATCH[3] + 1))"
rm -rf "$aside" "$next"
mv "$cur" "$aside"
restore() { rm -rf "$cur"; mv "$aside" "$cur"; }
trap 'if [ -d "$aside" ]; then restore; fi' EXIT
just package "version=$new"
mv "$cur" "$next"
restore
trap - EXIT
echo "package-next: N=$v, N+1=$new-1 in $next"
