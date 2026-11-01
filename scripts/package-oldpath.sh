#!/usr/bin/env bash
# Builds the old-path fixture of the e2e upgrade case (F61): the .deb and the .rpm as the M2 packages were before the daemon moved, that is
# this tree's packaging/nfpm.yaml with the daemon at /usr/lib/custodio/custodiod and the unit starting it there (scripts/lib/nfpm_edit.py `oldpath`),
# at the version of package N. They go into target/packages-oldpath (never target/packages or target/packages-next). Not a pinned old commit:
# the F48 case upgrades N to N+1 from one tree and both have the new path, so the fixture is made from the current tree on purpose.
# The Arch package has no old path (it keeps /usr/lib/custodio/custodiod), so none is built for it.
# Run after `just package` (which builds the binaries and derives the units); OLDPATH_ROOT (a tree with target/release, data and packaging), OLDPATH_OUT, PACKAGES and OLDPATH_NFPM override the paths (tests).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${OLDPATH_ROOT:-$here}"
cur=${PACKAGES:-target/packages}
out=${OLDPATH_OUT:-target/packages-oldpath}
die() { echo "package-oldpath: $*" >&2; exit 1; }
deb=$(find "$cur" -name 'custodio_*.deb' | head -n 1)
[ -n "$deb" ] || die "no package N in $cur (run just package first)"
v=$(dpkg-deb -f "$deb" Version)
[[ $v =~ ^([0-9]+\.[0-9]+\.[0-9]+)(~[0-9A-Za-z.]+)?-1$ ]] || die "unexpected version '$v' of N"
base=${BASH_REMATCH[1]}
pre=${BASH_REMATCH[2]#\~}
[ -f target/release/custodiod ] || die "target/release/custodiod is missing (run just package first)"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
"$here/scripts/derive-units.sh" data/custodio.service target/units
python3 -I "$here/scripts/lib/nfpm_edit.py" "${OLDPATH_NFPM:-packaging/nfpm.yaml}" "$tmp/nfpm-oldpath.yaml" oldpath
rm -rf "$out"
mkdir -p "$out"
for fmt in deb rpm; do
    NFPM_VERSION=$base NFPM_PRERELEASE=$pre nfpm package -f "$tmp/nfpm-oldpath.yaml" -p "$fmt" -t "$out" > /dev/null
done
echo "package-oldpath: the .deb and the .rpm of $v with the daemon at /usr/lib/custodio/custodiod are in $out"
