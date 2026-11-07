#!/usr/bin/env bash
# Builds the M3 packages of the e2e upgrade-m3-* cases (F142, SPEC acceptance 9) into target/packages-m3: the .deb, the .rpm and the Arch package of the tag v0.5.0
# (M3: the state format without record magic), built with the tag's own recipe (`just package`) in a copy of the tree that `git archive` writes under
# target/m3-build/tree, never from the working tree and never checked out over it. The version is lower than any later build (0.0.9 against N's 0.1.0), so that
# the target's own comparison accepts the upgrade from it. It touches neither target/packages, target/packages-next nor target/packages-oldpath.
# The build is kept: a stamp (the tag's commit, the version and this script) in target/m3-build/stamp makes the next run reuse the three files, if they are all still there.
# A missing tag (a shallow clone) fails with a message; it never skips. M3_ROOT (the repository), M3_TAG, M3_VERSION, M3_OUT and M3_BUILD override the defaults (tests).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${M3_ROOT:-$here}"
tag=${M3_TAG:-v0.5.0}
version=${M3_VERSION:-0.0.9}
out=${M3_OUT:-target/packages-m3}
build=${M3_BUILD:-target/m3-build}
die() { echo "package-m3: $*" >&2; exit 1; }
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "bad version '$version'"
commit=$(git rev-parse -q --verify "refs/tags/$tag^{commit}") || die "the tag $tag is missing (a shallow clone? run: git fetch --tags)"
stamp="$commit $version $(sha256sum < "$here/scripts/package-m3.sh" | cut -d' ' -f1)"
complete() { # the three packages are there
    local n
    for n in '*.deb' '*.rpm' '*.pkg.tar*'; do [ -n "$(find "$out" -maxdepth 1 -type f -name "$n" 2> /dev/null | head -n 1)" ] || return 1; done
}
if [ -f "$build/stamp" ] && [ "$(cat "$build/stamp")" = "$stamp" ] && complete; then
    echo "package-m3: $out is current ($tag at ${commit:0:12}, version $version); not rebuilt"
    exit 0
fi
rm -rf "$build" "$out"
mkdir -p "$build/tree" "$out"
git archive "$tag" | tar -x -C "$build/tree"
(
    cd "$build/tree"
    cargo fetch --locked > /dev/null
    just package "version=$version" > ../build.log 2>&1 || { tail -n 30 ../build.log >&2; exit 1; }
) || die "the build of $tag failed (log: $build/build.log)"
cp "$build/tree/target/packages/"* "$out/"
complete || die "the build of $tag left no .deb, .rpm and Arch package in $build/tree/target/packages"
echo "$stamp" > "$build/stamp"
echo "package-m3: the packages of $tag (${commit:0:12}) at version $version are in $out"
