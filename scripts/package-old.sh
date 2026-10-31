#!/usr/bin/env bash
# Builds the OLD package of the e2e upgrade case (F60): the .deb that `cargo deb` built at the end of milestone M1, into
# target/packages-old (never target/packages or target/packages-next). Called by the `e2e` recipe. cargo-deb is NOT a tool of this
# repository any more (not in mise.toml, mise.lock, harness/Containerfile or .github): it is installed here, with `cargo install --locked`,
# into a private directory that is removed at the end. The source is `git archive` of the pin into a fresh empty directory under
# $TMPDIR with its own CARGO_TARGET_DIR, so the working tree and its target/ are not touched.
#
# Why the pin is this commit: it is the commit of the tag v0.3.0 (the tag object is 0f48354; the commit is the id below). The five
# commits after it until M2 opened (d0f4314, 18b903b, 8fc81d8, 33a1ee6, d68e5dd) change only docs and tooling (CI, the Containerfile, the
# justfile, one typos line in mise.toml), not the crates or the cargo-deb metadata, so the package is the same. Do not "fix" the pin to a later
# commit: the last one is not the last that built a package. It must stay a full 40-character commit id.
#
# The result is cached in target/old-package-cache/<key>, the key being made of the pin and the cargo-deb version; a change to either
# rebuilds. OLD_NO_CACHE=1 builds again whatever the cache holds (used to check that two builds are byte-identical).
# A cold cache needs crates.io (cargo install, and the crates of the old tree); with no network the script stops at once.
# Environment (for the tests of the script): OLD_PIN, OLD_CARGO_DEB, OLD_OUT, OLD_CACHE, OLD_NET_PROBE, OLD_NO_CACHE, OLD_SRC_REPO.
#   package-old.sh            builds (or copies from the cache) the package into $OLD_OUT
#   package-old.sh --print-key   prints "<pin> <cargo-deb version> <key>" and exits
set -euo pipefail
PIN=${OLD_PIN-d870ab21890362c1e5ba0c5e223513fe52e421b5}
CARGO_DEB=${OLD_CARGO_DEB-3.8.0}
die() { echo "package-old: $*" >&2; exit 1; }

[[ $PIN =~ ^[0-9a-f]{40}$ ]] || die "the pin '$PIN' is not a full commit id"
[[ $CARGO_DEB =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "the cargo-deb version '$CARGO_DEB' is not a plain version"
key=$(printf 'pin=%s\ncargo-deb=%s\n' "$PIN" "$CARGO_DEB" | sha256sum | cut -c1-16)
if [ "${1:-}" = --print-key ]; then echo "$PIN $CARGO_DEB $key"; exit 0; fi
[ $# -eq 0 ] || die "usage: package-old.sh [--print-key]"

root=$(git rev-parse --show-toplevel)
repo=${OLD_SRC_REPO:-$root}
out=${OLD_OUT:-$root/target/packages-old}
cache=${OLD_CACHE:-$root/target/old-package-cache}/$key
[ "$(git -C "$repo" cat-file -t "$PIN" 2> /dev/null)" = commit ] || die "the pin $PIN is not a commit of this repository"

deb_name=custodio_0.1.0-1_amd64.deb
put_out() { rm -rf "$out"; mkdir -p "$out"; cp "$1/$deb_name" "$out/$deb_name"; }

if [ -z "${OLD_NO_CACHE:-}" ] && [ -f "$cache/$deb_name" ]; then
    put_out "$cache"
    echo "package-old: cached $out/$deb_name (key $key: pin $PIN, cargo-deb $CARGO_DEB)"
    exit 0
fi

probe=${OLD_NET_PROBE:-}
if [ -z "$probe" ]; then
    if command -v curl > /dev/null; then probe='curl -fsS --max-time 15 -o /dev/null https://index.crates.io/config.json'
    else probe="timeout 15 bash -c ': > /dev/tcp/index.crates.io/443'"; fi
fi
if ! bash -c "$probe" > /dev/null 2>&1; then
    die "crates.io is unreachable and the cache has no package for key $key (pin $PIN, cargo-deb $CARGO_DEB); building the old package needs the network once"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/custodio-old.XXXXXX")
trap 'rm -rf "$work"' EXIT
src=$work/src
mkdir "$src"
git -C "$repo" archive "$PIN" | tar -x -C "$src"
epoch=$(git -C "$repo" log -1 --format=%ct "$PIN")
export CARGO_TARGET_DIR=$work/target SOURCE_DATE_EPOCH=$epoch
# Paths of the build directory and of the cargo home must not reach the binaries.
export RUSTFLAGS="--remap-path-prefix=$src=/build/src --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/build/cargo"
cargo install --locked --quiet --root "$work/tools" --target-dir "$work/tools-target" "cargo-deb@$CARGO_DEB" > /dev/null
got=$("$work/tools/bin/cargo-deb" --version 2> /dev/null | head -n 1 || true)
[ "$got" = "cargo-deb $CARGO_DEB" ] || die "installed '$got', expected cargo-deb $CARGO_DEB"
# The M1 commands (justfile `package` at the pin).
cd "$src"
cargo build --release --locked -p custodiod -p custodio-cli -p custodio-pkcs11
PATH="$work/tools/bin:$PATH" cargo deb --locked --no-build -p custodiod > /dev/null
built=$(find "$CARGO_TARGET_DIR/debian" -name '*.deb' | head -n 1)
{ [ -n "$built" ] && [ "$(basename "$built")" = "$deb_name" ]; } || die "cargo deb produced '${built:-nothing}', expected $deb_name"
mkdir -p "$cache"
cp "$built" "$cache/$deb_name.tmp"
mv "$cache/$deb_name.tmp" "$cache/$deb_name"
put_out "$cache"
echo "package-old: built $out/$deb_name with cargo-deb $CARGO_DEB from $PIN (key $key); sha256 $(sha256sum "$out/$deb_name" | cut -d' ' -f1)"
