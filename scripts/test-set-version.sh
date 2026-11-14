#!/usr/bin/env bash
# scripts/set-version.sh on a made-up workspace: the workspace version, the internal path dependencies and the
# workspace packages in every Cargo.lock move; a crates.io package, a package with its own version and bad input do not.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-set-version: $*" >&2; fail=1; }

mkdir -p "$tmp/crates/a/fuzz" "$tmp/crates/b"
printf '[workspace]\nmembers = ["crates/*"]\n\n[workspace.package]\nedition = "2021"\nversion = "0.1.0"\n' > "$tmp/Cargo.toml"
printf '[package]\nname = "a"\nversion.workspace = true\n\n[dependencies]\nb = { path = "../b", version = "0.1.0" }\nrand = { version = "0.1.0" }\n' > "$tmp/crates/a/Cargo.toml"
printf '[package]\nname = "b"\nversion.workspace = true\n' > "$tmp/crates/b/Cargo.toml"
lock='version = 4\n\n[[package]]\nname = "a"\nversion = "0.1.0"\ndependencies = [\n "b",\n]\n\n[[package]]\nname = "b"\nversion = "0.1.0"\n\n[[package]]\nname = "rand"\nversion = "0.1.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "00"\n'
printf %b "$lock" > "$tmp/Cargo.lock"
printf %b "$lock"'\n[[package]]\nname = "a-fuzz"\nversion = "0.0.0"\n' > "$tmp/crates/a/fuzz/Cargo.lock"
cp -r "$tmp" "$tmp.orig"
trap 'rm -rf "$tmp" "$tmp.orig"' EXIT

"$ROOT/scripts/set-version.sh" "$tmp" v0.8.0 > "$tmp.out" 2>&1 || bad "v0.8.0 failed: $(cat "$tmp.out")"
grep -q '^version = "0.8.0"$' "$tmp/Cargo.toml" || bad "the workspace version did not move"
grep -q 'b = { path = "../b", version = "0.8.0" }' "$tmp/crates/a/Cargo.toml" || bad "the path dependency did not move"
grep -q 'rand = { version = "0.1.0" }' "$tmp/crates/a/Cargo.toml" || bad "a crates.io dependency moved"
for l in Cargo.lock crates/a/fuzz/Cargo.lock; do
    [ "$(grep -c '^version = "0.8.0"$' "$tmp/$l")" = 2 ] || bad "$l: the workspace packages did not move: $(cat "$tmp/$l")"
    grep -A1 '^name = "rand"$' "$tmp/$l" | grep -q '"0.1.0"' || bad "$l: the crates.io package moved"
done
grep -A1 '^name = "a-fuzz"$' "$tmp/crates/a/fuzz/Cargo.lock" | grep -q '"0.0.0"' || bad "a package with its own version moved"
cp -r "$tmp" "$tmp.once"
"$ROOT/scripts/set-version.sh" "$tmp" 0.8.0 > "$tmp.out" 2>&1 || bad "a second run failed"
diff -r "$tmp" "$tmp.once" > /dev/null || bad "a second run with the same version changed files"
rm -rf "$tmp.once"

for v in "" 0.8 v0.8.0.1 "0.8.0 x" latest; do
    rm -rf "$tmp" && cp -r "$tmp.orig" "$tmp"
    if "$ROOT/scripts/set-version.sh" "$tmp" "$v" > "$tmp.out" 2>&1; then bad "the version '$v' was accepted"; fi
    diff -r "$tmp" "$tmp.orig" > /dev/null || bad "the version '$v' changed files"
done
rm -f "$tmp.out"
exit "$fail"
