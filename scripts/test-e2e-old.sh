#!/usr/bin/env bash
# F60: scripts/package-old.sh (the old package of the e2e upgrade case, built by cargo-deb at the last M1 commit) with a stub `cargo` and a
# throwaway git repository, so no crate is built and no network is used: the pin is a full commit id, the build runs outside the working tree,
# the cache key is made of the pin and the cargo-deb version, a cold cache without network stops at once, and nothing of mise.toml,
# mise.lock, harness/Containerfile or .github is touched. NOT checked here: that the real package is built and reproducible; that is the
# real run of the script.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT=$ROOT/scripts/package-old.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-old: $*" >&2; fail=1; }

# A repository with two commits to pin, and the stub toolchain.
repo=$tmp/repo
git init -q "$repo"
git -C "$repo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m one
printf 'x\n' > "$repo/file"
git -C "$repo" add file
git -C "$repo" -c user.name=t -c user.email=t@t commit -q -m two
pin1=$(git -C "$repo" rev-parse HEAD~1)
pin2=$(git -C "$repo" rev-parse HEAD)
mkdir -p "$tmp/bin"
cat > "$tmp/bin/cargo" <<'STUB'
#!/usr/bin/env bash
# logs "SUBCOMMAND cwd=... target=..." and pretends: install makes a cargo-deb that prints its version, deb makes the package.
echo "$1 cwd=$PWD target=${CARGO_TARGET_DIR:-} args=$*" >> "$STUB_LOG"
case $1 in
install)
    root=''; spec=''
    while [ $# -gt 0 ]; do case $1 in --root) root=$2; shift ;; cargo-deb@*) spec=$1 ;; esac; shift; done
    mkdir -p "$root/bin"
    printf '#!/bin/sh\necho "cargo-deb %s"\n' "${STUB_REPORT_VERSION:-${spec#cargo-deb@}}" > "$root/bin/cargo-deb"
    chmod +x "$root/bin/cargo-deb"
    ;;
build) ;;
deb)
    [ -z "${STUB_NO_DEB:-}" ] || exit 0
    mkdir -p "$CARGO_TARGET_DIR/debian"
    printf 'deb of %s\n' "$(cat file 2>/dev/null || echo none)" > "$CARGO_TARGET_DIR/debian/${STUB_DEB_NAME:-custodio_0.1.0-1_amd64.deb}"
    ;;
esac
STUB
chmod +x "$tmp/bin/cargo"
export STUB_LOG=$tmp/cargo.log

# run NAME [VAR=VALUE...]: the script in the repository ROOT as the working directory, with its own cache and output
n=0
run() {
    n=$((n + 1))
    (cd "$ROOT" && env OLD_SRC_REPO="$repo" OLD_OUT="$tmp/out$n" OLD_CACHE="$tmp/cache" OLD_NET_PROBE=true TMPDIR="$tmp" PATH="$tmp/bin:$PATH" "$@" \
        bash "${SCRIPT_UNDER_TEST:-$SCRIPT}" > "$tmp/stdout" 2>&1)
}
calls() { grep -c "^$1 " "$STUB_LOG" || true; }

# --- the pin of the script itself
read -r real_pin real_cdeb _ <<< "$(bash "$SCRIPT" --print-key)"
[[ $real_pin =~ ^[0-9a-f]{40}$ ]] || bad "the script's pin '$real_pin' is not a full commit id"
[ "$(git -C "$ROOT" cat-file -t "$real_pin" 2> /dev/null)" = commit ] || bad "the script's pin is not a commit of this repository (is it the tag object?)"
[ "$real_cdeb" = 3.8.0 ] || bad "the script does not pin cargo-deb 3.8.0 (M1's version): $real_cdeb"
grep -q "$real_pin" "$SCRIPT" || bad "the pin is not written in the script"
{ grep -q 'd0f4314' "$SCRIPT" && grep -q 'v0.3.0' "$SCRIPT"; } || bad "the script does not explain the pin (v0.3.0 and the five later commits)"
for bad_pin in v0.3.0 0f48354 d870ab2 "${real_pin:0:39}" "${real_pin}0" "${real_pin^^}" ''; do
    if OLD_PIN=$bad_pin bash "$SCRIPT" --print-key > "$tmp/stdout" 2>&1; then bad "the pin '$bad_pin' was accepted"
    else grep -q 'full commit id' "$tmp/stdout" || bad "the pin '$bad_pin' was rejected without saying why: $(cat "$tmp/stdout")"; fi
done

# --- a build: where it runs, what it writes, what it leaves alone
before=$(cd "$ROOT" && git status --porcelain)
sums=$(cd "$ROOT" && { cat mise.toml mise.lock harness/Containerfile; find .github -type f -print0 | sort -z | xargs -0 cat; } | sha256sum)
: > "$STUB_LOG"
run OLD_PIN="$pin1" OLD_CARGO_DEB=3.8.0 || bad "a build with stubs failed: $(cat "$tmp/stdout")"
[ "$(cd "$ROOT" && git status --porcelain)" = "$before" ] || bad "the build changed the working tree"
[ "$(cd "$ROOT" && { cat mise.toml mise.lock harness/Containerfile; find .github -type f -print0 | sort -z | xargs -0 cat; } | sha256sum)" = "$sums" ] \
    || bad "the build changed mise.toml, mise.lock, harness/Containerfile or .github"
{ [ "$(find "$tmp/out$n" -type f | wc -l)" -eq 1 ] && [ -f "$tmp/out$n/custodio_0.1.0-1_amd64.deb" ]; } || bad "the output is not exactly custodio_0.1.0-1_amd64.deb: $(ls "$tmp/out$n")"
grep -q '^install .*--locked' "$STUB_LOG" || bad "cargo-deb is not installed with --locked"
grep -q '^install .*cargo-deb@3.8.0' "$STUB_LOG" || bad "cargo-deb 3.8.0 is not what is installed"
grep -q '^build .*--release --locked' "$STUB_LOG" || bad "the build is not the M1 build (--release --locked)"
grep -q '^deb .*--locked --no-build -p custodiod' "$STUB_LOG" || bad "the package is not made with the M1 command (cargo deb --locked --no-build -p custodiod)"
while read -r cmd cwd target _; do
    case ${cwd#cwd=} in "$ROOT"* | "$repo"*) bad "'$cmd' ran inside the working tree or the source repository (${cwd#cwd=})" ;; esac
    case ${target#target=} in "$ROOT"* | "$repo"*) bad "'$cmd' wrote its target inside the working tree (${target#target=})" ;; esac
    [ "${cwd#cwd=}" != "$ROOT" ] || bad "'$cmd' ran in the working tree"
done < <(grep -v '^install' "$STUB_LOG")
for cmd in build deb; do grep -q "^$cmd cwd=$tmp/custodio-old\.[A-Za-z0-9]*/src " "$STUB_LOG" || bad "$cmd did not run in a fresh directory of its own under TMPDIR"; done
# the same check must fail for a build that runs in the working tree (a mutated copy of the script)
# shellcheck disable=SC2016 # the pattern is a literal line of the script
sed 's|^cd "\$src"$|cd "$root"|' "$SCRIPT" > "$tmp/mutated.sh"
cmp -s "$SCRIPT" "$tmp/mutated.sh" && bad "the mutation of the script changed nothing"
: > "$STUB_LOG"
SCRIPT_UNDER_TEST=$tmp/mutated.sh run OLD_PIN="$pin1" OLD_NO_CACHE=1 || true
grep -q "^build cwd=$ROOT " "$STUB_LOG" || bad "control: the mutated script did not build in the working tree, so the check above proves nothing"

# --- the cache: the key is made of the pin and the cargo-deb version
key() { env OLD_PIN="$1" OLD_CARGO_DEB="$2" bash "$SCRIPT" --print-key | cut -d' ' -f3; }
k=$(key "$pin1" 3.8.0)
[ "$k" = "$(key "$pin1" 3.8.0)" ] || bad "the cache key is not stable"
[ "$k" != "$(key "$pin2" 3.8.0)" ] || bad "a changed pin does not change the cache key"
[ "$k" != "$(key "$pin1" 3.8.1)" ] || bad "a changed cargo-deb version does not change the cache key"
: > "$STUB_LOG"
run OLD_PIN="$pin1" OLD_CARGO_DEB=3.8.0 || bad "a cached run failed: $(cat "$tmp/stdout")"
{ [ "$(calls install)" -eq 0 ] && [ "$(calls build)" -eq 0 ]; } || bad "a warm cache still built"
grep -q cached "$tmp/stdout" || bad "a cached run does not say so"
[ -f "$tmp/out$n/custodio_0.1.0-1_amd64.deb" ] || bad "a cached run did not produce the package"
run OLD_PIN="$pin2" OLD_CARGO_DEB=3.8.0 || bad "a run with another pin failed: $(cat "$tmp/stdout")"
[ "$(calls build)" -eq 1 ] || bad "another pin did not rebuild"
grep -q 'deb of x' "$tmp/out$n/custodio_0.1.0-1_amd64.deb" || bad "the package of the second pin does not come from the second pin's tree"
run OLD_PIN="$pin2" OLD_CARGO_DEB=3.8.1 || bad "a run with another cargo-deb failed: $(cat "$tmp/stdout")"
[ "$(calls build)" -eq 2 ] || bad "another cargo-deb version did not rebuild"
run OLD_PIN="$pin2" OLD_CARGO_DEB=3.8.1 OLD_NO_CACHE=1 || bad "a run that bypasses the cache failed"
[ "$(calls build)" -eq 3 ] || bad "OLD_NO_CACHE did not rebuild"

# --- no network: a cold cache stops at once with a clear message; a warm cache does not need it. The probe is a stub: the real network is not used.
: > "$STUB_LOG"
if run OLD_PIN="$pin1" OLD_CARGO_DEB=3.9.0 OLD_NET_PROBE=false; then bad "a cold cache without network succeeded"
else
    grep -q 'crates.io is unreachable' "$tmp/stdout" || bad "no clear message for the missing network: $(cat "$tmp/stdout")"
    [ ! -s "$STUB_LOG" ] || bad "cargo was run although the network is unreachable"
fi
run OLD_PIN="$pin1" OLD_CARGO_DEB=3.8.0 OLD_NET_PROBE=false || bad "a warm cache needed the network: $(cat "$tmp/stdout")"

# --- failures of the toolchain are not hidden
if run OLD_PIN="$pin1" OLD_CARGO_DEB=4.0.0 OLD_NO_CACHE=1 STUB_REPORT_VERSION=3.8.0; then bad "a cargo-deb of another version was accepted"
else grep -q 'expected cargo-deb 4.0.0' "$tmp/stdout" || bad "a wrong cargo-deb version was not named: $(cat "$tmp/stdout")"; fi
if run OLD_PIN="$pin1" OLD_NO_CACHE=1 STUB_NO_DEB=1; then bad "a build that made no package was accepted"; fi
if run OLD_PIN="$pin1" OLD_NO_CACHE=1 STUB_DEB_NAME=custodio_9.9.9-1_amd64.deb; then bad "a package with another name was accepted"; fi
if run OLD_PIN=0000000000000000000000000000000000000000; then bad "a pin that is no commit of the repository was accepted"
else grep -q 'not a commit' "$tmp/stdout" || bad "an unknown pin was not named"; fi

# --- the script is where it should be: not in a recipe other than e2e, no other tool list names cargo-deb
grep -q 'scripts/package-old.sh' "$ROOT/justfile" || bad "the e2e recipe does not call scripts/package-old.sh"
awk '/^e2e target/{f=1;next} /^[a-z-]+.*:/{f=0} f && /package-old/{ok=1} END{exit !ok}' "$ROOT/justfile" || bad "package-old.sh is not called in the e2e recipe"
if grep -rqsE 'cargo[- ]deb' "$ROOT/mise.toml" "$ROOT/mise.lock" "$ROOT/harness/Containerfile" "$ROOT/.github"; then bad "cargo-deb is named in mise.toml, mise.lock, harness/Containerfile or .github"; fi
exit "$fail"
