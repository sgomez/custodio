#!/usr/bin/env bash
# Self-test of e2e/vm/image.sh (F158), offline: a throwaway test key, a small fake image, signed sums and file:// URLs.
# Shows the script refuses a bad signature, a signature by another key, a wrong checksum, a missing sums file, a sums file
# without the image, and a tampered cache, each for its own reason and leaving nothing in the cache.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMG=$ROOT/e2e/vm/image.sh
for tool in python3 gpgv curl sha256sum; do
    command -v "$tool" > /dev/null 2>&1 || { echo "test-vm-image: $tool is not installed" >&2; exit 127; }
done
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-vm-image: $*" >&2; fail=1; }
NAME=ubuntu-26.04-minimal-cloudimg-amd64.img
S1=20260101
S2=20260202

# The dev container has no gpg-agent, so gpg cannot make keys or sign: scripts/lib/openpgp_ed25519.py makes the throwaway keys
# (public keyring files) and the detached signatures, and gpgv verifies them like Ubuntu's.
PGP=$ROOT/scripts/lib/openpgp_ed25519.py
pgp() { python3 -I "$PGP" "$@"; }
for k in one two; do pgp pub "$k" "$tmp/$k.gpg"; done

# mk DIR SERIAL KEY CONTENT: DIR/release-SERIAL with the image, signed sums.
mk() {
    local d=$1/release-$2
    mkdir -p "$d"
    printf '%s\n' "$4" > "$d/$NAME"
    printf '%s *%s\n' "$(sha256sum < "$d/$NAME" | cut -d' ' -f1)" "$NAME" > "$d/SHA256SUMS"
    pgp sign "$3" "$d/SHA256SUMS" "$d/SHA256SUMS.gpg"
}
good=$tmp/good
mk "$good" $S1 one "image one"
mk "$good" $S2 one "image two, different"

# run NAME BASE [SERIAL [KEYRING]]: runs the script into $tmp/cache-NAME; sets rc_NAME, out_NAME, err_NAME.
run() {
    local n=$1 base=$2 serial=${3:-$S1} ring=${4:-$tmp/one.gpg} rc=0
    VM_IMAGE_BASE=file://$base VM_IMAGE_SERIAL=$serial VM_IMAGE_KEYRING=$ring VM_IMAGE_CACHE=$tmp/cache-$n \
        "${SCRIPT:-$IMG}" > "$tmp/out-$n" 2> "$tmp/err-$n" || rc=$?
    echo "$rc" > "$tmp/rc-$n"
}
rc_of() { cat "$tmp/rc-$1"; }
cache_empty() { [ -z "$(find "$tmp/cache-$1" -type f 2> /dev/null)" ]; }

# --- controls: each differs from the good fixture
cp -r "$good" "$tmp/c-badsig"
sed -i '1s/^./0/' "$tmp/c-badsig/release-$S1/SHA256SUMS"
cmp -s "$good/release-$S1/SHA256SUMS" "$tmp/c-badsig/release-$S1/SHA256SUMS" && bad "badsig fixture equals good"
# the sums line still matches the image, only the signature is off
cp -r "$good" "$tmp/c-badsig2"
printf '\n' >> "$tmp/c-badsig2/release-$S1/SHA256SUMS"

mkdir "$tmp/c-other"; mk "$tmp/c-other" $S1 two "image one"
cmp -s "$good/release-$S1/SHA256SUMS.gpg" "$tmp/c-other/release-$S1/SHA256SUMS.gpg" && bad "other-key signature equals good"

cp -r "$good" "$tmp/c-sum"
printf '%s *%s\n' "$(printf x | sha256sum | cut -d' ' -f1)" "$NAME" > "$tmp/c-sum/release-$S1/SHA256SUMS"
pgp sign one "$tmp/c-sum/release-$S1/SHA256SUMS" "$tmp/c-sum/release-$S1/SHA256SUMS.gpg"
cmp -s "$good/release-$S1/SHA256SUMS" "$tmp/c-sum/release-$S1/SHA256SUMS" && bad "wrong-sum fixture equals good"

cp -r "$good" "$tmp/c-noline"
printf '%s *other.img\n' "$(printf x | sha256sum | cut -d' ' -f1)" > "$tmp/c-noline/release-$S1/SHA256SUMS"
pgp sign one "$tmp/c-noline/release-$S1/SHA256SUMS" "$tmp/c-noline/release-$S1/SHA256SUMS.gpg"

cp -r "$good" "$tmp/c-nosums"; rm "$tmp/c-nosums/release-$S1/SHA256SUMS"
cp -r "$good" "$tmp/c-nosig"; rm "$tmp/c-nosig/release-$S1/SHA256SUMS.gpg"

# The refusals are independent (own fixture, own cache): run them at once, then check the results after the wait.
# badsig only changes a hash character, so the checksum line no longer matches either; badsig2 is the pure signature control.
refusals=(
    "badsig|$tmp/c-badsig|signature check failed"
    "badsig2|$tmp/c-badsig2|signature check failed"
    "other|$tmp/c-other|signature check failed"
    "sum|$tmp/c-sum|checksum mismatch"
    "noline|$tmp/c-noline|no single line"
    "nosums|$tmp/c-nosums|cannot fetch .*SHA256SUMS"
    "nosig|$tmp/c-nosig|cannot fetch .*SHA256SUMS\\.gpg"
)
# the independent good, two-serial and unpublished-serial runs go at the same time
for r in "${refusals[@]}"; do IFS='|' read -r n base _ <<< "$r"; run "$n" "$base" & done
run good "$good" &
run two "$good" $S2 &
run missing-serial "$good" 20300101 &
wait
for r in "${refusals[@]}"; do
    IFS='|' read -r n _ re <<< "$r"
    [ "$(rc_of "$n")" != 0 ] || bad "$n: exit 0, expected a refusal"
    grep -qE "$re" "$tmp/err-$n" || bad "$n: stderr lacks /$re/: $(cat "$tmp/err-$n")"
    [ ! -s "$tmp/out-$n" ] || bad "$n: printed a record on stdout"
    cache_empty "$n" || bad "$n: the cache holds a file"
done
# the four reasons differ
sig=$(cat "$tmp/err-badsig") sumr=$(cat "$tmp/err-sum") nol=$(cat "$tmp/err-noline") mis=$(cat "$tmp/err-nosums")
[ "$sig" != "$sumr" ] && [ "$sig" != "$nol" ] && [ "$sig" != "$mis" ] && [ "$sumr" != "$nol" ] && [ "$sumr" != "$mis" ] \
    && [ "$nol" != "$mis" ] || bad "refusal reasons are not distinct"
grep -q "release-$S1" "$tmp/err-nosums" || bad "a 404 does not name the serial"

# --- good run
[ "$(rc_of good)" = 0 ] || bad "good: exit $(rc_of good): $(cat "$tmp/err-good")"
cmp -s "$good/release-$S1/$NAME" "$tmp/cache-good/release-$S1/$NAME" || bad "good: cached image differs from the fixture"
want=$(sha256sum < "$good/release-$S1/$NAME" | cut -d' ' -f1)
grep -qx "sha256=$want" "$tmp/out-good" || bad "good: checksum not printed"
grep -qx "serial=$S1" "$tmp/out-good" || bad "good: serial not printed"
grep -qx "path=$tmp/cache-good/release-$S1/$NAME" "$tmp/out-good" || bad "good: path not printed"
find "$tmp/cache-good" -name '.download*' | grep -q . && bad "good: temporary directory left behind"

# --- the serial selects the directory
want2=$(sha256sum < "$good/release-$S2/$NAME" | cut -d' ' -f1)
[ "$want" != "$want2" ] || bad "the two serials have the same image"
{ grep -qx "sha256=$want2" "$tmp/out-two" && grep -qx "serial=$S2" "$tmp/out-two"; } || bad "serial 2: wrong record"
{ [ "$(rc_of missing-serial)" != 0 ] && grep -q 'release-20300101' "$tmp/err-missing-serial"; } || bad "unpublished serial not named"

# --- cache re-verification
# (c) the cache is reused with no download (the base URL does not exist)
VM_IMAGE_BASE=file://$tmp/nonexistent VM_IMAGE_SERIAL=$S1 VM_IMAGE_KEYRING=$tmp/one.gpg VM_IMAGE_CACHE=$tmp/cache-good "$IMG" > "$tmp/out-c" 2> "$tmp/err-c" \
    || bad "(c) cache hit failed: $(cat "$tmp/err-c")"
cmp -s "$tmp/out-c" "$tmp/out-good" || bad "(c) record differs from the first run"

cp -r "$tmp/cache-good" "$tmp/cache-a"
printf 'X' | dd of="$tmp/cache-a/release-$S1/$NAME" bs=1 seek=2 conv=notrunc 2> /dev/null
cmp -s "$tmp/cache-a/release-$S1/$NAME" "$good/release-$S1/$NAME" && bad "(a) tamper did not change the image"
VM_IMAGE_BASE=file://$good VM_IMAGE_SERIAL=$S1 VM_IMAGE_KEYRING=$tmp/one.gpg VM_IMAGE_CACHE=$tmp/cache-a "$IMG" > "$tmp/out-a" 2> "$tmp/err-a" && bad "(a) tampered image accepted"
grep -q 'checksum mismatch' "$tmp/err-a" || bad "(a) reason: $(cat "$tmp/err-a")"
[ -z "$(find "$tmp/cache-a" -type f)" ] || bad "(a) the tampered image was not removed"

cp -r "$tmp/cache-good" "$tmp/cache-b"
printf '\n' >> "$tmp/cache-b/release-$S1/SHA256SUMS"
VM_IMAGE_BASE=file://$good VM_IMAGE_SERIAL=$S1 VM_IMAGE_KEYRING=$tmp/one.gpg VM_IMAGE_CACHE=$tmp/cache-b "$IMG" > "$tmp/out-b" 2> "$tmp/err-b" && bad "(b) tampered sums accepted"
grep -q 'signature check failed' "$tmp/err-b" || bad "(b) reason: $(cat "$tmp/err-b")"
[ -z "$(find "$tmp/cache-b" -type f)" ] || bad "(b) the cache holds a file"

# --- the cache is outside the repository
export HOME=$tmp/home XDG_CACHE_HOME=$tmp/xdg
mkdir "$HOME"
before=$(git -C "$ROOT" status --porcelain)
out=$(VM_IMAGE_BASE=file://$good VM_IMAGE_SERIAL=$S1 VM_IMAGE_KEYRING=$tmp/one.gpg "$IMG" 2> /dev/null) || bad "default cache run failed"
case $(printf '%s\n' "$out" | sed -n 's/^path=//p') in
"$tmp/xdg/"*) ;;
*) bad "default cache path is not under XDG_CACHE_HOME: $out" ;;
esac
[ "$(git -C "$ROOT" status --porcelain)" = "$before" ] || bad "git status changed"
unset XDG_CACHE_HOME
out=$(VM_IMAGE_BASE=file://$good VM_IMAGE_SERIAL=$S1 VM_IMAGE_KEYRING=$tmp/one.gpg "$IMG" 2> /dev/null) || bad "HOME cache run failed"
case $out in *"path=$tmp/home/.cache/"*) ;; *) bad "HOME cache path wrong: $out" ;; esac
ln -s "$ROOT" "$tmp/rootlink"
for c in "$ROOT/.test-vm-image-cache" "$tmp/rootlink/.test-vm-image-cache" "$ROOT"; do
    rc=0
    VM_IMAGE_BASE=file://$good VM_IMAGE_SERIAL=$S1 VM_IMAGE_KEYRING=$tmp/one.gpg VM_IMAGE_CACHE=$c "$IMG" > /dev/null 2> "$tmp/err-repo" || rc=$?
    { [ "$rc" != 0 ] && grep -q 'inside the repository' "$tmp/err-repo"; } || bad "cache $c inside the repository not refused"
done
[ ! -e "$ROOT/.test-vm-image-cache" ] || { bad "a cache was created in the repository"; rm -rf "$ROOT/.test-vm-image-cache"; }

# --- the test can fail: a copy without the gpgv call accepts the bad-signature and other-key fixtures
mkdir -p "$tmp/mut/e2e/vm"
python3 -I - "$IMG" "$tmp/mut/e2e/vm/image.sh" << 'PY' || bad "mutated copy not built"
import re, sys
s = open(sys.argv[1]).read()
m = re.sub(r'gpgv --quiet[^\n]*\\\n', 'true \\\n', s)
open(sys.argv[2], 'w').write(m)
PY
cmp -s "$IMG" "$tmp/mut/e2e/vm/image.sh" && bad "mutated copy equals the original"
chmod +x "$tmp/mut/e2e/vm/image.sh"
SCRIPT=$tmp/mut/e2e/vm/image.sh
for n in badsig2 other; do run "m$n" "$tmp/c-$n" & done
wait
for n in badsig2 other; do
    [ "$(rc_of "m$n")" = 0 ] || bad "mutant without gpgv still refuses $n (the test would not notice)"
done
SCRIPT=

[ "$fail" = 0 ] || exit 1
echo "test-vm-image: ok"
