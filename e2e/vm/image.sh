#!/usr/bin/env bash
# Fetches the Ubuntu 26.04 minimal cloud image for the VM target (SPEC Design 1 "Image"), checks Ubuntu's signature on
# SHA256SUMS with gpgv and the image against the signed sums, and only then puts it in a cache outside the repository.
# A cached image is verified again on every use; a failing cache is removed, never silently replaced.
# stdout (on success): `path=...`, `serial=...`, `sha256=...`. Diagnostics go to stderr.
# Pinning: one dated serial (docs/decisions.md). Overrides, used by the self-test: VM_IMAGE_BASE, VM_IMAGE_SERIAL,
# VM_IMAGE_KEYRING, VM_IMAGE_CACHE.
set -euo pipefail

BASE=${VM_IMAGE_BASE:-https://cloud-images.ubuntu.com/minimal/releases/resolute}
SERIAL=${VM_IMAGE_SERIAL:-20261105}
KEYRING=${VM_IMAGE_KEYRING:-/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg}
CACHE=${VM_IMAGE_CACHE:-${XDG_CACHE_HOME:-${HOME:?HOME is not set}/.cache}/custodio/vm-image}
NAME=ubuntu-26.04-minimal-cloudimg-amd64.img
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)

die() { echo "image.sh: $*" >&2; exit 1; }

[[ $SERIAL =~ ^[0-9]{8}$ ]] || die "serial '$SERIAL' is not eight digits"
[ -r "$KEYRING" ] || die "keyring $KEYRING not found (package ubuntu-keyring)"
command -v gpgv > /dev/null || die "gpgv is not installed"

# The cache must not be inside the repository (compared after realpath, so a relative or symlinked path counts).
real_cache=$(realpath -m -- "$CACHE")
case $real_cache/ in
"$ROOT"/*) die "cache directory $CACHE is inside the repository ($ROOT): an image could be committed" ;;
esac

dir=$real_cache/release-$SERIAL
url=$BASE/release-$SERIAL

# verify DIR: the signature on DIR/SHA256SUMS, then DIR/NAME against its line. Sets SUM. Returns non-zero with a reason on stderr.
verify() {
    local d=$1 line
    [ -f "$d/SHA256SUMS" ] || { echo "image.sh: SHA256SUMS missing" >&2; return 1; }
    [ -f "$d/SHA256SUMS.gpg" ] || { echo "image.sh: SHA256SUMS.gpg missing" >&2; return 1; }
    gpgv --quiet --keyring "$KEYRING" "$d/SHA256SUMS.gpg" "$d/SHA256SUMS" 2> /dev/null \
        || { echo "image.sh: signature check failed: SHA256SUMS is not signed by the Ubuntu cloud image keyring" >&2; return 1; }
    line=$(grep -E "^[0-9a-f]{64} [ *]$NAME\$" "$d/SHA256SUMS" || true)
    [ "$(printf '%s' "$line" | grep -c .)" = 1 ] || { echo "image.sh: signed SHA256SUMS has no single line for $NAME" >&2; return 1; }
    [ -f "$d/$NAME" ] || { echo "image.sh: $NAME missing" >&2; return 1; }
    SUM=$(sha256sum -- "$d/$NAME")
    SUM=${SUM%% *}
    [ "$SUM" = "${line%% *}" ] || { echo "image.sh: checksum mismatch: $NAME is not the image the signed SHA256SUMS lists" >&2; return 1; }
}

report() { printf 'path=%s\nserial=%s\nsha256=%s\n' "$dir/$NAME" "$SERIAL" "$SUM"; }

if [ -d "$dir" ]; then
    if verify "$dir"; then
        echo "image.sh: cached image verified" >&2
        report
        exit 0
    fi
    # Only the three known files of this serial's directory (the serial is eight digits), then the directory if empty.
    rm -f -- "$dir/$NAME" "$dir/SHA256SUMS" "$dir/SHA256SUMS.gpg"
    rmdir -- "$dir" 2> /dev/null || true
    die "the cached image failed verification and was removed; run again to download"
fi

mkdir -p -- "$real_cache"
tmp=$(mktemp -d "$real_cache/.download.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
mkdir "$tmp/r"
for f in SHA256SUMS SHA256SUMS.gpg; do
    curl -fsS --retry 2 -o "$tmp/r/$f" "$url/$f" || die "cannot fetch $url/$f (is serial $SERIAL still published?)"
done
# Signature and sums first; the image is fetched only for sums that are signed.
gpgv --quiet --keyring "$KEYRING" "$tmp/r/SHA256SUMS.gpg" "$tmp/r/SHA256SUMS" 2> /dev/null \
    || die "signature check failed: SHA256SUMS is not signed by the Ubuntu cloud image keyring"
curl -fsS --retry 2 -o "$tmp/r/$NAME" "$url/$NAME" || die "cannot fetch $url/$NAME (is serial $SERIAL still published?)"
verify "$tmp/r" || die "downloaded image refused"
mv -- "$tmp/r" "$dir"
echo "image.sh: image verified and cached" >&2
report
