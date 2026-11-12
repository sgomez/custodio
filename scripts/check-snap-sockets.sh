#!/usr/bin/env bash
# The gate of `just snap-sockets` (F173): the shipped tmpfiles entry and socket unit are exactly the Firefox ones, and only Firefox.
#   - data/tmpfiles.d/custodio-snap.conf: one active line, `d /run/snap.firefox/ 0755 root root -`.
#   - data/custodio-firefox.socket: one ListenStream= on /run/snap.firefox/custodio.sock and no other Listen*=, Accept=no, the descriptor
#     name snap-firefox, Service= (when set) custodio.service, reachable by any uid (no SocketUser=/SocketGroup=, SocketMode= 0666 or
#     0777 when set), installed into sockets.target.
#   - neither that unit nor data/custodio.service has RuntimeDirectory= or RuntimeDirectoryPreserve= (the directory comes from tmpfiles.d).
#   - packaging/nfpm.yaml ships both files, without a `packager:` restriction, so every format has them.
#   - the test-seam feature of custodiod (it moves the directory the socket check inspects) is a dev-dependency of the crate only.
# Argument: the root of the tree to check (default: this repository), so the test can check altered copies.
set -euo pipefail

ROOT=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
TMPFILES=$ROOT/data/tmpfiles.d/custodio-snap.conf
SOCKET=$ROOT/data/custodio-firefox.socket
SERVICE=$ROOT/data/custodio.service
NFPM=$ROOT/packaging/nfpm.yaml
CARGO=$ROOT/crates/custodiod/Cargo.toml
fail=0
bad() { echo "check-snap-sockets: $*" >&2; fail=1; }

for f in "$TMPFILES" "$SOCKET" "$SERVICE" "$NFPM" "$CARGO"; do
    [ -f "$f" ] || { bad "$f does not exist"; exit 1; }
done

# Active lines of a unit or tmpfiles file: comments and blank lines dropped, whitespace around '=' and at the ends stripped.
active() { grep -Ev '^[[:space:]]*(#|;|$)' "$1" | sed 's/^[[:space:]]*\([A-Za-z0-9]*\)[[:space:]]*=[[:space:]]*/\1=/; s/[[:space:]]*$//'; }

# ---- tmpfiles.d
lines=$(active "$TMPFILES")
if [ "$(grep -c . <<< "$lines" || true)" != 1 ]; then
    bad "$TMPFILES must have exactly one active line (the Firefox directory, no other snap or path), has: $lines"
fi
norm=$(tr -s ' \t' ' ' <<< "$lines")
[ "$norm" = "d /run/snap.firefox/ 0755 root root -" ] \
    || bad "$TMPFILES must be exactly 'd /run/snap.firefox/ 0755 root root -', is: $norm"

# ---- socket unit
unit=$(active "$SOCKET")
count() { grep -c "$1" <<< "$unit" || true; }
[ "$(count '^ListenStream=')" = 1 ] || bad "$SOCKET must have exactly one ListenStream="
grep -qx 'ListenStream=/run/snap.firefox/custodio.sock' <<< "$unit" \
    || bad "$SOCKET must listen on /run/snap.firefox/custodio.sock and nowhere else"
other=$(grep -E '^Listen[A-Za-z]*=' <<< "$unit" | grep -v '^ListenStream=' || true)
[ -z "$other" ] || bad "$SOCKET has a listener besides the one stream socket: $other"
if [ "$(count '^Accept=')" != 1 ] || ! grep -qx 'Accept=no' <<< "$unit"; then bad "$SOCKET must have a single Accept=no"; fi
if [ "$(count '^FileDescriptorName=')" != 1 ] || ! grep -qx 'FileDescriptorName=snap-firefox' <<< "$unit"; then
    bad "$SOCKET must name its descriptor snap-firefox, once"
fi
service_lines=$(grep -c '^Service=' <<< "$unit" || true)
if [ "$service_lines" != 0 ]; then
    { [ "$service_lines" = 1 ] && grep -qx 'Service=custodio.service' <<< "$unit"; } \
        || bad "$SOCKET must activate custodio.service"
fi
if grep -qE '^Socket(User|Group)=' <<< "$unit"; then
    bad "$SOCKET sets SocketUser= or SocketGroup=: some uid could not connect"
fi
modes=$(grep -c '^SocketMode=' <<< "$unit" || true)
if [ "$modes" != 0 ]; then
    { [ "$modes" = 1 ] && grep -qE '^SocketMode=0?(666|777)$' <<< "$unit"; } \
        || bad "$SOCKET sets a SocketMode= other than 0666: some uid could not connect"
fi
if [ "$(count '^WantedBy=')" != 1 ] || ! grep -qx 'WantedBy=sockets.target' <<< "$unit"; then
    bad "$SOCKET must be installed into sockets.target only"
fi
if ! grep -qx '\[Socket\]' "$SOCKET" || ! grep -qx '\[Install\]' "$SOCKET"; then
    bad "$SOCKET lacks a [Socket] or [Install] section"
fi

# ---- never RuntimeDirectory=
for f in "$SERVICE" "$SOCKET"; do
    if active "$f" | grep -qE '^RuntimeDirectory(Preserve|Mode)?='; then
        bad "$f has RuntimeDirectory= (or its Preserve/Mode): the directory comes from tmpfiles.d, root 0755"
    fi
done

# ---- every format ships both files
# The items of nfpm.yaml's contents: from the `- src:` line to the line before the next item.
item() { awk -v src="$1" '/^  - / { on = ($0 == "  - src: " src) } on' "$NFPM"; }
check_item() { # SRC DST
    local block
    block=$(item "$1")
    if [ -z "$block" ]; then bad "$NFPM does not ship $1"; return; fi
    [ "$(grep -c '^  - src:' <<< "$block" || true)" = 1 ] || bad "$NFPM lists $1 more than once"
    grep -qx "    dst: $2" <<< "$block" || bad "$NFPM does not install $1 at $2"
    if grep -q 'packager:' <<< "$block"; then bad "$NFPM restricts $1 to some formats (packager:); every format ships it"; fi
}
[ "$(grep -c '^  - src: data/tmpfiles.d/custodio-snap.conf$' "$NFPM" || true)" -le 1 ] || bad "$NFPM lists the tmpfiles entry twice"
check_item data/tmpfiles.d/custodio-snap.conf /usr/lib/tmpfiles.d/custodio-snap.conf
check_item data/custodio-firefox.socket /usr/lib/systemd/system/custodio-firefox.socket

# ---- the seam of the tests stays out of the shipped build
if grep -qE '^default[[:space:]]*=' "$CARGO"; then bad "$CARGO sets default features: test-seam must not be among them"; fi
if grep -E 'test-seam' "$CARGO" | grep -vE '^test-seam = \[\]$|^custodiod = \{ path = "\.", features = \["test-seam"\] \}$' | grep -qv '^#'; then
    bad "$CARGO names test-seam anywhere but its definition and the dev-dependency on the crate itself"
fi
in_dev=$(awk '/^\[/ { sec = $0 } sec == "[dev-dependencies]" && /test-seam/' "$CARGO")
[ -n "$in_dev" ] || bad "$CARGO: the dev-dependency that turns test-seam on is missing, so the tests cannot reach the seam"
exit "$fail"
