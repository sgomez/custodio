#!/usr/bin/env bash
# Tests of scripts/check-snap-sockets.sh (F173) on copies of the shipped files with one fault each: the gate must pass the shipped files, and
# fail, with a message that names the fault, on a second snap, a wrong mode or owner, a socket outside the directory, RuntimeDirectory=, a
# restrictive SocketUser=/SocketGroup=/SocketMode=, a format left out of nfpm.yaml and a seam that reaches the default build.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-snap-sockets.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-check-snap-sockets: $*" >&2; fail=1; }

FILES=(data/tmpfiles.d/custodio-snap.conf data/custodio-firefox.socket data/custodio.service packaging/nfpm.yaml crates/custodiod/Cargo.toml)
fresh() { # NAME: a copy of the files under $tmp/NAME
    local f
    rm -rf "${tmp:?}/$1"
    for f in "${FILES[@]}"; do mkdir -p "$tmp/$1/$(dirname "$f")"; cp "$ROOT/$f" "$tmp/$1/$f"; done
}
"$GATE" >/dev/null 2>&1 || bad "the shipped files fail"
fresh ok
"$GATE" "$tmp/ok" >/dev/null 2>&1 || bad "the copy of the shipped files fails"

expect_fail() { # LABEL FILE SED-EXPRESSION WORD: the gate fails and its message holds WORD
    local out
    fresh case
    sed -i "$3" "$tmp/case/$2"
    if cmp -s "$ROOT/$2" "$tmp/case/$2"; then bad "$1: the fixture changed nothing"; return; fi
    if out=$("$GATE" "$tmp/case" 2>&1); then bad "$1: the gate passed"; return; fi
    grep -q -- "$4" <<< "$out" || bad "$1: the message does not hold '$4': $out"
}
append() { # LABEL FILE LINE WORD
    expect_fail "$1" "$2" "\$a\\
$3" "$4"
}
T=data/tmpfiles.d/custodio-snap.conf
S=data/custodio-firefox.socket
U=data/custodio.service

# A second snap: a second line, a second socket.
append "second snap in tmpfiles" $T 'd /run/snap.chromium/ 0755 root root -' 'exactly one'
append "second snap in tmpfiles (other path)" $T 'd /run/snap.firefox/x 0755 root root -' 'exactly one'
append "second ListenStream" $S 'ListenStream=/run/snap.chromium/custodio.sock' 'exactly one ListenStream'
expect_fail "snap swapped" $S 's|/run/snap.firefox/custodio.sock|/run/snap.chromium/custodio.sock|' 'must listen on'
append "ListenDatagram" $S 'ListenDatagram=/run/snap.firefox/d.sock' 'listener besides'
append "ListenSequentialPacket" $S 'ListenSequentialPacket=/run/snap.firefox/p.sock' 'listener besides'
expect_fail "socket outside the directory" $S 's|ListenStream=.*|ListenStream=/run/custodio.sock|' 'must listen on'
expect_fail "socket in a sub directory" $S 's|ListenStream=.*|ListenStream=/run/snap.firefox/x/custodio.sock|' 'must listen on'
# The directory entry.
expect_fail "mode 0775" $T 's/0755/0775/' 'exactly'
expect_fail "mode 1777" $T 's/0755/1777/' 'exactly'
expect_fail "owner not root" $T 's/root root/custodio custodio/' 'exactly'
expect_fail "group not root" $T 's/0755 root root/0755 root tss/' 'exactly'
expect_fail "type D" $T 's/^d /D /' 'exactly'
expect_fail "type z" $T 's/^d /z /' 'exactly'
expect_fail "path without the slash is another path" $T 's|/run/snap.firefox/|/run/snap.firefox/..|' 'exactly'
expect_fail "other directory" $T 's|/run/snap.firefox/|/run/snap.firefoxx/|' 'exactly'
expect_fail "age field" $T 's/ -$/ 1d/' 'exactly'
# RuntimeDirectory= in the service or the socket.
append "RuntimeDirectory in the service" $U 'RuntimeDirectory=custodio' 'RuntimeDirectory'
append "RuntimeDirectoryPreserve in the service" $U 'RuntimeDirectoryPreserve=yes' 'RuntimeDirectory'
append "RuntimeDirectory in the socket" $S 'RuntimeDirectory=snap.firefox' 'RuntimeDirectory'
append "RuntimeDirectory with spaces" $U 'RuntimeDirectory = snap.firefox' 'RuntimeDirectory'
# The activation.
expect_fail "Accept=yes" $S 's/^Accept=no/Accept=yes/' 'Accept=no'
expect_fail "no Accept" $S '/^Accept=/d' 'Accept=no'
expect_fail "descriptor renamed" $S 's/snap-firefox/snap-chromium/' 'snap-firefox'
expect_fail "descriptor name missing" $S '/^FileDescriptorName=/d' 'snap-firefox'
expect_fail "another service" $S 's/^Service=.*/Service=other.service/' 'custodio.service'
expect_fail "wanted by another target" $S 's/sockets.target/multi-user.target/' 'sockets.target'
# Reachable by any uid.
append "SocketUser" $S 'SocketUser=root' 'SocketUser'
append "SocketGroup" $S 'SocketGroup=tss' 'SocketGroup'
expect_fail "SocketMode 0660" $S 's/^SocketMode=.*/SocketMode=0660/' 'SocketMode'
expect_fail "SocketMode 0600" $S 's/^SocketMode=.*/SocketMode=0600/' 'SocketMode'
fresh case
sed -i 's/^SocketMode=.*/SocketMode=0666/' "$tmp/case/$S"
"$GATE" "$tmp/case" >/dev/null 2>&1 || bad "SocketMode=0666 fails"
fresh case
sed -i '/^SocketMode=/d' "$tmp/case/$S"
"$GATE" "$tmp/case" >/dev/null 2>&1 || bad "a socket without SocketMode= (systemd's 0666) fails"
# Every format ships both files.
N=packaging/nfpm.yaml
expect_fail "socket restricted to deb" $N '/^  - src: data\/custodio-firefox.socket$/{n;n;s/$/\n    packager: deb/}' 'packager'
expect_fail "tmpfiles entry restricted to rpm" $N '/^  - src: data\/tmpfiles.d\/custodio-snap.conf$/{n;n;s/$/\n    packager: rpm/}' 'packager'
expect_fail "socket not shipped" $N '/^  - src: data\/custodio-firefox.socket$/,+2d' 'does not ship'
expect_fail "tmpfiles entry not shipped" $N '/^  - src: data\/tmpfiles.d\/custodio-snap.conf$/,+2d' 'does not ship'
expect_fail "socket at another path" $N 's|/usr/lib/systemd/system/custodio-firefox.socket|/etc/systemd/system/custodio-firefox.socket|' 'does not install'
# The seam of the tests.
C=crates/custodiod/Cargo.toml
append "test-seam in the default features" $C 'default = ["test-seam"]' 'default features'
expect_fail "dev-dependency missing" $C '/^custodiod = /d' 'dev-dependency'
expect_fail "seam enabled for the normal build" $C 's|^zeroize = "1.9.1"|zeroize = "1.9.1"\ncustodiod-seam = { features = ["test-seam"] }|' 'test-seam'
exit "$fail"
