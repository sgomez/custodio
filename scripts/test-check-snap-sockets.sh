#!/usr/bin/env bash
# Test of scripts/check-snap-sockets.sh (F173) on copies of the shipped files with one fault each: the gate passes the copy and fails, with a
# message that names the fault, once per rule of the gate.
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
append "second ListenStream" $S 'ListenStream=/run/snap.chromium/custodio.sock' 'exactly one ListenStream'
expect_fail "snap swapped" $S 's|/run/snap.firefox/custodio.sock|/run/snap.chromium/custodio.sock|' 'must listen on'
append "ListenDatagram" $S 'ListenDatagram=/run/snap.firefox/d.sock' 'listener besides'
# The directory entry.
expect_fail "mode 0775" $T 's/0755/0775/' 'exactly'
expect_fail "path without the slash is another path" $T 's|/run/snap.firefox/|/run/snap.firefox/..|' 'exactly'
# RuntimeDirectory= in the service or the socket.
append "RuntimeDirectory in the service" $U 'RuntimeDirectory=custodio' 'RuntimeDirectory'
# The activation.
expect_fail "Accept=yes" $S 's/^Accept=no/Accept=yes/' 'Accept=no'
expect_fail "descriptor renamed" $S 's/snap-firefox/snap-chromium/' 'snap-firefox'
expect_fail "another service" $S 's/^Service=.*/Service=other.service/' 'custodio.service'
expect_fail "wanted by another target" $S 's/sockets.target/multi-user.target/' 'sockets.target'
# Reachable by any uid.
append "SocketUser" $S 'SocketUser=root' 'SocketUser'
expect_fail "SocketMode 0660" $S 's/^SocketMode=.*/SocketMode=0660/' 'SocketMode'
# Every format ships both files.
N=packaging/nfpm.yaml
expect_fail "socket restricted to deb" $N '/^  - src: data\/custodio-firefox.socket$/{n;n;s/$/\n    packager: deb/}' 'packager'
expect_fail "socket not shipped" $N '/^  - src: data\/custodio-firefox.socket$/,+2d' 'does not ship'
expect_fail "socket at another path" $N 's|/usr/lib/systemd/system/custodio-firefox.socket|/etc/systemd/system/custodio-firefox.socket|' 'does not install'
# The seam of the tests.
C=crates/custodiod/Cargo.toml
append "test-seam in the default features" $C 'default = ["test-seam"]' 'default features'
expect_fail "dev-dependency missing" $C '/^custodiod = /d' 'dev-dependency'
expect_fail "seam enabled for the normal build" $C 's|^zeroize = "1.9.1"|zeroize = "1.9.1"\ncustodiod-seam = { features = ["test-seam"] }|' 'test-seam'
exit "$fail"
