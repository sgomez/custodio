#!/usr/bin/env bash
# The dependency part of the package gate (scripts/check-packages.sh), on fixture packages built with nfpm:
# dependency names, NEEDED sonames, the lifecycle script set, versions, and a missing tool for each of six tools.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"

fx_init
trap fx_cleanup EXIT
fail=0
bad() { echo "test-check-packages-deps: $*" >&2; fail=1; }

GATE=$ROOT/scripts/check-packages.sh
REAL=$ROOT/packaging/nfpm.yaml
BASH_BIN=$(command -v bash)

gate() { "$GATE" "$1" "$2" > "$FX_DIR/gate.out" 2>&1; }
expect_fail() { # LABEL DIR CONFIG WORD...
    local label=$1 dir=$2 config=$3 word
    shift 3
    if gate "$dir" "$config"; then bad "$label: the gate passed"; return; fi
    for word in "$@"; do
        grep -qF -- "$word" "$FX_DIR/gate.out" || bad "$label: output lacks '$word': $(cat "$FX_DIR/gate.out")"
    done
}
# case NAME WORD... -- OP [ARG...]: fixture packages built from an edited list; the gate gets those packages and the real list.
case_fail() {
    local name=$1 words=()
    shift
    while [ "$1" != -- ]; do words+=("$1"); shift; done
    shift
    fx_build "$name" 0.1.0 '' "$@"
    expect_fail "$name" "$FX_DIR/out/$name" "$REAL" "${words[@]}"
}

fx_build good 0.1.0 '' none
gate "$FX_DIR/out/good" "$REAL" || bad "good set: the gate failed: $(cat "$FX_DIR/gate.out")"

# Dependency names: exact, and the old ones are gone.
case_fail deb-dbus deb: dbus -- dep-add deb dbus
case_fail deb-polkit-bare deb: polkit -- dep-set deb 'polkitd (>= 124)' polkitd
case_fail deb-polkit-name deb: polkit -- dep-add deb polkit
case_fail rpm-polkit-bare rpm: polkit -- dep-set rpm 'polkit >= 124' polkit
case_fail rpm-polkitd rpm: polkitd -- dep-add rpm polkitd
case_fail arch-polkit-bare arch: polkit -- dep-set archlinux 'polkit>=124' polkit
case_fail arch-polkitd arch: polkitd -- dep-add archlinux polkitd
for dep in systemd p11-kit; do
    case_fail "deb-no-$dep" deb: "$dep" -- dep-del deb "$dep"
    case_fail "rpm-no-$dep" rpm: "$dep" -- dep-del rpm "$dep"
    case_fail "arch-no-$dep" arch: "$dep" -- dep-del archlinux "$dep"
done
case_fail deb-no-bus deb: dbus-system-bus -- dep-del deb dbus-system-bus
case_fail rpm-no-bus rpm: dbus -- dep-set rpm dbus dbus-daemon
case_fail arch-no-bus arch: dbus -- dep-del archlinux dbus

# Every library the binaries link is a dependency; libc and libgcc have no exemption.
case_fail deb-no-libgcc deb: libgcc-s1 -- dep-del deb libgcc-s1
case_fail rpm-no-libgcc rpm: libgcc -- dep-del rpm libgcc
case_fail arch-no-libgcc arch: gcc-libs -- dep-del archlinux gcc-libs
case_fail deb-no-libc deb: libc6 -- dep-del deb libc6
case_fail rpm-no-libc rpm: glibc -- dep-del rpm glibc
case_fail arch-no-libc arch: glibc -- dep-del archlinux glibc
fx_elf_needed libc.so.6 libq.so.6
fx_build needed-unknown 0.1.0 '' none
fx_elf_restore
expect_fail needed-unknown "$FX_DIR/out/needed-unknown" "$REAL" libq.so.6 deb: rpm: arch:

# The lifecycle script set per format.
case_fail deb-no-postinst deb: postinst -- script-del deb postinstall
case_fail deb-preinst deb: preinst -- script-add deb preinstall
case_fail deb-prerm deb: prerm -- script-add deb preremove
case_fail deb-postrm deb: postrm -- script-add deb postremove
case_fail rpm-no-post rpm: post -- script-del rpm postinstall
case_fail rpm-pre rpm: pre -- script-add rpm preinstall
case_fail rpm-preun rpm: preun -- script-add rpm preremove
case_fail rpm-postun rpm: postun -- script-add rpm postremove
case_fail arch-no-post-install arch: post_install -- script-del archlinux postinstall
case_fail arch-no-post-upgrade arch: post_upgrade -- script-del archlinux postupgrade
case_fail arch-pre-install arch: pre_install -- script-add archlinux preinstall
case_fail arch-pre-upgrade arch: pre_upgrade -- script-add archlinux preupgrade
case_fail arch-post-remove arch: post_remove -- script-add archlinux postremove

# Versions: the three formats carry the same version, and a pre-release sorts below its release.
version_of() { # NAME: "deb rpm arch" version-release strings
    local dir=$FX_DIR/out/$1
    printf '%s %s %s' "$(dpkg-deb -f "$dir"/*.deb Version)" "$(fx_rpm -qp --qf '%{VERSION}-%{RELEASE}' "$dir"/*.rpm)" \
        "$(bsdtar -xOf "$dir"/*.pkg.tar.zst .PKGINFO | sed -n 's/^pkgver = //p')"
}
fx_build v010 0.1.0 '' none
fx_build v011 0.1.1 '' none
fx_build v020rc 0.2.0 rc.1 none
fx_build v020 0.2.0 '' none
[ "$(version_of v010)" = '0.1.0-1 0.1.0-1 0.1.0-1' ] || bad "0.1.0 metadata: $(version_of v010)"
[ "$(version_of v020rc)" = '0.2.0~rc.1-1 0.2.0~rc.1-1 0.2.0_rc.1-1' ] || bad "0.2.0-rc.1 metadata: $(version_of v020rc)"
gate "$FX_DIR/out/v020rc" "$REAL" || bad "pre-release set: the gate failed: $(cat "$FX_DIR/gate.out")"
dpkg --compare-versions 0.2.0~rc.1-1 lt 0.2.0-1 || bad "deb: rc.1 does not sort below the release"
dpkg --compare-versions 0.1.0-1 lt 0.1.1-1 || bad "deb: 0.1.0 does not sort below 0.1.1"
[ "$(fx_rpm --eval '%{lua:print(rpm.vercmp("0.2.0~rc.1-1","0.2.0-1"))}')" = -1 ] || bad "rpm: rc.1 does not sort below the release"
[ "$(fx_rpm --eval '%{lua:print(rpm.vercmp("0.1.0-1","0.1.1-1"))}')" = -1 ] || bad "rpm: 0.1.0 does not sort below 0.1.1"
fx_mix ver-mix v010 archlinux v011
expect_fail version-mismatch "$FX_DIR/out/ver-mix" "$REAL" versions

# A missing tool: PATH holds symlinks to every tool but the one under test; the others must still resolve.
tools=(bash sh env dirname mktemp rm mkdir grep cat ls tar sed head sort wc id gzip xz zstd python3 dpkg-deb dpkg-split rpm bsdtar readelf nfpm)
make_path() { # TOOL: directory with every tool but TOOL
    local dir=$FX_DIR/path-$1 t
    mkdir -p "$dir"
    for t in "${tools[@]}"; do
        [ "$t" = "$1" ] || ! command -v "$t" >/dev/null || ln -sf "$(command -v "$t")" "$dir/$t"
    done
    echo "$dir"
}
for tool in nfpm dpkg-deb rpm bsdtar readelf python3; do
    dir=$(make_path "$tool")
    for other in nfpm dpkg-deb rpm bsdtar readelf python3; do
        [ "$other" = "$tool" ] || PATH=$dir command -v "$other" >/dev/null || bad "$tool: $other does not resolve in the test PATH"
    done
    ! PATH=$dir command -v "$tool" >/dev/null || bad "$tool: still resolves in the test PATH"
    if [ "$tool" = nfpm ]; then
        # The fixture library is what builds packages, so it is the part that needs nfpm.
        # shellcheck disable=SC2016 # the inner shell expands $ROOT
        if PATH=$dir ROOT=$ROOT "$BASH_BIN" -c '. "$ROOT/scripts/lib/package-fixtures.sh"; fx_init' > "$FX_DIR/gate.out" 2>&1; then
            bad "nfpm: the fixture library passed"
        fi
    else
        if PATH=$dir "$BASH_BIN" "$GATE" "$FX_DIR/out/good" "$REAL" > "$FX_DIR/gate.out" 2>&1; then bad "$tool: the gate passed"; fi
    fi
    grep -qF "'$tool'" "$FX_DIR/gate.out" || bad "$tool: output does not name the tool: $(cat "$FX_DIR/gate.out")"
done
# The helper has its own message when a tool is missing after the shell part's check (CHECK_PACKAGES_SKIP_TOOL_CHECK=1 skips that check).
for tool in rpm readelf; do
    dir=$(make_path "$tool")
    if PATH=$dir CHECK_PACKAGES_SKIP_TOOL_CHECK=1 "$BASH_BIN" "$GATE" "$FX_DIR/out/good" "$REAL" > "$FX_DIR/gate.out" 2>&1; then
        bad "$tool (helper): the gate passed"
    fi
    grep -qF "'$tool'" "$FX_DIR/gate.out" || bad "$tool (helper): output does not name the tool: $(cat "$FX_DIR/gate.out")"
done
exit "$fail"
