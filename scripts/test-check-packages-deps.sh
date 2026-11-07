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
TSS=$ROOT/scripts/check-tss-deps.sh

# tss_elf NAME [SONAME...]: $FX_DIR/NAME, a real executable that needs exactly those sonames besides libc (stub libraries carry the names).
tss_elf() {
    local name=$1 soname dir=$FX_DIR/stubs-$1 args=()
    shift
    command -v cc >/dev/null || { bad "tss_elf: required tool 'cc' is not installed"; return; }
    mkdir -p "$dir"
    echo 'void stub(void) {}' > "$dir/stub.c"
    echo 'int main(void) { return 0; }' > "$dir/main.c"
    for soname in "$@"; do
        cc -shared -o "$dir/$soname" -Wl,-soname,"$soname" "$dir/stub.c"
        args+=("-l:$soname")
    done
    cc -o "$FX_DIR/$name" "$dir/main.c" -L"$dir" -Wl,--no-as-needed -Wl,-rpath,/nonexistent "${args[@]}"
}

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
case_fail rpm-no-systemd rpm: systemd -- dep-del rpm 'systemd >= 257'
case_fail arch-no-systemd arch: systemd -- dep-del archlinux 'systemd>=257'
case_fail rpm-no-p11-kit rpm: p11-kit -- dep-del rpm p11-kit
case_fail arch-no-p11-kit arch: p11-kit -- dep-del archlinux p11-kit
# setpriv (F89): util-linux on rpm and arch. The deb leaves it out because util-linux is Essential there (lintian flags a dependency on
# it), and pkttyagent comes with the polkit package already required on every format.
case_fail rpm-no-util-linux rpm: util-linux -- dep-del rpm util-linux
case_fail arch-no-util-linux arch: util-linux -- dep-del archlinux util-linux
case_fail deb-util-linux deb: util-linux -- dep-add deb util-linux
case_fail deb-no-p11-kit deb: p11-kit -- dep-del deb p11-kit
# The deb's systemd is a Pre-Depends (the preinst runs systemd-sysusers): missing from both fields fails, only in Depends fails, in both
# fails, and the two fields are not mixed up.
case_fail deb-no-systemd deb: Pre-Depends -- predep-del 'systemd (>= 255)'
case_fail deb-systemd-only-in-depends deb: Pre-Depends -- predep-to-depends 'systemd (>= 255)'
case_fail deb-systemd-in-both deb: "in Depends as well" -- dep-add deb 'systemd (>= 255)'
case_fail deb-extra-predepends deb: Pre-Depends -- predep-add dbus-system-bus
case_fail deb-no-bus deb: dbus-system-bus -- dep-del deb dbus-system-bus
case_fail rpm-no-bus rpm: dbus -- dep-set rpm dbus dbus-daemon
case_fail arch-no-bus arch: dbus -- dep-del archlinux dbus

# systemd bounds (F110): deb 255 (ubuntu2404 uses the plain CLI), rpm and Arch 257 (the user-scoped Varlink calls of alma10, fedora44, arch).
case_fail deb-systemd-too-old deb: Pre-Depends -- predep-set 'systemd (>= 255)' 'systemd (>= 254)'
case_fail rpm-systemd-too-old rpm: systemd -- dep-set rpm 'systemd >= 257' 'systemd >= 255'
case_fail arch-systemd-too-old arch: systemd -- dep-set archlinux 'systemd>=257' 'systemd>=255'
case_fail rpm-systemd-unversioned rpm: systemd -- dep-set rpm 'systemd >= 257' systemd
case_fail arch-systemd-unversioned arch: systemd -- dep-set archlinux 'systemd>=257' systemd

# TPM2 Software Stack (F125): each linked library, the dlopen TCTI and the package that creates `tss` is a dependency. On the rpm and Arch
# one package (tpm2-tss) is all of them, so one case per format stands for esys, tctildr, mu and the group.
case_fail deb-no-tss-esys deb: libtss2-esys-3.0.2-0t64 -- dep-del deb libtss2-esys-3.0.2-0t64
case_fail deb-no-tss-tctildr deb: libtss2-tctildr0t64 -- dep-del deb libtss2-tctildr0t64
case_fail deb-no-tss-mu deb: libtss2-mu-4.0.1-0t64 -- dep-del deb libtss2-mu-4.0.1-0t64
case_fail deb-no-tss-tcti-device deb: libtss2-tcti-device0t64 -- dep-del deb libtss2-tcti-device0t64
case_fail deb-no-tss-group deb: tpm-udev -- dep-del deb tpm-udev
case_fail rpm-no-tss rpm: tpm2-tss -- dep-del rpm tpm2-tss
case_fail arch-no-tss arch: tpm2-tss -- dep-del archlinux tpm2-tss

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

# A binary that links the three libraries: the good set passes; the same binary with one dependency gone fails naming the soname's package.
tss_elf custodiod-tss libtss2-esys.so.0 libtss2-tctildr.so.0 libtss2-mu.so.0
cp "$FX_DIR/custodiod-tss" "$FX_DIR/target/release/custodiod"
fx_build tss-good 0.1.0 '' none
gate "$FX_DIR/out/tss-good" "$REAL" || bad "tss good set: the gate failed: $(cat "$FX_DIR/gate.out")"
case_fail tss-deb-no-esys deb: "libtss2-esys.so.0" "libtss2-esys-3.0.2-0t64" -- dep-del deb libtss2-esys-3.0.2-0t64
case_fail tss-rpm-no-tss rpm: "libtss2-mu.so.0" tpm2-tss -- dep-del rpm tpm2-tss
case_fail tss-arch-no-tss arch: "libtss2-mu.so.0" tpm2-tss -- dep-del archlinux tpm2-tss
# A libtss2 soname the table lacks.
tss_elf custodiod-foo libtss2-esys.so.0 libtss2-foo.so.9
cp "$FX_DIR/custodiod-foo" "$FX_DIR/target/release/custodiod"
fx_build tss-unknown 0.1.0 '' none
expect_fail tss-unknown "$FX_DIR/out/tss-unknown" "$REAL" libtss2-foo.so.9 "soname table"
fx_elf_restore

# The lifecycle script set per format.
case_fail deb-no-postinst deb: postinst -- script-del deb postinstall
case_fail deb-no-preinst deb: preinst -- script-del deb preinstall
case_fail deb-no-prerm deb: prerm -- script-del deb preremove
case_fail deb-no-postrm deb: postrm -- script-del deb postremove
case_fail rpm-no-post rpm: post -- script-del rpm postinstall
case_fail rpm-no-pre rpm: pre -- script-del rpm preinstall
case_fail rpm-no-preun rpm: preun -- script-del rpm preremove
case_fail rpm-no-postun rpm: postun -- script-del rpm postremove
case_fail arch-no-post-install arch: post_install -- script-del archlinux postinstall
case_fail arch-no-post-upgrade arch: post_upgrade -- script-del archlinux postupgrade
case_fail arch-no-pre-install arch: pre_install -- script-del archlinux preinstall
case_fail arch-no-pre-upgrade arch: pre_upgrade -- script-del archlinux preupgrade
case_fail arch-no-hook arch: custodio-bus-check.hook -- drop /usr/share/libalpm/hooks/custodio-bus-check.hook
case_fail arch-no-hook-script arch: libalpm/scripts/custodio-bus-check -- drop /usr/share/libalpm/scripts/custodio-bus-check
case_fail hook-in-every-format deb: libalpm -- unpackager /usr/share/libalpm/hooks/custodio-bus-check.hook
case_fail hook-mode arch: custodio-bus-check -- mode /usr/share/libalpm/scripts/custodio-bus-check 0644
case_fail arch-no-post-remove arch: post_remove -- script-del archlinux postremove
case_fail arch-no-pre-remove arch: pre_remove -- script-del archlinux preremove
case_fail arch-no-restart-hook arch: zz-custodio-restart.hook -- drop /usr/share/libalpm/hooks/zz-custodio-restart.hook
case_fail restart-hook-in-every-format deb: libalpm -- unpackager /usr/share/libalpm/hooks/zz-custodio-restart.hook
case_fail restart-hook-mode arch: zz-custodio-restart.hook -- mode /usr/share/libalpm/hooks/zz-custodio-restart.hook 0755

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
# One table: a copy of package_expected.py with one more soname, read by the gate and by check-tss-deps.sh through the same override.
# Both must name the package that only the copy knows; with the real table both name the soname as unknown.
tss_elf custodiod-fapi libtss2-esys.so.0 libtss2-fapi.so.1
TABLE=$FX_DIR/table/package_expected.py
mkdir -p "$FX_DIR/table"
sed 's|^    "libtss2-mu.so.0": (\(.*\)),$|&\n    "libtss2-fapi.so.1": ("libtss2-fapi1t64", "tpm2-tss", "tpm2-tss"),|' "$ROOT/scripts/package_expected.py" > "$TABLE"
grep -qF libtss2-fapi1t64 "$TABLE" || bad "the table copy was not edited"
cp "$FX_DIR/custodiod-fapi" "$FX_DIR/target/release/custodiod"
fx_build table-fapi 0.1.0 '' none
fx_elf_restore
if CUSTODIO_PACKAGE_EXPECTED=$TABLE gate "$FX_DIR/out/table-fapi" "$REAL"; then bad "shared table: the gate passed"; fi
grep -qF libtss2-fapi1t64 "$FX_DIR/gate.out" || bad "shared table: the gate does not name libtss2-fapi1t64: $(cat "$FX_DIR/gate.out")"
if CUSTODIO_PACKAGE_EXPECTED=$TABLE "$TSS" "$FX_DIR/custodiod-fapi" "$REAL" > "$FX_DIR/tss.out" 2>&1; then bad "shared table: check-tss-deps passed"; fi
grep -qF libtss2-fapi1t64 "$FX_DIR/tss.out" || bad "shared table: check-tss-deps does not name libtss2-fapi1t64: $(cat "$FX_DIR/tss.out")"
if "$TSS" "$FX_DIR/custodiod-fapi" "$REAL" > "$FX_DIR/tss.out" 2>&1; then bad "real table: check-tss-deps passed"; fi
grep -qF "libtss2-fapi.so.1 is not in the soname table" "$FX_DIR/tss.out" || bad "real table: unknown soname not named: $(cat "$FX_DIR/tss.out")"

# scripts/check-tss-deps.sh: a soname without its package, per format; exit 1 for a missing dependency, 3 for no libtss2 at all, 2 for bad input.
tss_run() { # LABEL EXPECTED_STATUS NFPM BINARY WORD...
    local label=$1 want=$2 cfg=$3 elf=$4 status=0 word
    shift 4
    "$TSS" "$elf" "$cfg" > "$FX_DIR/tss.out" 2>&1 || status=$?
    [ "$status" -eq "$want" ] || bad "tss $label: exit $status, expected $want: $(cat "$FX_DIR/tss.out")"
    for word in "$@"; do
        grep -qF -- "$word" "$FX_DIR/tss.out" || bad "tss $label: output lacks '$word': $(cat "$FX_DIR/tss.out")"
    done
}
tss_cfg() { python3 -I "$ROOT/scripts/lib/nfpm_edit.py" "$REAL" "$FX_DIR/tss-$1.yaml" "${@:2}"; }
tss_run good 0 "$REAL" "$FX_DIR/custodiod-tss" "3 libtss2 sonames"
tss_cfg deb dep-del deb libtss2-mu-4.0.1-0t64
tss_run deb-no-mu 1 "$FX_DIR/tss-deb.yaml" "$FX_DIR/custodiod-tss" libtss2-mu.so.0 deb libtss2-mu-4.0.1-0t64
tss_cfg rpm dep-del rpm tpm2-tss
tss_run rpm-no-tss 1 "$FX_DIR/tss-rpm.yaml" "$FX_DIR/custodiod-tss" libtss2-esys.so.0 rpm tpm2-tss
tss_cfg arch dep-del archlinux tpm2-tss
tss_run arch-no-tss 1 "$FX_DIR/tss-arch.yaml" "$FX_DIR/custodiod-tss" libtss2-esys.so.0 arch tpm2-tss
tss_run unknown 1 "$REAL" "$FX_DIR/custodiod-foo" libtss2-foo.so.9 "soname table"
tss_elf custodiod-plain
tss_run none 3 "$REAL" "$FX_DIR/custodiod-plain" "needs no libtss2 soname"
grep -qF "does not declare" "$FX_DIR/tss.out" && bad "tss none: reports a missing dependency as well"
tss_run missing-binary 2 "$REAL" "$FX_DIR/no-such-binary" no-such-binary
tss_run missing-config 2 "$FX_DIR/no-such.yaml" "$FX_DIR/custodiod-tss" no-such.yaml
dir=$(make_path readelf)
if PATH=$dir "$BASH_BIN" "$TSS" "$FX_DIR/custodiod-tss" "$REAL" > "$FX_DIR/tss.out" 2>&1; then bad "tss without readelf: passed"; fi
grep -qF "'readelf'" "$FX_DIR/tss.out" || bad "tss without readelf: output does not name the tool: $(cat "$FX_DIR/tss.out")"

# The helper has its own message when a tool is missing after the shell part's check (CHECK_PACKAGES_SKIP_TOOL_CHECK=1 skips that check).
for tool in rpm readelf; do
    dir=$(make_path "$tool")
    if PATH=$dir CHECK_PACKAGES_SKIP_TOOL_CHECK=1 "$BASH_BIN" "$GATE" "$FX_DIR/out/good" "$REAL" > "$FX_DIR/gate.out" 2>&1; then
        bad "$tool (helper): the gate passed"
    fi
    grep -qF "'$tool'" "$FX_DIR/gate.out" || bad "$tool (helper): output does not name the tool: $(cat "$FX_DIR/gate.out")"
done
exit "$fail"
