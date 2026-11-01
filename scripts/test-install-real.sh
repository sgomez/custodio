#!/usr/bin/env bash
# A refusal really stops an installation (F42): the fixture packages (nfpm, the real packaging/ scripts) are installed with the real
# package tools while a stub bus lacks ProcessFD, has it, or is absent.
#   deb: `dpkg --root` into a small root, rpm: `rpm -i --root` into the same kind of root. Both run as root of a user namespace
#        (scripts/lib/bus-fixtures.sh, bf_in_root), so the tools chroot into the root and run the scripts with the root's own sh, grep,
#        awk and busctl. Refused: the tool exits non-zero, prints the message, and no Custodio file and no database entry exist.
#   Arch: `pacman -U` in the Arch image of packaging/lint/namcap.Containerfile (pinned base, rootless podman or docker). Without
#        ProcessFD the first installation warns and succeeds (libalpm ignores the status of pre_install), a reinstall and an
#        upgrade are aborted by the PreTransaction hook and leave files and version unchanged.
# The Arch cases need a container engine and the image; without them the test fails, unless CUSTODIO_SKIP_ARCH_INSTALL=1 is set, which
# skips them with a message (the verify run of the loop does not set it).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
# shellcheck source=scripts/lib/bus-fixtures.sh
. "$ROOT/scripts/lib/bus-fixtures.sh"

fx_init
bf_init
trap 'bf_cleanup; fx_cleanup' EXIT
fail=0
bad() { echo "test-install-real: $*" >&2; fail=1; }

fx_build real 0.1.0 "" none
fx_build next 0.1.1 "" none
without_bus='' with_bus='' absent_bus=''
bf_stub without_bus without
bf_stub with_bus with
bf_absent absent_bus

SKELETON=$BF_DIR/skeleton
bf_mkroot "$SKELETON"
bf_in_root "$SKELETON" true || { echo "test-install-real: cannot make a user namespace for dpkg and rpm" >&2; exit 1; }

# Paths of the package in a root, apart from the package databases.
custodio_files() { find "$1" -mindepth 1 \( -iname '*custodio*' -o -name 'com.rfirma*' \) -not -path "$1/var/lib/*" -not -path "$1/dpkg.log"; }

# install_in_root FORMAT BUS: installs the fixture package into a fresh root; sets root, rc, out.
install_in_root() {
    local fmt=$1 address pkg
    address=$(bf_root_address "$2")
    # The previous case is done with its root; keeping every one fills /tmp (GBs per run).
    if [ -n "${root:-}" ] && [ -d "$root" ]; then chmod -R u+w "$root" 2> /dev/null || true; rm -rf "$root"; fi
    root=$(mktemp -d "$BF_DIR/root.XXXXXX")
    cp -a "$SKELETON/." "$root/"
    rc=0
    case $fmt in
    deb)
        pkg=$(fx_file real deb)
        out=$(bf_in_root "$root" env DBUS_SYSTEM_BUS_ADDRESS="$address" dpkg --root="$root" --log="$root/dpkg.log" --force-depends --force-bad-path \
            --no-triggers -i "$pkg" 2>&1) || rc=$?
        ;;
    rpm)
        pkg=$(fx_file real rpm)
        bf_in_root "$root" rpm --root "$root" --initdb
        out=$(bf_in_root "$root" env DBUS_SYSTEM_BUS_ADDRESS="$address" rpm --root "$root" -i --nodeps --nosignature --nodigest "$pkg" 2>&1) || rc=$?
        ;;
    esac
}

# installed FORMAT ROOT: succeeds when the package manager lists custodio.
installed() {
    case $1 in
    deb) bf_in_root "$2" dpkg --root="$2" -L custodio > /dev/null 2>&1 ;;
    rpm) bf_in_root "$2" rpm --root "$2" -q custodio > /dev/null 2>&1 ;;
    esac
}

expect_install() { # FORMAT BUS-NAME KIND (refused | installed | notice)
    local fmt=$1 name=$2 kind=$3 bus files
    case $name in without) bus=$without_bus ;; with) bus=$with_bus ;; *) bus=$absent_bus ;; esac
    install_in_root "$fmt" "$bus"
    files=$(custodio_files "$root")
    case $kind in
    refused)
        [ "$rc" -ne 0 ] || bad "$fmt, bus $name: the tool exited 0: $out"
        grep -qF "does not provide ProcessFD" <<< "$out" || bad "$fmt, bus $name: the refusal message is not in the output: $out"
        grep -qF "docs/install.md" <<< "$out" || bad "$fmt, bus $name: the output does not point to docs/install.md: $out"
        [ -z "$files" ] || bad "$fmt, bus $name: files exist after the refusal: $files"
        if installed "$fmt" "$root"; then bad "$fmt, bus $name: the package manager lists custodio after the refusal"; fi
        [ ! -e "$root/recorded-calls" ] || bad "$fmt, bus $name: a later script ran: $(cat "$root/recorded-calls")"
        ;;
    installed | notice)
        [ "$rc" -eq 0 ] || bad "$fmt, bus $name: the install failed ($rc): $out"
        if [ ! -x "$root/usr/bin/custodio" ] || [ ! -f "$root/usr/lib/systemd/system/custodio.service" ]; then bad "$fmt, bus $name: the files are missing"; fi
        installed "$fmt" "$root" || bad "$fmt, bus $name: the package manager does not list custodio"
        if grep -qF "does not provide ProcessFD" <<< "$out"; then bad "$fmt, bus $name: a refusal message appears: $out"; fi
        # The post script ran after the check (the recorders are in the root).
        grep -q '^systemctl daemon-reload' "$root/recorded-calls" 2> /dev/null || bad "$fmt, bus $name: the post script did not run"
        if [ "$kind" = notice ]; then
            grep -qF "will refuse to sign until a bus with ProcessFD runs" <<< "$out" || bad "$fmt, bus $name: the notice is not in the output: $out"
        elif grep -qF "will refuse to sign" <<< "$out"; then
            bad "$fmt, bus $name: a notice appears on a bus with ProcessFD: $out"
        fi
        ;;
    esac
    rm -rf "$root"
}

for fmt in deb rpm; do
    expect_install "$fmt" without refused
    expect_install "$fmt" with installed
    expect_install "$fmt" absent notice
done

# An upgrade is refused too: install on a bus with ProcessFD, then upgrade on one without (deb: the new package's preinst gets
# `upgrade`; rpm: %pre gets 2).
upgrade_refused() { # FORMAT
    local fmt=$1 address_with address_without next
    address_with=$(bf_root_address "$with_bus")
    address_without=$(bf_root_address "$without_bus")
    # The previous case is done with its root; keeping every one fills /tmp (GBs per run).
    if [ -n "${root:-}" ] && [ -d "$root" ]; then chmod -R u+w "$root" 2> /dev/null || true; rm -rf "$root"; fi
    root=$(mktemp -d "$BF_DIR/root.XXXXXX")
    cp -a "$SKELETON/." "$root/"
    case $fmt in
    deb)
        bf_in_root "$root" env DBUS_SYSTEM_BUS_ADDRESS="$address_with" dpkg --root="$root" --log="$root/dpkg.log" --force-depends --force-bad-path --no-triggers \
            -i "$(fx_file real deb)" > /dev/null 2>&1 || bad "deb upgrade: the first install failed"
        next=$(fx_file next deb)
        rc=0
        out=$(bf_in_root "$root" env DBUS_SYSTEM_BUS_ADDRESS="$address_without" dpkg --root="$root" --log="$root/dpkg.log" --force-depends --force-bad-path \
            --no-triggers -i "$next" 2>&1) || rc=$?
        version=$(bf_in_root "$root" dpkg-query --admindir="$root/var/lib/dpkg" -W -f "\${Version}" custodio 2> /dev/null || true)
        ;;
    rpm)
        bf_in_root "$root" rpm --root "$root" --initdb
        bf_in_root "$root" env DBUS_SYSTEM_BUS_ADDRESS="$address_with" rpm --root "$root" -i --nodeps --nosignature --nodigest "$(fx_file real rpm)" > /dev/null 2>&1 \
            || bad "rpm upgrade: the first install failed"
        next=$(fx_file next rpm)
        rc=0
        out=$(bf_in_root "$root" env DBUS_SYSTEM_BUS_ADDRESS="$address_without" rpm --root "$root" -U --nodeps --nosignature --nodigest "$next" 2>&1) || rc=$?
        version=$(bf_in_root "$root" rpm --root "$root" -q --qf '%{VERSION}' custodio 2> /dev/null || true)
        ;;
    esac
    [ "$rc" -ne 0 ] || bad "$fmt upgrade: the tool exited 0: $out"
    grep -qF "does not provide ProcessFD" <<< "$out" || bad "$fmt upgrade: no refusal message: $out"
    [ "$version" = "0.1.0-1" ] || [ "$version" = "0.1.0" ] || bad "$fmt upgrade: the installed version is '$version', not the first one"
    [ -x "$root/usr/bin/custodio" ] || bad "$fmt upgrade: the installed files are gone"
    rm -rf "$root"
}
upgrade_refused deb
upgrade_refused rpm

# ---- Arch ----
arch_image() { # prints the image tag, building it when needed; fails with a reason on stderr
    local rt='' pins=$ROOT/packaging/lint/pins.txt base ala namcap tag
    command -v podman > /dev/null && rt=podman
    [ -n "$rt" ] || { command -v docker > /dev/null && rt=docker; }
    [ -n "$rt" ] || { echo "no container engine (podman or docker)" >&2; return 1; }
    base=$(sed -n 's/^base_arch *= *//p' "$pins")
    ala=$(sed -n 's/^namcap_ala_date *= *//p' "$pins")
    namcap=$(sed -n 's/^namcap *= *//p' "$pins")
    tag=custodio-f42-arch:$(cat "$ROOT/packaging/lint/namcap.Containerfile" <(printf '%s\n' "$base" "$ala" "$namcap") | sha256sum | cut -c1-12)
    if ! "$rt" image inspect "$tag" > /dev/null 2>&1; then
        "$rt" build -q -t "$tag" -f "$ROOT/packaging/lint/namcap.Containerfile" --build-arg "BASE=docker.io/library/$base" \
            --build-arg "ALA_DATE=$ala" --build-arg "NAMCAP=$namcap" "$ROOT/packaging/lint" > "$BF_DIR/image-build.log" 2>&1 \
            || { echo "cannot build the Arch image: $(tail -n 3 "$BF_DIR/image-build.log")" >&2; return 1; }
    fi
    printf '%s %s' "$rt" "$tag"
}

# The steps run inside the container: install, reinstall, upgrade; each reports its status, its output, the version and the files.
mkdir "$BF_DIR/arch"
cat > "$BF_DIR/arch/steps.sh" <<'EOF'
#!/bin/sh
step() { # NAME PACKAGE
    pacman -U --noconfirm --disable-sandbox -dd "$2" > "/tmp/$1.out" 2>&1
    echo "RC_$1=$?"
    sed "s/^/OUT_$1: /" "/tmp/$1.out"
    echo "Q_$1=$(pacman -Q custodio 2>&1)"
    echo "SNAP_$1=$(find /usr -iname '*custodio*' -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum | cut -c1-16)"
}
step install /pkg/real/custodio.pkg.tar.zst
step reinstall /pkg/real/custodio.pkg.tar.zst
step upgrade /pkg/next/custodio.pkg.tar.zst
EOF
for n in real next; do mkdir "$BF_DIR/arch/$n"; cp "$(fx_file $n archlinux)" "$BF_DIR/arch/$n/custodio.pkg.tar.zst"; done

field() { sed -n "s/^$2=//p" <<< "$1"; } # RESULT NAME

arch_run() { # BUS-NAME ADDRESS-IN-CONTAINER: sets result
    result=$($rt run --rm --network none --user 0:0 -v "$BF_DIR/arch:/pkg:ro" -v "$BF_SOCKDIR:/bus" -e "DBUS_SYSTEM_BUS_ADDRESS=$2" \
        "$tag" sh /pkg/steps.sh 2>&1) || bad "arch, bus $1: the container run failed: $(tail -n 5 <<< "$result")"
}

if image=$(arch_image 2> "$BF_DIR/arch-why"); then
    read -r rt tag <<< "$image"
    arch_run without "unix:path=/bus/without_bus.sock"
    r=$result
    [ "$(field "$r" RC_install)" = 0 ] || bad "arch, bus without ProcessFD: the first installation did not succeed: $r"
    [ "$(field "$r" Q_install)" = "custodio 0.1.0-1" ] || bad "arch, bus without ProcessFD: the package is not installed after the first installation: $r"
    grep -qF "does not provide ProcessFD" <<< "$r" || bad "arch, bus without ProcessFD: no message on the first installation: $r"
    first=$(field "$r" SNAP_install)
    [ -n "$first" ] || bad "arch: no file snapshot"
    for step in reinstall upgrade; do
        [ "$(field "$r" RC_$step)" != 0 ] || bad "arch, bus without ProcessFD: the $step exited 0: $r"
        [ "$(field "$r" Q_$step)" = "custodio 0.1.0-1" ] || bad "arch, bus without ProcessFD: the version changed on $step: $r"
        [ "$(field "$r" SNAP_$step)" = "$first" ] || bad "arch, bus without ProcessFD: the files changed on $step: $r"
        grep -q "^OUT_$step: .*does not provide ProcessFD" <<< "$r" \
            || bad "arch, bus without ProcessFD: the $step printed no message: $r"
    done
    arch_run with "unix:path=/bus/with_bus.sock"
    r=$result
    for step in install reinstall upgrade; do
        [ "$(field "$r" RC_$step)" = 0 ] || bad "arch, bus with ProcessFD: the $step failed: $r"
    done
    [ "$(field "$r" Q_upgrade)" = "custodio 0.1.1-1" ] || bad "arch, bus with ProcessFD: the upgrade did not install 0.1.1: $r"
    if grep -q "does not provide ProcessFD" <<< "$r"; then bad "arch, bus with ProcessFD: a refusal message appears: $r"; fi
    arch_run absent "unix:path=/bus/nowhere.sock"
    r=$result
    for step in install reinstall upgrade; do
        [ "$(field "$r" RC_$step)" = 0 ] || bad "arch, no bus: the $step failed: $r"
    done
    grep -q "^OUT_install: .*will refuse to sign until a bus with ProcessFD runs" <<< "$r" || bad "arch, no bus: no notice on the first installation: $r"
else
    if [ "${CUSTODIO_SKIP_ARCH_INSTALL:-}" = 1 ]; then
        echo "test-install-real: SKIPPED the Arch (pacman -U) cases: $(cat "$BF_DIR/arch-why") (CUSTODIO_SKIP_ARCH_INSTALL=1)" >&2
    else
        bad "the Arch (pacman -U) cases cannot run: $(cat "$BF_DIR/arch-why"); set CUSTODIO_SKIP_ARCH_INSTALL=1 to skip them"
    fi
fi

exit "$fail"
