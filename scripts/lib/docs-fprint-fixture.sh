# shellcheck shell=bash disable=SC2016,SC2153
# Fixtures for the docs tests that run `custodio fingerprint` and `custodio doctor` on a documented page (F207). Sourced; the
# caller sets ROOT. The CLI is built with the test-only `fixture-root` feature in its own target directory (so it does not
# replace the binary the other tests use) and every path it touches is under CUSTODIO_FIXTURE_ROOT. Tools the dev container lacks are
# wrappers first on PATH: `sudo` runs `custodio ...` as the fixture's root (CUSTODIO_FIXTURE_EUID=0) and refuses anything else;
# `gsettings` records its arguments in $GS_LOG and accepts only the `set` the document shows (a stand-in: it proves the
# command is the one SPEC Design 5 names, not that GNOME honours it). The fake fprintd is the example docs_fprintd.

FP_TARGET=$ROOT/target/docs-fixture
FP_CLI=$FP_TARGET/debug/custodio-cli
FP_FAKE=$ROOT/target/debug/examples/docs_fprintd

# fp_build NAME: builds the fixture CLI and the fake fprintd.
fp_build() {
    timeout 900 cargo build --quiet --locked -p custodio-cli --features fixture-root --target-dir "$FP_TARGET" \
        || { echo "${1:-test}: cannot build the fixture custodio-cli" >&2; return 1; }
    timeout 900 cargo build --quiet --locked -p custodio-it --example docs_fprintd \
        || { echo "${1:-test}: cannot build docs_fprintd" >&2; return 1; }
}

# fp_wrappers BINDIR: sudo, gsettings and the custodio link.
fp_wrappers() {
    mkdir -p "$1"
    ln -sf "$FP_CLI" "$1/custodio"
    cat > "$1/sudo" << 'W'
#!/bin/sh
[ "$1" = custodio ] || { echo "sudo (test stand-in): only 'sudo custodio ...' is known, not: $*" >&2; exit 1; }
CUSTODIO_FIXTURE_EUID=0 exec "$@"
W
    cat > "$1/gsettings" << 'W'
#!/bin/sh
echo "$*" >> "$GS_LOG"
[ "$*" = "set org.gnome.login-screen enable-fingerprint-authentication false" ] || { echo "gsettings (test stand-in): unknown arguments: $*" >&2; exit 1; }
W
    chmod +x "$1/sudo" "$1/gsettings"
}

# fp_root DIR NAME: (re)creates the fixture root DIR for the system NAME: debian (the default: module, fprintd, no override),
# debian-foreign (someone else's polkit-1), omarchy, global-debian, global-fedora, global-arch (fingerprint on for the whole system),
# nomodule-debian, nomodule-fedora, nomodule-arch, nomodule-ubuntu.
fp_root() {
    local d=$1 name=$2 os=debian lib=usr/lib/x86_64-linux-gnu/security
    rm -rf "${d:?}"
    case $name in
        *fedora) os=fedora lib=usr/lib64/security ;;
        *arch) os=arch lib=usr/lib/security ;;
        omarchy) os=arch lib=usr/lib/security ;;
        *ubuntu) os=ubuntu ;;
    esac
    mkdir -p "$d/etc/pam.d" "$d/usr/lib/pam.d" "$d/usr/share/dbus-1/system-services" "$d/home/person" "$d/etc/systemd"
    echo "ID=$os" > "$d/etc/os-release"
    echo "auth include system-auth" > "$d/usr/lib/pam.d/polkit-1"
    echo "[D-BUS Service]" > "$d/usr/share/dbus-1/system-services/net.reactivated.Fprint.service"
    printf '[Journal]\nStorage=persistent\n' > "$d/etc/systemd/journald.conf"
    case $name in nomodule-*) ;; *) mkdir -p "$d/$lib" && echo module > "$d/$lib/pam_fprintd.so" ;; esac
    case $name in
        debian-foreign) echo "# the administrator's own file" > "$d/etc/pam.d/polkit-1" ;;
        omarchy) printf '#%%PAM-1.0\nauth sufficient pam_fprintd.so\nauth include system-auth\n' > "$d/etc/pam.d/polkit-1" ;;
        global-debian) printf 'auth sufficient pam_fprintd.so\nauth required pam_unix.so\n' > "$d/etc/pam.d/common-auth" ;;
        global-fedora) mkdir -p "$d/etc/authselect" && printf 'sssd\nwith-fingerprint\n' > "$d/etc/authselect/authselect.conf" ;;
        global-arch) printf 'auth sufficient pam_fprintd.so\nauth required pam_unix.so\n' > "$d/etc/pam.d/system-auth" ;;
    esac
}

# fp_tree DIR: a listing of every file under DIR with its mode and hash (what must not change).
fp_tree() { (cd "$1" && find . -mindepth 1 \( -type f -o -type l -o -type d \) -printf '%p %m %y\n' -exec sh -c 'for f; do [ -f "$f" ] && sha256sum "$f"; done' sh {} + | LC_ALL=C sort); }

# fp_bus DIR [FAKE ARGS...]: a private bus with the fake fprintd; sets FP_BUS_PID, FP_FAKE_PID and DBUS_SYSTEM_BUS_ADDRESS.
fp_bus() {
    local d=$1
    shift
    mkdir -p "$d"
    cat > "$d/bus.conf" << CONF
<busconfig>
  <type>session</type>
  <listen>unix:path=$d/bus.sock</listen>
  <auth>EXTERNAL</auth>
  <policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy>
</busconfig>
CONF
    dbus-daemon --config-file="$d/bus.conf" --nofork --print-address=3 3> "$d/address" > /dev/null 2>&1 &
    FP_BUS_PID=$!
    timeout 20 sh -c 'until [ -s "$1" ]; do sleep 0.1; done' _ "$d/address" || return 1
    DBUS_SYSTEM_BUS_ADDRESS=$(head -n 1 "$d/address")
    export DBUS_SYSTEM_BUS_ADDRESS
    "$FP_FAKE" "$DBUS_SYSTEM_BUS_ADDRESS" "$@" > "$d/fake.out" 2> "$d/fake.err" &
    FP_FAKE_PID=$!
    timeout 20 sh -c 'until grep -q ready "$1"; do sleep 0.1; done' _ "$d/fake.out" || return 1
}
fp_bus_stop() { kill "$FP_FAKE_PID" "$FP_BUS_PID" 2> /dev/null || true; wait "$FP_FAKE_PID" "$FP_BUS_PID" 2> /dev/null || true; }
