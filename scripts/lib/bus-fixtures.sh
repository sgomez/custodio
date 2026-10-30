#!/usr/bin/env bash
# Buses and tool directories for the tests of the install-time ProcessFD check (F42). Source it after package-fixtures.sh; it sets BF_DIR.
# A bus is an address (`unix:path=...`) put in the variable named by the first argument.
set -euo pipefail

ROOT=${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
BF_PIDS=()

bf_init() {
    BF_DIR=$(mktemp -d)
    BF_SOCKDIR=$BF_DIR/bus # the sockets of the stub buses
    mkdir "$BF_SOCKDIR"
    local tool dir real
    # Tool directories: a PATH holding the shells and the two tools the check uses, plus none, one or a recording query tool.
    for dir in path-none path-busctl path-dbus-send path-rec-busctl path-rec-dbus-send; do
        mkdir "$BF_DIR/$dir"
        for tool in dash bash sh grep awk; do
            real=$(command -v "$tool") || { echo "bus-fixtures: '$tool' is not installed" >&2; return 1; }
            ln -s "$(readlink -f "$real")" "$BF_DIR/$dir/$tool"
        done
    done
    ln -s "$(command -v busctl)" "$BF_DIR/path-busctl/busctl"
    ln -s "$(command -v dbus-send)" "$BF_DIR/path-dbus-send/dbus-send"
    # Recording tools: they log what the check gives them and behave like a tool that cannot connect.
    # shellcheck disable=SC2016 # the stubs expand $CALLS themselves
    printf '#!/bin/sh\necho "$*" >> "$CALLS"\necho "Failed to connect to bus: No such file or directory" >&2\nexit 1\n' > "$BF_DIR/path-rec-busctl/busctl"
    # shellcheck disable=SC2016
    printf '#!/bin/sh\necho "$* address=$DBUS_SYSTEM_BUS_ADDRESS" >> "$CALLS"\necho "Failed to open connection to \\"system\\" message bus: Failed to connect to socket: No such file or directory" >&2\nexit 1\n' > "$BF_DIR/path-rec-dbus-send/dbus-send"
    chmod +x "$BF_DIR/path-rec-busctl/busctl" "$BF_DIR/path-rec-dbus-send/dbus-send"
}

bf_cleanup() {
    local pid
    for pid in "${BF_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${BF_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    rm -rf "${BF_DIR:?}"
}

bf_wait_for() { # FILE: wait until it exists
    local _
    for _ in $(seq 100); do [ -e "$1" ] && return 0; sleep 0.1; done
    echo "bus-fixtures: $1 did not appear" >&2
    return 1
}

# bf_stub VAR MODE: the stub bus of scripts/lib/stub-bus.py (without | with | error).
bf_stub() {
    local sock="$BF_SOCKDIR/$1.sock"
    python3 -I "$ROOT/scripts/lib/stub-bus.py" "$sock" "$2" "$BF_DIR/$1.ready" &
    BF_PIDS+=("$!")
    bf_wait_for "$BF_DIR/$1.ready"
    printf -v "$1" '%s' "unix:path=$sock"
}

# bf_dbus_daemon VAR: the dbus-daemon of the dev container on a temporary socket.
bf_dbus_daemon() {
    local sock="$BF_SOCKDIR/$1.sock"
    {
        echo '<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"'
        echo ' "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">'
        echo "<busconfig><type>system</type><listen>unix:path=$sock</listen><auth>EXTERNAL</auth>"
        echo '<policy context="default"><allow user="*"/><allow send_destination="*"/><allow own="*"/><allow receive_sender="*"/></policy></busconfig>'
    } > "$BF_DIR/$1.conf"
    dbus-daemon --config-file="$BF_DIR/$1.conf" --nofork --nopidfile &
    BF_PIDS+=("$!")
    bf_wait_for "$sock"
    printf -v "$1" '%s' "unix:path=$sock"
}

# bf_absent VAR: an address whose socket does not exist.
bf_absent() { printf -v "$1" '%s' "unix:path=$BF_SOCKDIR/$1.nosuchsocket"; }

# bf_dead VAR: an address whose socket file exists and nothing listens on.
bf_dead() {
    python3 -I -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$BF_SOCKDIR/$1.sock"
    printf -v "$1" '%s' "unix:path=$BF_SOCKDIR/$1.sock"
}

# bf_fake_os: succeeds when a private mount namespace is available; prepares the files run_fake_os needs.
bf_fake_os() {
    unshare --map-root-user --mount true 2> /dev/null || return 1
    printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\n' > "$BF_DIR/os-debian13"
    printf 'PRETTY_NAME="Ubuntu 24.04 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n' > "$BF_DIR/os-ubuntu2404"
    mkdir -p "$BF_DIR/names"
    printf '#!/bin/sh\necho "dbus-broker 36"\n' > "$BF_DIR/names/dbus-broker"
    printf '#!/bin/sh\necho "D-Bus Message Bus Daemon 1.14.10"\n' > "$BF_DIR/names/dbus-daemon"
    printf '#!/bin/sh\necho "Distributor ID: Ubuntu"\n' > "$BF_DIR/names/lsb_release"
    chmod +x "$BF_DIR/names/"*
}

# bf_mkroot DIR: a small root for the real package tools: dash as sh, grep, awk and busctl with their libraries, the account files
# rpm reads and recorders for the commands the post scripts run. The buses of the stubs are bound at /run/bus by bf_in_root.
bf_mkroot() {
    local r=$1 tool real lib dest
    mkdir -p "$r"/usr/{bin,lib,lib64} "$r"/{run/bus,tmp,var/lib/dpkg/info,var/lib/dpkg/updates,etc,dev,proc}
    ln -sfn usr/bin "$r/bin"
    ln -sfn usr/lib "$r/lib"
    ln -sfn usr/lib64 "$r/lib64" 2> /dev/null || true
    for tool in dash grep awk busctl; do
        real=$(readlink -f "$(type -P "$tool")")
        cp "$real" "$r/usr/bin/$tool"
        for lib in $(ldd "$real" | awk '/=> \//{print $3}'); do
            dest=$r$lib # under the name the loader looks for
            mkdir -p "$(dirname "$dest")"
            cp -L "$lib" "$dest"
        done
    done
    # The loader named in the binaries (PT_INTERP) and the sh link.
    cp -L /lib64/ld-linux-x86-64.so.2 "$r/usr/lib64/ld-linux-x86-64.so.2"
    ln -sf dash "$r/usr/bin/sh"
    : > "$r/var/lib/dpkg/status"
    : > "$r/var/lib/dpkg/available"
    printf 'root:x:0:0:root:/root:/bin/sh\n' > "$r/etc/passwd"
    printf 'root:x:0:\n' > "$r/etc/group"
    for tool in systemd-sysusers systemctl deb-systemd-invoke; do
        printf '#!/bin/sh\necho "%s $*" >> /recorded-calls\n' "$tool" > "$r/usr/bin/$tool"
        chmod +x "$r/usr/bin/$tool"
    done
}

# bf_in_root ROOT COMMAND...: runs the command as root of a user namespace with the stub buses (BF_SOCKDIR) bound at ROOT/run/bus, so
# that the package tools can chroot into ROOT. Fails when the namespace cannot be made.
bf_in_root() {
    local root=$1
    shift
    # shellcheck disable=SC2016 # the inner shell expands $1, $2 and $@
    unshare --map-root-user --mount sh -c 'mount --bind "$1" "$2/run/bus" && shift 2 && exec "$@"' sh "$BF_SOCKDIR" "$root" "$@"
}

# bf_root_address ADDRESS: the same bus as seen from inside the root of bf_in_root (its sockets are at /run/bus).
bf_root_address() { printf 'unix:path=/run/bus/%s' "$(basename "${1#unix:path=}")"; }
