#!/usr/bin/env bash
# Roots with stub tools for the tests of the deb maintainer scripts (F43). Source it after package-fixtures.sh and bus-fixtures.sh
# (bf_init done). A root is a small directory the scripts run in with chroot (inside a user namespace, as bf_in_root does) or that dpkg
# --root installs into; the stubs record every call, one line each, in /recorded-calls of the root and model a service that is
# active or not, so that "restart only if it was running" can be asserted from the log and from the state afterwards.
#
# Switches (files in the root's /stub, created by the test): active (the service runs), fail (systemctl, deb-systemd-invoke and
# journalctl exit 1), fail-sysusers (systemd-sysusers exits 1), reactivate-once (the next stop is undone, as a D-Bus activation between
# prerm and the removal of the files would do). Outputs the stubs write: policy-at-sysusers ("present" or "absent": whether the bus
# policy was already unpacked when systemd-sysusers ran), sysusers-input (what it read on stdin), violation (a file-changing tool was
# called with a path under the state directory).
set -euo pipefail

STATE_PATTERN='/var/lib/custodio*|/var/lib/private*|var/lib/custodio*|var/lib/private*'

# lc_stubs ROOT: the stateful stubs and the file-tool wrappers in a root made by bf_mkroot.
lc_stubs() {
    local r=$1 tool
    mkdir -p "$r/stub" "$r/scripts"
    cat > "$r/usr/bin/systemctl" <<'STUB'
#!/bin/sh
echo "systemctl $*" >> /recorded-calls
[ ! -e /stub/fail ] || exit 1
case "$1" in
is-active) [ -e /stub/active ] || exit 3 ;;
stop) rm -f /stub/active ;;
start | restart) : > /stub/active ;;
esac
exit 0
STUB
    # deb-systemd-invoke ACTION UNIT: the same model, and the undone stop.
    cat > "$r/usr/bin/deb-systemd-invoke" <<'STUB'
#!/bin/sh
echo "deb-systemd-invoke $*" >> /recorded-calls
[ ! -e /stub/fail ] || exit 1
case "$1:$2" in
stop:custodio.service)
    if [ -e /stub/reactivate-once ]; then rm -f /stub/reactivate-once; else rm -f /stub/active; fi ;;
start:custodio.service | restart:custodio.service) : > /stub/active ;;
esac
exit 0
STUB
    cat > "$r/usr/bin/systemd-sysusers" <<'STUB'
#!/bin/sh
echo "systemd-sysusers $*" >> /recorded-calls
if [ -e /usr/share/dbus-1/system.d/com.rfirma.Custodio1.conf ]; then echo present >> /stub/policy-at-sysusers; else echo absent >> /stub/policy-at-sysusers; fi
: > /stub/sysusers-input
# `-` reads the text from stdin (F43); the M1 postinst named the packaged file, whose text is the same.
if [ "$1" = - ]; then
    while IFS= read -r line; do
        echo "$line" >> /stub/sysusers-input
        set -- $line
        if [ "$1" = u ] && ! grep -q "^$2:" /etc/passwd; then echo "$2:x:998:998:$2:/:/usr/sbin/nologin" >> /etc/passwd; fi
    done
elif ! grep -q '^custodio:' /etc/passwd; then
    echo 'custodio:x:998:998:Custodio:/:/usr/sbin/nologin' >> /etc/passwd
fi
if [ -e /stub/fail-sysusers ]; then echo "systemd-sysusers: stub failure" >&2; exit 1; fi
exit 0
STUB
    # Tools that only record: the journal, the helper the scripts must not need, account removal, and the bus.
    for tool in journalctl deb-systemd-helper userdel groupdel deluser delgroup usermod; do
        printf '#!/bin/sh\necho "%s $*" >> /recorded-calls\n[ ! -e /stub/fail ] || exit 1\n' "$tool" > "$r/usr/bin/$tool"
    done
    cat > "$r/usr/bin/busctl" <<'STUB'
#!/bin/sh
echo "busctl $*" >> /recorded-calls
echo 'a{sv} 2 "UnixUserID" u 0 "ProcessFD" h 3'
STUB
    # File tools: they record in /fs-calls and mark a call with a path under the state directory as a violation. rm really runs;
    # the others are not in the root for real, so a script that needs them fails.
    mv "$r/usr/bin/rm" "$r/usr/bin/rm.real"
    for tool in rm chown chmod chgrp cp cat mv mkdir ln touch tee install; do
        cat > "$r/usr/bin/$tool" <<STUB
#!/bin/sh
echo "$tool \$*" >> /fs-calls
for a in "\$@"; do
    case \$a in
    $STATE_PATTERN) : > /stub/violation ;;
    esac
done
[ ! -x /usr/bin/$tool.real ] || exec /usr/bin/$tool.real "\$@"
exit 0
STUB
    done
    chmod +x "$r"/usr/bin/*
}

# lc_populate ROOT: a state directory as systemd lays it out under DynamicUser= (/var/lib/custodio -> private/custodio) with fixed
# modes, content and times: a key (0600), a hidden file, a symlink, a subdirectory.
lc_populate() {
    local r=$1 d=$1/var/lib/private/custodio
    mkdir -p "$d/sub"
    chmod 700 "$r/var/lib/private" "$d" "$d/sub"
    printf 'PKCS12-key-material-1\n' > "$d/key-1.p12"
    printf 'hidden\n' > "$d/.hidden"
    printf 'nested\n' > "$d/sub/key-2.p12"
    chmod 600 "$d/key-1.p12" "$d/.hidden" "$d/sub/key-2.p12"
    ln -s key-1.p12 "$d/link"
    ln -sfn private/custodio "$r/var/lib/custodio"
    touch -h -d '2026-01-02 03:04:05' "$d/key-1.p12" "$d/.hidden" "$d/sub/key-2.p12" "$d/link" "$d/sub" "$d" "$r/var/lib/private" "$r/var/lib/custodio"
}

# lc_snapshot ROOT: everything under var/lib with type, mode, owner, size, link target, mtime and the hash of each regular file.
lc_snapshot() {
    (
        cd "$1"
        find var/lib -printf '%p\t%y\t%m\t%u:%g\t%s\t%l\t%T@\n' | sort
        find var/lib -type f -exec sha256sum {} + | sort
    )
}

# lc_snapshot_state ROOT: the same for the state directory only (the real one and the symlink to it), for a root where dpkg changes the
# rest of var/lib.
lc_snapshot_state() {
    (
        cd "$1"
        { find var/lib/private var/lib/custodio -printf '%p\t%y\t%m\t%u:%g\t%s\t%l\t%T@\n' 2> /dev/null || true; } | sort
        { find var/lib/private -type f -exec sha256sum {} + 2> /dev/null || true; } | sort
    )
}

# shellcheck disable=SC2034 # rc, out and err are the results the tests read
# lc_run ROOT SCRIPT ARGS...: runs a script file in the root (as root of a user namespace, chrooted, with an empty environment but
# for PATH and the bus address); sets rc, out (stdout) and err (stderr). The script is copied into the root first.
lc_run() {
    local r=$1 script=$2
    shift 2
    cp "$script" "$r/scripts/$(basename "$script")"
    rc=0
    bf_in_root "$r" env -i PATH=/usr/bin DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket \
        "$(command -v chroot)" "$r" /bin/sh "/scripts/$(basename "$script")" "$@" > "$BF_DIR/lc.out" 2> "$BF_DIR/lc.err" || rc=$?
    out=$(cat "$BF_DIR/lc.out")
    err=$(cat "$BF_DIR/lc.err")
}

# lc_calls ROOT: the recorded calls, one per line.
lc_calls() { cat "$1/recorded-calls" 2> /dev/null || true; }
lc_reset() { rm -f "$1/recorded-calls" "$1/fs-calls"; }

# shellcheck disable=SC2034 # rc, out and err are the results the tests read
# lc_run_offline ROOT SCRIPT ARGS...: like lc_run, with the directories named in LC_RO (default "var run") bind-mounted read-only over
# themselves first: what rpm-ostree gives a scriptlet (a read-only /var, a /run without the marker) and an image build on a read-only tree.
lc_run_offline() {
    local r=$1 script=$2
    shift 2
    cp "$script" "$r/scripts/$(basename "$script")"
    rc=0
    # shellcheck disable=SC2016 # the inner shell expands $r, $d and $@
    bf_in_root "$r" sh -c 'r=$1; ro=$2; shift 2; for d in $ro; do mount --bind "$r/$d" "$r/$d" && mount -o remount,ro,bind "$r/$d" || exit 99; done; exec "$@"' \
        sh "$r" "${LC_RO:-var run}" env -i PATH=/usr/bin DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket \
        "$(command -v chroot)" "$r" /bin/sh "/scripts/$(basename "$script")" "$@" > "$BF_DIR/lc.out" 2> "$BF_DIR/lc.err" || rc=$?
    out=$(cat "$BF_DIR/lc.out")
    err=$(cat "$BF_DIR/lc.err")
}

# lc_bus_without_processfd ROOT / lc_bus_down ROOT: replace the busctl stub of the root by a bus that answers without ProcessFD, or by
# one that is not there (the F42 check refuses the first and prints a notice for the second).
lc_bus_without_processfd() {
    printf '#!/bin/sh\necho "busctl $*" >> /recorded-calls\necho "a{sv} 1 \\"UnixUserID\\" u 0"\n' > "$1/usr/bin/busctl"
}
lc_bus_down() {
    printf '#!/bin/sh\necho "busctl $*" >> /recorded-calls\necho "Failed to connect to bus: No such file or directory" >&2\nexit 1\n' > "$1/usr/bin/busctl"
}
