#!/usr/bin/env bash
# Prints the record of the run as key=value lines: the process that is the system bus (asked of the bus, not read from the
# package list) and its version, and the polkit version. Runs as root in the container after the services are up.
# dbus-broker: the bus names its LAUNCHER (dbus-broker-launch) as its own process (GetConnectionUnixProcessID of
# org.freedesktop.DBus), and the broker itself is the launcher's child; the record names the broker and says what the bus reported.
set -euo pipefail
pid=$(busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus \
    GetConnectionUnixProcessID s org.freedesktop.DBus | awk '$1 == "u" { print $2 }')
[ -n "$pid" ] || { echo "probe: the bus did not report its own pid" >&2; exit 1; }
reported=$(basename "$(readlink "/proc/$pid/exe")")
daemon=$reported
if [ "$reported" = dbus-broker-launch ]; then
    broker=$(pgrep -P "$pid" -x dbus-broker | head -n 1 || true)
    [ -n "$broker" ] || { echo "probe: dbus-broker-launch (pid $pid) has no dbus-broker child" >&2; exit 1; }
    daemon=$(basename "$(readlink "/proc/$broker/exe")")
fi
echo "bus-daemon=$daemon"
echo "bus-daemon-version=$("$daemon" --version | head -n 1)"
echo "bus-reported-process=$reported"
echo "polkit-version=$(pkaction --version | awk '{ print $NF }')"
