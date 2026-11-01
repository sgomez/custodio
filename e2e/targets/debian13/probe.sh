#!/usr/bin/env bash
# Prints the record of the run as key=value lines: the process that is the system bus (asked of the bus, not read from the
# package list) and its version, and the polkit version. Runs as root in the container after the services are up.
set -euo pipefail
pid=$(busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus \
    GetConnectionUnixProcessID s org.freedesktop.DBus | awk '$1 == "u" { print $2 }')
[ -n "$pid" ] || { echo "probe: the bus did not report its own pid" >&2; exit 1; }
daemon=$(basename "$(readlink "/proc/$pid/exe")")
echo "bus-daemon=$daemon"
echo "bus-daemon-version=$("$daemon" --version | head -n 1)"
echo "polkit-version=$(pkaction --version | awk '{ print $NF }')"
