#!/usr/bin/env bash
# The install-time check that the system bus provides ProcessFD (F42, packaging/bus-check.sh), tested as the source and as the scripts
# extracted from real fixture packages (deb preinst, rpm %pre, Arch .INSTALL and the alpm hook script), against: the dev container's
# dbus-daemon (has ProcessFD), a stub bus without it, the same stub with it, a stub that answers an error, no bus, and no query tool.
# The scripts run with dash (the /bin/sh of Debian and Ubuntu) and the Arch ones with bash. The real package tools are in
# test-install-real.sh.
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
bad() { echo "test-bus-check: $*" >&2; fail=1; }

fx_build real 0.1.0 "" none
for fmt in "${FORMATS[@]}"; do fx_scripts real "$fmt" "$BF_DIR/$fmt"; done

real_bus='' with_bus='' without_bus='' error_bus='' absent_bus='' dead_bus='' # set by the bf_ functions
bf_dbus_daemon real_bus
bf_stub without_bus without
bf_stub with_bus with
bf_stub error_bus error
bf_absent absent_bus
bf_dead dead_bus
# A bus that really answers with ProcessFD, so the pass case cannot pass by accident.
busctl --address="$real_bus" call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionCredentials s org.freedesktop.DBus \
    | grep -q '"ProcessFD" h' || bad "the dev container's dbus-daemon does not return ProcessFD"

# SUBJECTS: every way the check runs. "label|shell|file|argument-or-function".
D=$BF_DIR
SUBJECTS=(
    "source-dash|dash|$ROOT/packaging/bus-check.sh|"
    "source-bash|bash|$ROOT/packaging/bus-check.sh|"
    "deb-install|dash|$D/deb/preinst|install"
    "deb-upgrade|dash|$D/deb/preinst|upgrade"
    "rpm-1|dash|$D/rpm/pre|1"
    "rpm-2|dash|$D/rpm/pre|2"
    "arch-install|bash|$D/archlinux/INSTALL|pre_install"
    "arch-upgrade|bash|$D/archlinux/INSTALL|pre_upgrade"
    "alpm-hook|dash|$D/archlinux/hook-check|"
)

# shellcheck disable=SC2016 # the shell that runs these expands $1 and $2
SOURCE_SNIPPET='. "$1"; custodio_bus_check'
# shellcheck disable=SC2016
ARCH_SNIPPET='. "$1"; "$2"'


# subject_cmd SUBJECT: sets CMD to the command line of the subject.
subject_cmd() {
    local label shell file arg
    IFS='|' read -r label shell file arg <<< "$1"
    case $label in
    source-*) CMD=("$shell" -c "$SOURCE_SNIPPET" sh "$file") ;;
    arch-*) CMD=("$shell" -c "$ARCH_SNIPPET" sh "$file" "$arg") ;;
    *) CMD=("$shell" "$file"); [ -z "$arg" ] || CMD+=("$arg") ;;
    esac
}

# run_subject SUBJECT ADDRESS [PATH]: runs it, sets rc and out (stdout and stderr).
run_subject() {
    subject_cmd "$1"
    rc=0
    out=$("${WRAP[@]}" env PATH="$BF_DIR/stubs:${3:-$PATH}" DBUS_SYSTEM_BUS_ADDRESS="$2" "${CMD[@]}" 2>&1) || rc=$?
}

# run_fake_os ID SUBJECT ADDRESS: run_subject with /etc/os-release replaced (debian13 or ubuntu2404) and daemons by those names on PATH.
run_fake_os() {
    # shellcheck disable=SC2016 # the inner shell expands $1 and $@
    WRAP=(unshare --map-root-user --mount sh -c 'mount --bind "$1" /etc/os-release && shift && exec "$@"' sh "$BF_DIR/os-$1")
    run_subject "$2" "$3" "$BF_DIR/names:$PATH"
    WRAP=()
}

# expect LABEL KIND: KIND is pass (exit 0, silent), refuse (non-zero, the message names ProcessFD, docs/install.md, Ubuntu 24.04 and
# dbus-broker), notice (exit 0, says the service refuses to sign, and no refusal) or error (non-zero, says docs/install.md).
expect() {
    local label=$1 kind=$2 word
    case $kind in
    pass) { [ "$rc" -eq 0 ] && [ -z "$out" ]; } || bad "$label: expected a silent pass, got status $rc: $out" ;;
    refuse)
        [ "$rc" -ne 0 ] || bad "$label: expected a refusal, got status 0: $out"
        for word in "does not provide ProcessFD" "docs/install.md" "Ubuntu 24.04" "dbus-broker"; do
            grep -qF -- "$word" <<< "$out" || bad "$label: the refusal lacks '$word': $out"
        done
        ;;
    notice)
        [ "$rc" -eq 0 ] || bad "$label: expected exit 0 with a notice, got status $rc: $out"
        grep -qF "will refuse to sign until a bus with ProcessFD runs" <<< "$out" || bad "$label: no notice: $out"
        if grep -qF "does not provide ProcessFD" <<< "$out"; then bad "$label: the notice case refuses: $out"; fi
        ;;
    error)
        [ "$rc" -ne 0 ] || bad "$label: expected a refusal, got status 0: $out"
        grep -qF "docs/install.md" <<< "$out" || bad "$label: the message does not point to docs/install.md: $out"
        ;;
    esac
}

for subject in "${SUBJECTS[@]}"; do
    label=${subject%%|*}
    run_subject "$subject" "$real_bus"; expect "$label, private dbus-daemon" pass
    run_subject "$subject" "$with_bus"; expect "$label, stub with ProcessFD" pass
    run_subject "$subject" "$without_bus"; expect "$label, stub without ProcessFD" refuse
    run_subject "$subject" "$absent_bus"; expect "$label, socket absent" notice
    run_subject "$subject" "$dead_bus"; expect "$label, nothing listens" notice
    # An error whose text names ProcessFD is not the capability.
    run_subject "$subject" "$error_bus"; expect "$label, bus returns an error" error
    if grep -qF "ProcessFD" <<< "$out" && [ "$rc" -eq 0 ]; then bad "$label: an error naming ProcessFD counted as present"; fi
    # The same with dbus-send only, and with busctl only.
    run_subject "$subject" "$with_bus" "$BF_DIR/path-dbus-send"; expect "$label, dbus-send, with ProcessFD" pass
    run_subject "$subject" "$without_bus" "$BF_DIR/path-dbus-send"; expect "$label, dbus-send, without ProcessFD" refuse
    run_subject "$subject" "$error_bus" "$BF_DIR/path-dbus-send"; expect "$label, dbus-send, error" error
    run_subject "$subject" "$absent_bus" "$BF_DIR/path-dbus-send"; expect "$label, dbus-send, socket absent" notice
    run_subject "$subject" "$dead_bus" "$BF_DIR/path-dbus-send"; expect "$label, dbus-send, nothing listens" notice
    run_subject "$subject" "$with_bus" "$BF_DIR/path-busctl"; expect "$label, busctl, with ProcessFD" pass
    run_subject "$subject" "$without_bus" "$BF_DIR/path-busctl"; expect "$label, busctl, without ProcessFD" refuse
    # A socket but no query tool is refused (never a silent install); no socket and no tool is "no bus".
    run_subject "$subject" "$with_bus" "$BF_DIR/path-none"; expect "$label, socket but no tool" error
    grep -qF "neither busctl nor dbus-send" <<< "$out" || bad "$label: the no-tool message does not name the tools: $out"
    run_subject "$subject" "$absent_bus" "$BF_DIR/path-none"; expect "$label, no socket and no tool" notice
done

# deb: abort-* calls (and any other) do not run the check.
for arg in abort-upgrade abort-install abort-remove; do
    run_subject "deb-$arg|dash|$D/deb/preinst|$arg" "$without_bus"
    { [ "$rc" -eq 0 ] && [ -z "$out" ]; } || bad "deb preinst $arg ran the check: $rc $out"
done

# The address: the production check uses the system bus socket and the variable overrides it. A recording tool stands for the real ones.
for tool in busctl dbus-send; do
    for subject in "${SUBJECTS[@]}"; do
        label=${subject%%|*}
        subject_cmd "$subject"
        : > "$BF_DIR/calls"
        env -u DBUS_SYSTEM_BUS_ADDRESS PATH="$BF_DIR/path-rec-$tool" CALLS="$BF_DIR/calls" "${CMD[@]}" > /dev/null 2>&1 || true
        grep -qF "address=unix:path=/run/dbus/system_bus_socket" "$BF_DIR/calls" \
            || bad "$label, $tool: the default address is not /run/dbus/system_bus_socket: $(cat "$BF_DIR/calls")"
        : > "$BF_DIR/calls"
        env PATH="$BF_DIR/path-rec-$tool" CALLS="$BF_DIR/calls" DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nowhere/x "${CMD[@]}" > /dev/null 2>&1 || true
        grep -qF "address=unix:path=/nowhere/x" "$BF_DIR/calls" || bad "$label, $tool: DBUS_SYSTEM_BUS_ADDRESS does not override the default: $(cat "$BF_DIR/calls")"
        if grep -qF "/run/dbus" "$BF_DIR/calls"; then bad "$label, $tool: the override still reaches the default address"; fi
    done
done

# The capability, not the name: with an os-release that says Debian 13 / Ubuntu 24.04 and daemons named dbus-broker / dbus-daemon on PATH,
# the verdict follows the bus alone.
if bf_fake_os; then
    for subject in "${SUBJECTS[@]}"; do
        label=${subject%%|*}
        for id in debian13 ubuntu2404; do
            run_fake_os "$id" "$subject" "$without_bus"; expect "$label, without ProcessFD, looks like $id" refuse
            run_fake_os "$id" "$subject" "$with_bus"; expect "$label, with ProcessFD, looks like $id" pass
        done
    done
else
    echo "test-bus-check: notice: no mount namespace here, so the os-release cases did not run" >&2
fi
# The check source tests no daemon, release or distribution.
if grep -nE 'os-release|lsb_release|dbus-broker|dbus-daemon|/etc/issue|ubuntu|debian|uname' <(sed -n '/^# >>> /,/^# <<< /p' "$ROOT/packaging/bus-check.sh" | grep -v '^[[:space:]]*printf'); then
    bad "the check names a daemon or a distribution"
fi

# It fails before anything changes: the refused run calls none of the commands the later scripts run, and the check is the first
# thing in each script.
mkdir "$BF_DIR/recorders"
for s in systemd-sysusers systemctl deb-systemd-invoke; do
    # shellcheck disable=SC2016 # the stub expands $CALLS itself
    printf '#!/bin/sh\necho "%s $*" >> "$CALLS"\n' "$s" > "$BF_DIR/recorders/$s"
    chmod +x "$BF_DIR/recorders/$s"
done
for subject in "${SUBJECTS[@]}"; do
    label=${subject%%|*}
    : > "$BF_DIR/calls"
    CALLS="$BF_DIR/calls" run_subject "$subject" "$without_bus" "$BF_DIR/recorders:$PATH"
    [ "$rc" -ne 0 ] || bad "$label: not refused with recorders on PATH"
    [ ! -s "$BF_DIR/calls" ] || bad "$label: a refused run called: $(cat "$BF_DIR/calls")"
done
for f in "$D/deb/preinst" "$D/rpm/pre" "$D/archlinux/hook-check"; do
    first=$(grep -vE '^[[:space:]]*(#|$)' "$f" | sed -n 1,2p | tr '\n' ' ')
    case $first in
    "custodio_bus_check() {"* | "set -e custodio_bus_check() {"*) ;;
    *) bad "$f: the first command is not the check: $first" ;;
    esac
done
for fn in pre_install pre_upgrade; do
    first=$(sed -n "/^function $fn()/,/^}/p" "$D/archlinux/INSTALL" | grep -vE '^[[:space:]]*(#|$)' | sed -n 2p)
    case $first in *"custodio_bus_check() {"*) ;; *) bad "arch $fn: the first command is not the check: $first" ;; esac
done

# The deb and rpm scripts hand the status of the check to the package manager: exit 1, nothing before or after matters.
grep -q 'custodio_bus_check || exit 1' "$D/deb/preinst" || bad "deb preinst does not exit on a refusal"
grep -q 'custodio_bus_check || exit 1' "$D/rpm/pre" || bad "rpm pre does not exit on a refusal"

# The Arch hook aborts and triggers on an upgrade of custodio only.
grep -qx 'AbortOnFail' "$D/archlinux/hook" || bad "the hook has no AbortOnFail"
grep -qx 'When = PreTransaction' "$D/archlinux/hook" || bad "the hook is not a PreTransaction hook"
grep -qx 'Target = custodio' "$D/archlinux/hook" || bad "the hook does not target custodio"
grep -qx 'Exec = /usr/share/libalpm/scripts/custodio-bus-check' "$D/archlinux/hook" || bad "the hook does not run the packaged check"

exit "$fail"
