#!/usr/bin/env bash
# The four scriptlets of the .rpm (packaging/rpm/{pre,post,preun,postun}, F44), run one by one in a temporary root with stubbed systemctl,
# systemd-sysusers, journalctl and busctl (scripts/lib/lifecycle-fixtures.sh, shared with the deb test). The real rpm runs them in
# scripts/test-rpm-lifecycle-real.sh. What the stubs cannot cover: a real systemd and bus, a real rpm-ostree, Fedora or Alma (F45 and later).
#
# Mechanisms (named here because the tests prove exactly these):
#   account before unpack: %pre runs systemd-sysusers - (text embedded, see check-sysusers-sync.sh) after the F42 check and before rpm
#       unpacks the bus policy; the rpm has no user() provide, so rpm's own sysusers step does not run before the check. The real test
#       has the stub record whether the policy file existed when it ran.
#   restart on upgrade: %pre ($1 = 2) notes `systemctl is-active` in /run/custodio-restart-after-upgrade; %post ($1 = 2) restarts once,
#       after the reloads, if the marker exists. The old package's %preun/%postun (they run after the new %post) take no part.
#
# The calls each scriptlet makes per argument count (the one place that decides them; every line is a call logged by a stub, in this order,
# and nothing else is logged; BUS is the F42 query). $1 is the number of instances of the package that remain: 1 install, 2 upgrade, 0 erase.
#   %pre 1                 BUS; systemd-sysusers -.   A refusing bus: BUS only, exit 1, no account. A failing systemd-sysusers, or none on
#                          PATH: exit 1 with a message naming it, no marker.
#   %pre 2                 BUS; systemd-sysusers -; systemctl is-active --quiet custodio.service. The marker exists afterwards only if
#                          that said active. (A first installation never writes the marker.)
#   %post 1                systemctl daemon-reload; systemctl reload dbus.service; journalctl --update-catalog.
#   %post 2                the same three; then, only with the marker: systemctl restart custodio.service (once). Failing tools: exit 0.
#   %preun 0               systemctl stop custodio.service
#   %preun 1               nothing (the old package's %preun during an upgrade)
#   %postun 0              systemctl daemon-reload; systemctl reload dbus.service; systemctl is-active --quiet custodio.service and, only
#                          when it says active, systemctl stop custodio.service; then the notice on STDERR (stdout stays empty).
#   %postun 1              nothing (no output either)
# No %posttrans, %pretrans or trigger. No scriptlet enables, starts or presets the unit. None changes, reads, lists or prints anything
# under the state directory; the account is never removed (no userdel, groupdel). Where the deb does the same, the calls are the deb's
# with deb-systemd-invoke read as systemctl (the parity cases below compare them and the notice text).
# Offline (rpm-ostree, chroot, image build): no bus socket, systemctl failing, /run and /var read-only (the "run" and "var" switches of
# lc_run_offline) change no exit status, and the F42 "no bus" notice appears. rpm-ostree runs no erase scriptlet (docs/findings.md), so
# %preun and %postun are offline-tested for dnf in a chroot only.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
# shellcheck source=scripts/lib/bus-fixtures.sh
. "$ROOT/scripts/lib/bus-fixtures.sh"
# shellcheck source=scripts/lib/lifecycle-fixtures.sh
. "$ROOT/scripts/lib/lifecycle-fixtures.sh"

bf_init
trap bf_cleanup EXIT
fail=0
mutant_mode=0
mutant_hit=0
bad() {
    if [ "$mutant_mode" = 1 ]; then mutant_hit=1; else echo "test-rpm-lifecycle: $*" >&2; fail=1; fi
}

SKELETON=$BF_DIR/skeleton
bf_mkroot "$SKELETON"
lc_stubs "$SKELETON"
bf_in_root "$SKELETON" true || { echo "test-rpm-lifecycle: cannot make a user namespace" >&2; exit 1; }

BUS='busctl --address=unix:path=/run/dbus/system_bus_socket call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionCredentials s org.freedesktop.DBus'
ACTIVE='systemctl is-active --quiet custodio.service'
RELOAD=$'systemctl daemon-reload\nsystemctl reload dbus.service'
CATALOG='journalctl --update-catalog'
MARKER=run/custodio-restart-after-upgrade
SRC=$ROOT/packaging/rpm
DEB=$ROOT/packaging/deb

# new_root [none]: a fresh root with a populated state directory (or none) and an account list holding root only.
new_root() {
    # The previous case is done with its root; keeping every one fills a small /tmp (18 MB each).
    if [ -n "${root:-}" ] && [ -d "$root" ]; then chmod -R u+w "$root" 2> /dev/null || true; rm -rf "$root"; fi
    root=$(mktemp -d "$BF_DIR/root.XXXXXX")
    cp -a "$SKELETON/." "$root/"
    mkdir -p "$root/var/lib"
    [ "${1:-}" = none ] || lc_populate "$root"
    before=$(lc_snapshot "$root")
}
# run SCRIPT ARGS...: one scriptlet of $SRC in the current root; resets the call log first. run_offline: the same with read-only /var and /run.
run() {
    lc_reset "$root"
    lc_run "$root" "$SRC/$1" "${@:2}"
    calls=$(lc_calls "$root")
}
run_offline() {
    lc_reset "$root"
    lc_run_offline "$root" "$SRC/$1" "${@:2}"
    calls=$(lc_calls "$root")
}
want_calls() { # LABEL EXPECTED
    [ "$calls" = "$2" ] || bad "$1: calls were:"$'\n'"$calls"$'\n'"expected:"$'\n'"$2"
}
want_ok() { [ "$rc" -eq 0 ] || bad "$1: exit status $rc: $err"; }
# state_intact LABEL: the state directory (if any) is exactly as it was, nothing was created, and no tool was called on its path.
state_intact() {
    local after
    after=$(lc_snapshot "$root")
    [ "$after" = "$before" ] || bad "$1: the state directory changed:"$'\n'"$(diff <(echo "$before") <(echo "$after") || true)"
    [ ! -e "$root/stub/violation" ] || bad "$1: a file tool was called with a path under the state directory: $(cat "$root/fs-calls" 2> /dev/null)"
    if grep -qE '/var/lib/(custodio|private)' <<< "$calls"; then bad "$1: a call names the state directory: $calls"; fi
    if grep -qE '/var/lib/(custodio|private)' "$root/fs-calls" 2> /dev/null; then bad "$1: a file tool names the state directory: $(cat "$root/fs-calls" 2> /dev/null)"; fi
}
no_account_removal() { # LABEL
    if grep -qE '^(userdel|groupdel|deluser|delgroup|usermod) ' <<< "$calls"; then bad "$1: the account was changed: $calls"; fi
    grep -qE '^custodio:' "$root/etc/passwd" || [ ! -e "$root/stub/had-account" ] || bad "$1: the account is gone"
}
no_enable() { # LABEL: never enable, start, preset or mask
    if grep -E '(^| )(enable|start|preset|mask)( |$)' <<< "$calls" > /dev/null; then bad "$1: enable, start or preset was called: $calls"; fi
}
active() { [ -e "$root/stub/active" ]; }
want_notice() { # LABEL: the notice is on stderr and names what SPEC asks for; stdout is empty
    grep -qF '/var/lib/custodio' <<< "$err" || bad "$1: the notice does not name the state directory: $err"
    grep -qF 'destroys the keys for good' <<< "$err" || bad "$1: the notice lacks the warning: $err"
    grep -qF 'still on disk' <<< "$err" || bad "$1: the notice does not say the keys stay: $err"
    grep -qF 'account custodio was kept' <<< "$err" || bad "$1: the notice does not say the account stays: $err"
    [ -z "$out" ] || bad "$1: output on stdout: $out"
}
bus_without_processfd() { lc_bus_without_processfd "$root"; }
bus_down() { lc_bus_down "$root"; }
# normalize: the deb's calls read as the rpm's (deb-systemd-invoke is the deb's systemctl).
normalize() { sed 's/^deb-systemd-invoke /systemctl /; s/ dbus\.service$/ dbus.service/'; }

# shellcheck source=scripts/lib/rpm-lifecycle-parity.sh
. "$ROOT/scripts/lib/rpm-lifecycle-parity.sh"

cases() {
    # ---- install ----
    for populated in yes none; do
        if [ "$populated" = none ]; then new_root none; else new_root; fi
        L="install ($populated state)"
        run pre 1
        want_ok "%pre 1 $L"
        want_calls "%pre 1 $L" "$BUS"$'\n''systemd-sysusers -'
        grep -qx 'u custodio - "Custodio signing service" -' "$root/stub/sysusers-input" 2> /dev/null || bad "%pre 1 $L: sysusers got: $(cat "$root/stub/sysusers-input" 2> /dev/null)"
        grep -q '^custodio:' "$root/etc/passwd" || bad "%pre 1 $L: the account was not created"
        [ ! -e "$root/$MARKER" ] || bad "%pre 1 $L: a marker on a first installation"
        run post 1
        want_ok "%post 1 $L"
        want_calls "%post 1 $L" "$RELOAD"$'\n'"$CATALOG"
        no_enable "%post 1 $L"
        active && bad "%post 1 $L: the service was started"
        state_intact "install ($populated state)"
        if [ "$populated" = none ] && { [ -e "$root/var/lib/custodio" ] || [ -e "$root/var/lib/private" ]; }; then bad "install: the state directory was created"; fi
    done

    # ---- install, account before the reload; the bus policy is not in this root, so only the order of the calls is seen here ----
    new_root none
    lc_reset "$root"
    lc_run "$root" "$SRC/pre" 1
    lc_run "$root" "$SRC/post" 1
    bus_line=$(grep -n '^busctl' "$root/recorded-calls" | head -1 | cut -d: -f1 || true)
    sysusers_line=$(grep -n '^systemd-sysusers' "$root/recorded-calls" | head -1 | cut -d: -f1 || true)
    reload_line=$(grep -n '^systemctl reload dbus' "$root/recorded-calls" | head -1 | cut -d: -f1 || true)
    if [ -z "$bus_line" ] || [ -z "$sysusers_line" ] || [ -z "$reload_line" ] || [ "$bus_line" -ge "$sysusers_line" ] || [ "$sysusers_line" -ge "$reload_line" ]; then
        bad "install: the bus query ($bus_line), the account ($sysusers_line) and the bus reload ($reload_line) are not in that order"
    fi
    [ "$(grep -c '^systemctl daemon-reload' "$root/recorded-calls")" = 1 ] || bad "install: daemon-reload not exactly once"
    [ "$(grep -c '^systemctl reload dbus' "$root/recorded-calls")" = 1 ] || bad "install: the bus reload not exactly once"
    [ "$(grep -c '^journalctl --update-catalog' "$root/recorded-calls")" = 1 ] || bad "install: the catalog update not exactly once"

    # ---- install while the service is already active (a leftover unit): still no marker, no restart ----
    new_root none
    : > "$root/stub/active"
    run pre 1
    want_calls "%pre 1 (active)" "$BUS"$'\n''systemd-sysusers -'
    [ ! -e "$root/$MARKER" ] || bad "%pre 1 (active): a marker on a first installation"
    run post 1
    want_calls "%post 1 (active)" "$RELOAD"$'\n'"$CATALOG"

    # ---- a refusing bus: nothing is changed, not even the account ----
    new_root none
    bus_without_processfd
    for n in 1 2; do
        run pre "$n"
        [ "$rc" -ne 0 ] || bad "%pre $n with a bus without ProcessFD exited 0"
        want_calls "%pre $n with a bus without ProcessFD" "$BUS"
        grep -q '^custodio:' "$root/etc/passwd" && bad "%pre $n with a bus without ProcessFD: an account exists"
        [ ! -e "$root/$MARKER" ] || bad "%pre $n with a bus without ProcessFD: a marker"
        grep -q 'ProcessFD' <<< "$err" || bad "%pre $n with a bus without ProcessFD: the message does not name it: $err"
    done
    state_intact "refusing bus"

    # ---- upgrade over the M1 account, service running: the order of rpm is new %pre, new %post, old %preun, old %postun ----
    new_root
    printf 'custodio:x:996:996:Custodio:/:/usr/sbin/nologin\n' >> "$root/etc/passwd"
    : > "$root/stub/had-account"
    : > "$root/stub/active"
    run pre 2
    want_ok "%pre 2"
    want_calls "%pre 2 (running)" "$BUS"$'\n''systemd-sysusers -'$'\n'"$ACTIVE"
    [ -e "$root/$MARKER" ] || bad "%pre 2: no marker although the service runs"
    grep -c '^custodio:' "$root/etc/passwd" | grep -qx 1 || bad "%pre 2: a second account line"
    grep -q '^custodio:x:996:996:' "$root/etc/passwd" || bad "%pre 2: the uid of custodio changed"
    run post 2
    want_ok "%post 2"
    want_calls "%post 2 (running)" "$RELOAD"$'\n'"$CATALOG"$'\n''systemctl restart custodio.service'
    [ ! -e "$root/$MARKER" ] || bad "%post 2: the marker is still there"
    active || bad "%post 2: the service is not running afterwards"
    no_enable "%post 2"
    run preun 1
    want_ok "%preun 1"
    want_calls "%preun 1" ""
    active || bad "%preun 1: the service was stopped"
    run postun 1
    want_ok "%postun 1"
    want_calls "%postun 1" ""
    [ -z "$out$err" ] || bad "%postun 1 printed: $out$err"
    active || bad "%postun 1: the service was stopped"
    no_account_removal "upgrade"
    state_intact "upgrade (running)"
    # A second %post 2 (the marker is gone): no second restart.
    run post 2
    want_calls "%post 2 again" "$RELOAD"$'\n'"$CATALOG"

    # ---- upgrade, service not running ----
    new_root
    run pre 2
    want_calls "%pre 2 (stopped)" "$BUS"$'\n''systemd-sysusers -'$'\n'"$ACTIVE"
    [ ! -e "$root/$MARKER" ] || bad "%pre 2: a marker although the service is stopped"
    run post 2
    want_ok "%post 2 (stopped)"
    want_calls "%post 2 (stopped)" "$RELOAD"$'\n'"$CATALOG"
    active && bad "%post 2: a stopped service was started"
    state_intact "upgrade (stopped)"

    # ---- %post 2 with no marker and an active service (the %pre did not finish): no restart ----
    new_root
    : > "$root/stub/active"
    run post 2
    want_ok "%post 2 without marker"
    want_calls "%post 2 without marker" "$RELOAD"$'\n'"$CATALOG"
    state_intact "%post 2 without marker"

    # ---- first installation with a stale marker (a failed earlier upgrade): no restart on $1 = 1 ----
    new_root none
    : > "$root/stub/active"
    : > "$root/$MARKER"
    run post 1
    want_calls "%post 1 with a stale marker" "$RELOAD"$'\n'"$CATALOG"
    # ... and a %pre 1 clears it
    run pre 1
    [ ! -e "$root/$MARKER" ] || bad "%pre 1 left a stale marker"

    # ---- failing %pre ----
    new_root none
    : > "$root/stub/fail-sysusers"
    run pre 1
    [ "$rc" -ne 0 ] || bad "%pre with a failing systemd-sysusers exited 0"
    grep -q 'systemd-sysusers' <<< "$err" || bad "%pre with a failing systemd-sysusers printed no message: $err"
    [ ! -e "$root/$MARKER" ] || bad "%pre with a failing systemd-sysusers left a marker"
    new_root none
    rm "$root/usr/bin/systemd-sysusers"
    run pre 1
    [ "$rc" -ne 0 ] || bad "%pre without systemd-sysusers exited 0"
    grep -q 'systemd-sysusers is not installed' <<< "$err" || bad "%pre without systemd-sysusers does not name the tool: $err"
    grep -q '^custodio:' "$root/etc/passwd" && bad "%pre without systemd-sysusers: an account exists"
    want_calls "%pre without systemd-sysusers" "$BUS"
    state_intact "%pre without sysusers"

    # ---- hostile tools: reloads may fail ----
    new_root
    : > "$root/stub/fail"
    : > "$root/stub/active"
    run pre 2
    want_ok "%pre 2 with failing tools"
    run post 2
    want_ok "%post 2 with failing tools"
    run postun 0
    want_ok "%postun 0 with failing tools"
    run preun 0
    want_ok "%preun 0 with failing tools"
    state_intact "failing tools"

    # ---- erase ----
    new_root
    : > "$root/stub/had-account"
    printf 'custodio:x:998:998:Custodio:/:/usr/sbin/nologin\n' >> "$root/etc/passwd"
    : > "$root/stub/active"
    run preun 0
    want_ok "%preun 0"
    want_calls "%preun 0" 'systemctl stop custodio.service'
    active && bad "%preun 0: the service still runs"
    state_intact "%preun 0"
    run postun 0
    want_ok "%postun 0"
    want_calls "%postun 0" "$RELOAD"$'\n'"$ACTIVE"
    want_notice "%postun 0"
    state_intact "erase"
    no_account_removal "erase"
    no_enable "erase"
    active && bad "erase: the service runs afterwards"
    if grep -E '^(rm|chown|chmod|cp|cat) ' "$root/fs-calls" 2> /dev/null | grep -E 'custodio' > /dev/null; then bad "erase: a file tool was called on a custodio path"; fi

    # ---- erase: the service came back between %preun and the removal of the files ----
    new_root
    : > "$root/stub/active"
    run preun 0
    : > "$root/stub/active"
    run postun 0
    want_calls "%postun 0 (reactivated)" "$RELOAD"$'\n'"$ACTIVE"$'\n''systemctl stop custodio.service'
    active && bad "%postun 0: the service runs after the stop"
    state_intact "erase (reactivated)"

    # ---- an upgrade neither stops the service nor prints the notice, whatever the old package left around ----
    new_root
    : > "$root/stub/active"
    : > "$root/$MARKER"
    for spec in "preun 1" "postun 1"; do
        # shellcheck disable=SC2086 # the spec is words
        run $spec
        want_ok "$spec"
        want_calls "$spec" ""
        [ -z "$out$err" ] || bad "$spec printed: $out$err"
        active || bad "$spec: the service was stopped"
        [ -e "$root/$MARKER" ] || bad "$spec: the marker was removed"
        state_intact "$spec"
    done

    # ---- offline: no bus, systemctl failing, /var and /run read-only ----
    for kind in install upgrade; do
        new_root none
        bus_down
        : > "$root/stub/fail"
        n=1; [ "$kind" = install ] || n=2
        run_offline pre "$n"
        want_ok "offline %pre $n"
        grep -q 'no system bus is running' <<< "$err" || bad "offline %pre $n: the no-bus notice is missing: $err"
        grep -q '^custodio:' "$root/etc/passwd" || bad "offline %pre $n: the account was not created"
        run_offline post "$n"
        want_ok "offline %post $n"
        want_calls "offline %post $n" "$RELOAD"$'\n'"$CATALOG"
        run_offline preun 0
        want_ok "offline %preun 0"
        run_offline postun 0
        want_ok "offline %postun 0"
        want_notice "offline %postun 0"
        [ ! -e "$root/$MARKER" ] || bad "offline: a marker"
        state_intact "offline $kind"
    done
    # A running service and a read-only /run: the marker cannot be written, which is not an error (rpm-ostree has no service at all).
    new_root none
    : > "$root/stub/active"
    run_offline pre 2
    want_ok "%pre 2 with a read-only /run"
    [ ! -e "$root/$MARKER" ] || bad "%pre 2 with a read-only /run: a marker"
    grep -q '^custodio:' "$root/etc/passwd" || bad "%pre 2 with a read-only /run: the account was not created"
    run_offline post 2
    want_ok "%post 2 with a read-only /run"
    want_calls "%post 2 with a read-only /run" "$RELOAD"$'\n'"$CATALOG"
    # Failing account creation is still fatal offline.
    new_root none
    bus_down
    : > "$root/stub/fail-sysusers"
    run_offline pre 1
    [ "$rc" -ne 0 ] || bad "offline %pre with a failing systemd-sysusers exited 0"

    parity_cases
}

# ---- the scriptlets as they are ----
cases

# ---- the controls and the mutants: each must be caught by the cases above (they run on every test-scripts, not once by hand) ----
# shellcheck source=scripts/lib/rpm-lifecycle-mutants.sh
. "$ROOT/scripts/lib/rpm-lifecycle-mutants.sh"

exit "$fail"
