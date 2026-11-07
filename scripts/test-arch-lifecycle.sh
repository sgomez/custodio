#!/usr/bin/env bash
# The six install-script functions of the Arch package (packaging/arch/{pre_install,pre_upgrade,post_install,post_upgrade,pre_remove,post_remove},
# F58) and its restart hook (zz-custodio-restart.hook), run one by one in a temporary root with stubbed systemctl, systemd-sysusers,
# journalctl, busctl and systemd-hook (scripts/lib/lifecycle-fixtures.sh, shared with the deb and rpm tests). The real pacman runs them in
# scripts/test-arch-lifecycle-real.sh. What the stubs cannot cover: a real running systemd and bus, and pacman's own order of scripts and hooks
# (the real test records it with sequence numbers); a real Arch system is F45 and later.
#
# What the hooks of systemd and dbus already do (docs/findings/F58.md; docs/decisions.md) is NOT done by these scripts, so no call below is
# daemon-reload, the bus reload or the catalog update: 30-systemd-daemon-reload-system, dbus-reload and 25-systemd-catalog each do theirs once
# for the unit, the bus policy and the catalog, on install, upgrade and removal, after the scripts. The account is created in pre_*: the
# sysusers hook runs after the files, too late for the bus policy.
#
# The calls each script makes (the one place that decides them; each line is a call logged by a stub, in this order, nothing else is logged;
# BUS is the F42 query). pacman runs pre_install for a first installation and pre_upgrade for an upgrade or reinstall of the new package only;
# the old package's scripts never run on an upgrade, and pre_remove/post_remove run only for a real removal (so no case below calls them with
# "upgrade semantics": pacman never does).
#   pre_install, pre_upgrade   BUS; systemd-sysusers -.  Exit 0. A bus without ProcessFD, or a failing systemd-sysusers, or none on PATH:
#                              the account is still created (the installation goes on whatever the status), the messages are on stderr, exit 1
#                              (also when both fail). Only the embedded check function equals packaging/bus-check.sh.
#   post_install, post_upgrade nothing: no call, no output, no file changed, exit 0 (the hooks do it).
#   pre_remove                 systemctl stop custodio.service. Exit 0 even when systemctl fails.
#   post_remove                systemctl is-active --quiet custodio.service and, only when it says active, systemctl stop custodio.service;
#                              then the notice on STDERR (stdout stays empty). Exit 0.
#   zz-custodio-restart.hook   (PostTransaction, Operation Upgrade only, Target custodio) systemd-hook restart custodio.service, which is
#                              systemctl try-restart: the stub restarts the service only if it is active. The hook never fires on a first
#                              installation or a removal (the Trigger is read from the file), and its name sorts after dbus-reload.hook.
# No script enables, starts, restarts or presets the unit. None changes, reads, lists or prints anything under the state directory; the account
# is never removed (no userdel, groupdel). The failed-check path of pre_upgrade is stub-only: in a real upgrade the PreTransaction hook
# aborts before pre_upgrade runs (scripts/test-install-real.sh), so pre_upgrade sees a refusing bus only on a reinstall without the hook.
# Offline (chroot, image build): no bus socket, systemctl failing, /run and /var read-only change no exit status of the post and remove scripts.
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
    if [ "$mutant_mode" = 1 ]; then mutant_hit=1; else echo "test-arch-lifecycle: $*" >&2; fail=1; fi
}

SKELETON=$BF_DIR/skeleton
bf_mkroot "$SKELETON"
lc_stubs "$SKELETON"
# systemctl with try-restart (restarts only an active service; /stub/restarts has one line per restart) and the systemd-hook of Arch's systemd.
cat > "$SKELETON/usr/bin/systemctl" <<'STUB'
#!/bin/sh
echo "systemctl $*" >> /recorded-calls
[ ! -e /stub/fail ] || exit 1
case "$1" in
is-active) [ -e /stub/active ] || exit 3 ;;
stop) rm -f /stub/active ;;
start) : > /stub/active; echo start >> /stub/starts ;;
restart) : > /stub/active; echo restart >> /stub/restarts ;;
try-restart) if [ -e /stub/active ]; then echo restart >> /stub/restarts; fi ;;
esac
exit 0
STUB
# Account tools other than systemd-sysusers: recorded, so that a fallback shows in the calls.
for tool in useradd adduser groupadd; do printf '#!/bin/sh\necho "%s $*" >> /recorded-calls\nexit 1\n' "$tool" > "$SKELETON/usr/bin/$tool"; chmod +x "$SKELETON/usr/bin/$tool"; done
mkdir -p "$SKELETON/usr/share/libalpm/scripts"
cat > "$SKELETON/usr/share/libalpm/scripts/systemd-hook" <<'STUB'
#!/bin/sh
echo "systemd-hook $*" >> /recorded-calls
op=$1; shift
case "$op" in
restart) exec systemctl try-restart "$@" ;;
*) exit 1 ;;
esac
STUB
chmod +x "$SKELETON/usr/bin/systemctl" "$SKELETON/usr/share/libalpm/scripts/systemd-hook"
bf_in_root "$SKELETON" true || { echo "test-arch-lifecycle: cannot make a user namespace" >&2; exit 1; }

BUS='busctl --address=unix:path=/run/dbus/system_bus_socket call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionCredentials s org.freedesktop.DBus'
SYSUSERS='systemd-sysusers -'
ACTIVE='systemctl is-active --quiet custodio.service'
RESTART_HOOK=$'systemd-hook restart custodio.service\nsystemctl try-restart custodio.service'
SRC=$ROOT/packaging/arch
HOOK=zz-custodio-restart.hook

# shellcheck source=scripts/lib/arch-lifecycle-helpers.sh
. "$ROOT/scripts/lib/arch-lifecycle-helpers.sh"

cases() {
    # ---- first installation ----
    for populated in yes none; do
        if [ "$populated" = none ]; then new_root none; else new_root; fi
        L="install ($populated state)"
        run pre_install
        want_ok "pre_install $L"
        want_calls "pre_install $L" "$BUS"$'\n'"$SYSUSERS"
        grep -qx 'u custodio - "Custodio signing service" -' "$root/stub/sysusers-input" 2> /dev/null || bad "pre_install $L: sysusers got: $(cat "$root/stub/sysusers-input" 2> /dev/null)"
        grep -q '^custodio:' "$root/etc/passwd" || bad "pre_install $L: the account was not created"
        [ -z "$out" ] || bad "pre_install $L: output on stdout: $out"
        snap=$(root_snapshot)
        run post_install
        want_ok "post_install $L"
        want_calls "post_install $L" ""
        [ -z "$out$err" ] || bad "post_install $L printed: $out$err"
        [ "$(root_snapshot)" = "$snap" ] || bad "post_install $L changed files"
        [ ! -e "$root/fs-calls" ] || bad "post_install $L called a file tool: $(cat "$root/fs-calls")"
        no_enable "post_install $L"
        active && bad "post_install $L: the service was started"
        state_intact "install ($populated state)"
        if [ "$populated" = none ] && { [ -e "$root/var/lib/custodio" ] || [ -e "$root/var/lib/private" ]; }; then bad "install: the state directory was created"; fi
    done

    # ---- the account is made before anything else that changes the system; the bus query comes first ----
    new_root none
    run pre_install
    [ "$(grep -n '^busctl' <<< "$calls" | head -1 | cut -d: -f1)" = 1 ] || bad "pre_install: the bus query is not the first call"
    [ "$(grep -c '^systemd-sysusers' <<< "$calls")" = 1 ] || bad "pre_install: the account is not created exactly once"

    # ---- install while the service is already active (a leftover unit): the scripts do not restart, and the hook is not for installs ----
    new_root none
    : > "$root/stub/active"
    run pre_install
    run post_install
    want_calls "post_install (active)" ""
    [ "$(restarts)" = 0 ] || bad "install with an active service restarted it"

    # ---- a refusing bus: the installation goes on, so the account is made anyway; the status is the check's ----
    for s in pre_install pre_upgrade; do
        new_root none
        bus_without_processfd
        run "$s"
        [ "$rc" -eq 1 ] || bad "$s with a bus without ProcessFD exited $rc, not 1"
        want_calls "$s with a bus without ProcessFD" "$BUS"$'\n'"$SYSUSERS"
        grep -q '^custodio:' "$root/etc/passwd" || bad "$s with a bus without ProcessFD: no account"
        grep -q 'does not provide ProcessFD' <<< "$err" || bad "$s with a bus without ProcessFD: the message does not name it: $err"
        grep -q 'pacman ignores a failing pre-install script' <<< "$err" || bad "$s with a bus without ProcessFD: no note that the installation goes on: $err"
        state_intact "$s refusing bus"
        # ... and both failing: still the account attempt, both messages, exit 1
        new_root none
        bus_without_processfd
        : > "$root/stub/fail-sysusers"
        run "$s"
        [ "$rc" -eq 1 ] || bad "$s with both failing exited $rc, not 1"
        grep -q 'does not provide ProcessFD' <<< "$err" || bad "$s with both failing: no bus message: $err"
        grep -q 'systemd-sysusers failed' <<< "$err" || bad "$s with both failing: no account message: $err"
        want_calls "$s with both failing" "$BUS"$'\n'"$SYSUSERS"
        # ... a missing tool and a refusing bus
        new_root none
        bus_without_processfd
        rm "$root/usr/bin/systemd-sysusers"
        run "$s"
        [ "$rc" -eq 1 ] || bad "$s with a refusing bus and no systemd-sysusers exited $rc, not 1"
        grep -q 'systemd-sysusers is not installed' <<< "$err" || bad "$s with a refusing bus and no systemd-sysusers: $err"
    done

    # ---- account failure is loud and has no fallback ----
    for s in pre_install pre_upgrade; do
        new_root none
        : > "$root/stub/fail-sysusers"
        run "$s"
        [ "$rc" -eq 1 ] || bad "$s with a failing systemd-sysusers exited $rc, not 1"
        grep -q 'systemd-sysusers failed' <<< "$err" || bad "$s with a failing systemd-sysusers printed no message naming it: $err"
        new_root none
        rm "$root/usr/bin/systemd-sysusers"
        run "$s"
        [ "$rc" -eq 1 ] || bad "$s without systemd-sysusers exited $rc, not 1"
        grep -q 'systemd-sysusers is not installed' <<< "$err" || bad "$s without systemd-sysusers does not name the tool: $err"
        grep -q '^custodio:' "$root/etc/passwd" && bad "$s without systemd-sysusers: an account exists"
        want_calls "$s without systemd-sysusers" "$BUS"
        if grep -qE '(^| )(useradd|adduser|groupadd)( |$)' <<< "$calls"; then bad "$s without systemd-sysusers: a fallback account tool was called"; fi
        state_intact "$s without sysusers"
    done

    # ---- a refusing bus on the first installation never touches anything else ----
    new_root none
    bus_down
    run pre_install
    want_ok "pre_install without a bus"
    grep -q 'no system bus is running' <<< "$err" || bad "pre_install without a bus: the notice is missing: $err"
    grep -q '^custodio:' "$root/etc/passwd" || bad "pre_install without a bus: no account"

    # ---- upgrade over the M1 account, service running: pre_upgrade, post_upgrade, then the hook ----
    new_root
    printf 'custodio:x:996:996:Custodio:/:/usr/sbin/nologin\n' >> "$root/etc/passwd"
    : > "$root/stub/had-account"
    : > "$root/stub/active"
    run pre_upgrade
    want_ok "pre_upgrade"
    want_calls "pre_upgrade (running)" "$BUS"$'\n'"$SYSUSERS"
    grep -c '^custodio:' "$root/etc/passwd" | grep -qx 1 || bad "pre_upgrade: a second account line"
    grep -q '^custodio:x:996:996:' "$root/etc/passwd" || bad "pre_upgrade: the uid of custodio changed"
    active || bad "pre_upgrade: the service was stopped"
    run post_upgrade
    want_ok "post_upgrade"
    want_calls "post_upgrade (running)" ""
    [ -z "$out$err" ] || bad "post_upgrade printed: $out$err"
    [ "$(restarts)" = 0 ] || bad "post_upgrade restarted the service (the hook does, after both reloads)"
    run_hook
    want_ok "restart hook (running)"
    want_calls "restart hook (running)" "$RESTART_HOOK"
    [ "$(restarts)" = 1 ] || bad "the hook restarted the running service $(restarts) times"
    active || bad "the hook left the service stopped"
    no_account_removal "upgrade"
    state_intact "upgrade (running)"
    ! grep -qE '(^| )(stop|start)( |$)' <<< "$calls" || bad "upgrade: stop or start was called: $calls"

    # ---- upgrade, service not running: the hook's try-restart leaves it alone ----
    new_root
    run pre_upgrade
    want_calls "pre_upgrade (stopped)" "$BUS"$'\n'"$SYSUSERS"
    run post_upgrade
    want_calls "post_upgrade (stopped)" ""
    run_hook
    want_ok "restart hook (stopped)"
    [ "$(restarts)" = 0 ] || bad "the hook restarted a stopped service"
    [ ! -e "$root/stub/starts" ] || bad "the hook started a stopped service"
    active && bad "the hook left a stopped service running"
    state_intact "upgrade (stopped)"

    # ---- the hook file: its trigger and its place in pacman's order (read from the file) ----
    msg=$(hook_ok "$HOOK" "$SRC/$HOOK") || bad "the restart hook is not as decided: $msg"

    # ---- hostile tools: the post scripts and pre_remove exit 0 whatever systemctl says ----
    new_root
    : > "$root/stub/fail"
    : > "$root/stub/active"
    for s in post_install post_upgrade pre_remove post_remove; do
        run "$s"
        want_ok "$s with failing tools"
    done
    state_intact "failing tools"

    # ---- removal ----
    new_root
    : > "$root/stub/had-account"
    printf 'custodio:x:998:998:Custodio:/:/usr/sbin/nologin\n' >> "$root/etc/passwd"
    : > "$root/stub/active"
    run pre_remove
    want_ok "pre_remove"
    want_calls "pre_remove" 'systemctl stop custodio.service'
    active && bad "pre_remove: the service still runs"
    state_intact "pre_remove"
    run post_remove
    want_ok "post_remove"
    want_calls "post_remove" "$ACTIVE"
    want_notice "post_remove"
    state_intact "remove"
    no_account_removal "remove"
    no_enable "remove"
    active && bad "remove: the service runs afterwards"
    if grep -E '^(rm|chown|chmod|cp|cat) ' "$root/fs-calls" 2> /dev/null | grep -E 'custodio' > /dev/null; then bad "remove: a file tool was called on a custodio path"; fi

    # ---- removal: the service came back between pre_remove and the removal of the files ----
    new_root
    : > "$root/stub/active"
    run pre_remove
    : > "$root/stub/active"
    run post_remove
    want_calls "post_remove (reactivated)" "$ACTIVE"$'\n''systemctl stop custodio.service'
    active && bad "post_remove: the service runs after the stop"
    want_notice "post_remove (reactivated)"
    state_intact "remove (reactivated)"

    # ---- removal without a state directory: nothing is created ----
    new_root none
    run pre_remove
    run post_remove
    want_notice "post_remove (no state)"
    state_intact "remove (no state)"
    if [ -e "$root/var/lib/custodio" ] || [ -e "$root/var/lib/private" ]; then bad "remove: the state directory was created"; fi

    # ---- the notice is the one of the deb and of the rpm, byte for byte (stderr of the rpm scriptlet in an equal root) ----
    new_root
    lc_reset "$root"
    lc_run "$root" "$ROOT/packaging/rpm/postun" 0
    rpm_err=$err
    new_root
    run post_remove
    [ "$err" = "$rpm_err" ] || bad "parity: the notice differs from the rpm postun:"$'\n'"$err"$'\n'"$rpm_err"
    [ "$(notice_of "$SRC/post_remove")" = "$(notice_of "$ROOT/packaging/deb/postrm")" ] || bad "parity: the notice differs from the deb postrm"
    [ "$(notice_of "$SRC/post_remove")" = "$(notice_of "$ROOT/packaging/rpm/postun")" ] || bad "parity: the notice differs from the rpm postun"
    [ "$(notice_of "$SRC/post_remove" | wc -l)" = 3 ] || bad "parity: the notice is not three lines"

    # ---- offline: no bus, systemctl failing, /var and /run read-only ----
    for kind in install upgrade; do
        new_root none
        bus_down
        : > "$root/stub/fail"
        run_offline "pre_$kind"
        want_ok "offline pre_$kind"
        grep -q 'no system bus is running' <<< "$err" || bad "offline pre_$kind: the no-bus notice is missing: $err"
        grep -q '^custodio:' "$root/etc/passwd" || bad "offline pre_$kind: the account was not created"
        run_offline "post_$kind"
        want_ok "offline post_$kind"
        run_offline pre_remove
        want_ok "offline pre_remove"
        run_offline post_remove
        want_ok "offline post_remove"
        want_notice "offline post_remove"
        state_intact "offline $kind"
    done
    # A failing account creation is still fatal offline.
    new_root none
    bus_down
    : > "$root/stub/fail-sysusers"
    run_offline pre_install
    [ "$rc" -ne 0 ] || bad "offline pre_install with a failing systemd-sysusers exited 0"
}

# ---- the scripts as they are ----
cases

# ---- the controls and the mutants: each must be caught by the cases above (they run on every test-scripts, not once by hand) ----
# shellcheck source=scripts/lib/arch-lifecycle-mutants.sh
. "$ROOT/scripts/lib/arch-lifecycle-mutants.sh"

exit "$fail"
