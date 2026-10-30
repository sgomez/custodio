#!/usr/bin/env bash
# The four maintainer scripts of the .deb (packaging/deb/{preinst,postinst,prerm,postrm}, F43), run one by one in a temporary root with
# stubbed systemctl, deb-systemd-invoke, systemd-sysusers, journalctl and busctl (scripts/lib/lifecycle-fixtures.sh). The real dpkg
# runs them in scripts/test-deb-lifecycle-real.sh. What the stubs cannot cover: a real systemd and bus, which F45 and later exercise.
#
# The calls each script makes per maintainer-script action (this is the one place that decides them; every line is a call logged
# by a stub, in this order, and nothing else is logged; BUS is the F42 query):
#   preinst install | upgrade        BUS; systemd-sysusers -; (upgrade only) systemctl is-active --quiet custodio.service.
#                                    The marker /run/custodio-restart-after-upgrade exists afterwards only if that said active.
#                                    A failing systemd-sysusers, or none on PATH, makes it exit 1 with a message and no marker.
#   preinst abort-upgrade            nothing
#   postinst configure [OLD]         systemctl daemon-reload; deb-systemd-invoke reload dbus.service; journalctl --update-catalog;
#                                    then, only with OLD and the marker: deb-systemd-invoke restart custodio.service (once).
#                                    Never enable, start, preset. Failing tools: still exit 0.
#   postinst abort-upgrade|abort-remove|abort-deconfigure    nothing (the marker is removed)
#   prerm remove                     deb-systemd-invoke stop custodio.service
#   prerm upgrade | failed-upgrade | deconfigure             nothing (upgrade: postinst restarts the service once)
#   postrm remove | purge            systemctl daemon-reload; deb-systemd-invoke reload dbus.service; systemctl is-active --quiet
#                                    custodio.service and, only when it says active (it came back between prerm and the removal of
#                                    the files), deb-systemd-invoke stop custodio.service; then the notice on STDERR (stdout stays
#                                    empty: debconf frontends use stdout of maintainer scripts). Purge is the same as remove.
#   postrm upgrade | failed-upgrade | disappear              nothing
#   postrm abort-install | abort-upgrade                     nothing (the marker is removed)
# No script changes, reads, lists or prints anything under the state directory; the account is never removed (no userdel, deluser,
# groupdel). The expected lists below are compared line by line.
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
    if [ "$mutant_mode" = 1 ]; then mutant_hit=1; else echo "test-deb-lifecycle: $*" >&2; fail=1; fi
}

SKELETON=$BF_DIR/skeleton
bf_mkroot "$SKELETON"
lc_stubs "$SKELETON"
bf_in_root "$SKELETON" true || { echo "test-deb-lifecycle: cannot make a user namespace" >&2; exit 1; }

BUS='busctl --address=unix:path=/run/dbus/system_bus_socket call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionCredentials s org.freedesktop.DBus'
ACTIVE='systemctl is-active --quiet custodio.service'
RELOAD=$'systemctl daemon-reload\ndeb-systemd-invoke reload dbus.service'
CATALOG='journalctl --update-catalog'
MARKER=run/custodio-restart-after-upgrade
OLD=0.1.0-1 # the version of the last cargo-deb package: lower than the nfpm one and with the M1 postinst only
SRC=$ROOT/packaging/deb

# new_root [none]: a fresh root with a populated state directory (or none) and an account list holding root only.
new_root() {
    root=$(mktemp -d "$BF_DIR/root.XXXXXX")
    cp -a "$SKELETON/." "$root/"
    mkdir -p "$root/var/lib"
    [ "${1:-}" = none ] || lc_populate "$root"
    before=$(lc_snapshot "$root")
}
# run SCRIPT ARGS...: one script of $SRC in the current root; resets the call log first.
run() {
    lc_reset "$root"
    lc_run "$root" "$SRC/$1" "${@:2}"
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
no_enable() { # LABEL: never enable, start, preset or use the helper
    if grep -E '(^| )(enable|start|preset|mask)( |$)|^deb-systemd-helper' <<< "$calls" > /dev/null; then bad "$1: enable, start or preset was called: $calls"; fi
}
active() { [ -e "$root/stub/active" ]; }

cases() {
    # ---- install ----
    for populated in yes none; do
        if [ "$populated" = none ]; then new_root none; else new_root; fi
        L="install ($populated state)"
        run preinst install
        want_ok "preinst $L"
        want_calls "preinst $L" "$BUS"$'\n''systemd-sysusers -'
        grep -qx 'u custodio - "Custodio signing service" -' "$root/stub/sysusers-input" || bad "preinst $L: sysusers got: $(cat "$root/stub/sysusers-input")"
        grep -q '^custodio:' "$root/etc/passwd" || bad "preinst $L: the account was not created"
        [ ! -e "$root/$MARKER" ] || bad "preinst $L: a marker on a first installation"
        run postinst configure
        want_ok "postinst $L"
        want_calls "postinst $L" "$RELOAD"$'\n'"$CATALOG"
        no_enable "postinst $L"
        active && bad "postinst $L: the service was started"
        state_intact "install ($populated state)"
        if [ "$populated" = none ] && { [ -e "$root/var/lib/custodio" ] || [ -e "$root/var/lib/private" ]; }; then bad "install: the state directory was created"; fi
    done

    # ---- install, account before the reload ----
    new_root none
    lc_reset "$root"
    lc_run "$root" "$SRC/preinst" install
    lc_run "$root" "$SRC/postinst" configure
    sysusers_line=$(grep -n '^systemd-sysusers' "$root/recorded-calls" | head -1 | cut -d: -f1 || true)
    reload_line=$(grep -n '^deb-systemd-invoke reload' "$root/recorded-calls" | head -1 | cut -d: -f1 || true)
    if [ -z "$sysusers_line" ] || [ -z "$reload_line" ] || [ "$sysusers_line" -ge "$reload_line" ]; then bad "install: sysusers ($sysusers_line) does not come before the bus reload ($reload_line)"; fi

    # ---- upgrade over the M1 account, service running ----
    new_root
    printf 'custodio:x:996:996:Custodio:/:/usr/sbin/nologin\n' >> "$root/etc/passwd"
    : > "$root/stub/had-account"
    : > "$root/stub/active"
    run preinst upgrade "$OLD"
    want_ok "preinst upgrade"
    want_calls "preinst upgrade (running)" "$BUS"$'\n''systemd-sysusers -'$'\n'"$ACTIVE"
    [ -e "$root/$MARKER" ] || bad "preinst upgrade: no marker although the service runs"
    grep -c '^custodio:' "$root/etc/passwd" | grep -qx 1 || bad "preinst upgrade: a second account line"
    grep -q '^custodio:x:996:996:' "$root/etc/passwd" || bad "preinst upgrade: the uid of custodio changed"
    run prerm upgrade 0.2.0-1
    want_ok "prerm upgrade"
    want_calls "prerm upgrade" ""
    run postinst configure "$OLD"
    want_ok "postinst upgrade"
    want_calls "postinst upgrade (running)" "$RELOAD"$'\n'"$CATALOG"$'\n''deb-systemd-invoke restart custodio.service'
    [ ! -e "$root/$MARKER" ] || bad "postinst upgrade: the marker is still there"
    active || bad "postinst upgrade: the service is not running afterwards"
    no_enable "postinst upgrade"
    no_account_removal "upgrade"
    state_intact "upgrade (running)"
    # A second configure (the marker is gone): no second restart.
    run postinst configure 0.2.0-1
    want_calls "postinst configure again" "$RELOAD"$'\n'"$CATALOG"

    # ---- upgrade, service not running ----
    new_root
    run preinst upgrade "$OLD"
    want_calls "preinst upgrade (stopped)" "$BUS"$'\n''systemd-sysusers -'$'\n'"$ACTIVE"
    [ ! -e "$root/$MARKER" ] || bad "preinst upgrade: a marker although the service is stopped"
    run postinst configure "$OLD"
    want_ok "postinst upgrade (stopped)"
    want_calls "postinst upgrade (stopped)" "$RELOAD"$'\n'"$CATALOG"
    active && bad "postinst upgrade: a stopped service was started"
    state_intact "upgrade (stopped)"

    # ---- upgrade from the cargo-deb package, or after a preinst that did not finish: no marker, service active ----
    new_root
    : > "$root/stub/active"
    run postinst configure "$OLD"
    want_ok "postinst without marker"
    want_calls "postinst without marker" "$RELOAD"$'\n'"$CATALOG"
    state_intact "postinst without marker"

    # ---- first installation with a stale marker (a failed earlier upgrade): no restart without an old version ----
    new_root none
    : > "$root/stub/active"
    : > "$root/$MARKER"
    run postinst configure
    want_calls "postinst install with a stale marker" "$RELOAD"$'\n'"$CATALOG"

    # ---- failing preinst ----
    new_root none
    : > "$root/stub/fail-sysusers"
    run preinst install
    [ "$rc" -ne 0 ] || bad "preinst with a failing systemd-sysusers exited 0"
    grep -q 'systemd-sysusers' <<< "$err" || bad "preinst with a failing systemd-sysusers printed no message: $err"
    [ ! -e "$root/$MARKER" ] || bad "preinst with a failing systemd-sysusers left a marker"
    new_root none
    rm "$root/usr/bin/systemd-sysusers"
    run preinst install
    [ "$rc" -ne 0 ] || bad "preinst without systemd-sysusers exited 0"
    grep -q 'systemd-sysusers is not installed' <<< "$err" || bad "preinst without systemd-sysusers does not name the tool: $err"
    grep -q '^custodio:' "$root/etc/passwd" && bad "preinst without systemd-sysusers: an account exists"
    want_calls "preinst without systemd-sysusers" "$BUS"
    state_intact "preinst without sysusers"

    # ---- hostile tools: reloads may fail ----
    new_root
    : > "$root/stub/fail"
    : > "$root/stub/active"
    run preinst upgrade "$OLD"
    want_ok "preinst with failing tools"
    run postinst configure "$OLD"
    want_ok "postinst with failing tools"
    run postrm remove
    want_ok "postrm remove with failing tools"
    run prerm remove
    want_ok "prerm remove with failing tools"
    state_intact "failing tools"

    # ---- remove and purge ----
    for action in remove purge; do
        new_root
        : > "$root/stub/had-account"
        printf 'custodio:x:998:998:Custodio:/:/usr/sbin/nologin\n' >> "$root/etc/passwd"
        : > "$root/stub/active"
        run prerm remove
        want_ok "prerm remove ($action)"
        want_calls "prerm remove ($action)" 'deb-systemd-invoke stop custodio.service'
        active && bad "prerm remove ($action): the service still runs"
        state_intact "prerm remove ($action)"
        run postrm remove
        want_ok "postrm remove ($action)"
        want_calls "postrm remove ($action)" "$RELOAD"$'\n'"$ACTIVE"
        [ -z "$out" ] || bad "postrm remove ($action): output on stdout: $out"
        if [ "$action" = purge ]; then
            run postrm purge
            want_ok "postrm purge"
            want_calls "postrm purge" "$RELOAD"$'\n'"$ACTIVE"
        fi
        grep -qF '/var/lib/custodio' <<< "$err" || bad "postrm $action: the notice does not name the state directory: $err"
        grep -qF 'destroys the keys for good' <<< "$err" || bad "postrm $action: the notice lacks the warning: $err"
        grep -qF 'still on disk' <<< "$err" || bad "postrm $action: the notice does not say the keys stay: $err"
        [ -z "$out" ] || bad "postrm $action: output on stdout: $out"
        state_intact "remove ($action)"
        no_account_removal "$action"
        no_enable "$action"
        active && bad "$action: the service runs afterwards"
        if grep -E '^(rm|chown|chmod|cp|cat) ' "$root/fs-calls" 2> /dev/null | grep -E 'custodio' > /dev/null; then bad "$action: a file tool was called on a custodio path"; fi
    done

    # ---- remove: the service came back between prerm and the removal of the files ----
    new_root
    : > "$root/stub/active"
    : > "$root/stub/reactivate-once"
    run prerm remove
    active || bad "the stub does not model a reactivation"
    run postrm remove
    want_calls "postrm remove (reactivated)" "$RELOAD"$'\n'"$ACTIVE"$'\n''deb-systemd-invoke stop custodio.service'
    active && bad "postrm remove: the service runs after the stop"
    state_intact "remove (reactivated)"

    # ---- the other actions ----
    for spec in "prerm upgrade 0.2.0-1" "prerm failed-upgrade $OLD" "prerm deconfigure in-favour other" "prerm remove in-favour other:1" \
        "postrm upgrade 0.2.0-1" "postrm failed-upgrade $OLD" "postrm abort-install" "postrm abort-upgrade $OLD" "postrm disappear other" \
        "postinst abort-upgrade 0.2.0-1" "postinst abort-remove" "postinst abort-deconfigure in-favour other" "preinst abort-upgrade 0.2.0-1"; do
        new_root
        : > "$root/stub/active"
        : > "$root/$MARKER"
        # shellcheck disable=SC2086 # the spec is words
        run $spec
        want_ok "$spec"
        expect=""
        [ "$spec" != "prerm remove in-favour other:1" ] || expect='deb-systemd-invoke stop custodio.service'
        want_calls "$spec" "$expect"
        active || [ -n "$expect" ] || bad "$spec: the service was stopped"
        no_enable "$spec"
        no_account_removal "$spec"
        state_intact "$spec"
        case $spec in
        "postrm abort-"* | "postinst abort-"*) [ ! -e "$root/$MARKER" ] || bad "$spec: the marker is still there" ;;
        esac
    done
}

# ---- the scripts as they are ----
cases

# ---- the stubs are checked: a bad script is seen ----
bad_script() { # NAME BODY: a copy of postrm with an extra line
    mkdir -p "$BF_DIR/bad"
    { printf '#!/bin/sh\n'; printf '%s\n' "$2"; } > "$BF_DIR/bad/$1"
}
control() { # LABEL BODY: the state check must fail for a script with that body
    bad_script ctl "$2"
    new_root
    lc_run "$root" "$BF_DIR/bad/ctl" x
    calls=$(lc_calls "$root")
    mutant_mode=1
    mutant_hit=0
    state_intact "control"
    mutant_mode=0
    [ "$mutant_hit" = 1 ] || bad "control '$1': the state checks did not see it"
}
control "rm -rf of the directory" 'rm -rf /var/lib/custodio/'
control "rm of a key through the real path" 'rm /var/lib/private/custodio/key-1.p12'
control "redirection into the directory" 'echo x > /var/lib/custodio/new'
control "redirection over a key" ': > /var/lib/private/custodio/key-1.p12'
control "chmod" 'chmod 777 /var/lib/custodio'
control "cat" 'cat /var/lib/custodio/key-1.p12'
control "creating the directory" 'mkdir -p /var/lib/custodio2/../custodio/x'

# ---- mutants of the scripts: each must be caught by the cases above ----
mutant() { # NAME SCRIPT SED-EXPRESSION
    local dir=$BF_DIR/mutant-$1
    rm -rf "$dir"
    cp -r "$ROOT/packaging/deb" "$dir"
    sed -i "$3" "$dir/$2"
    cmp -s "$dir/$2" "$ROOT/packaging/deb/$2" && { bad "mutant $1 changes nothing"; return; }
    SRC=$dir
    mutant_mode=1
    mutant_hit=0
    cases
    mutant_mode=0
    SRC=$ROOT/packaging/deb
    [ "$mutant_hit" = 1 ] || bad "mutant '$1' survived"
}
mutant enable-in-postinst postinst 's|^    journalctl --update-catalog .*|&\n    systemctl enable custodio.service|'
# shellcheck disable=SC2016 # sed expressions
mutant restart-always postinst 's|if \[ -n "\$2" \] && \[ -e /run/custodio-restart-after-upgrade \]; then|if [ -n "$2" ]; then|'
# shellcheck disable=SC2016
mutant restart-on-install postinst 's|if \[ -n "\$2" \] && \[ -e /run/custodio-restart-after-upgrade \]; then|if [ -e /run/custodio-restart-after-upgrade ]; then|'
mutant restart-before-reload postinst 's|^    systemctl daemon-reload .*|    deb-systemd-invoke restart custodio.service\n&|'
mutant start-in-postinst postinst 's|^    journalctl --update-catalog .*|&\n    deb-systemd-invoke start custodio.service|'
mutant sysusers-ignored-failure preinst 's|custodio_create_account \|\| exit 1|custodio_create_account \|\| true|'
mutant sysusers-pipe-true preinst 's|^        return 1$|        return 0|'
# shellcheck disable=SC2016
mutant marker-always preinst 's|\[ "\$1" = upgrade \] && ||'
mutant stop-on-upgrade prerm 's|^remove)|remove \| upgrade)|'
mutant no-stop-on-remove prerm 's|^    deb-systemd-invoke stop custodio.service.*|    :|'
mutant delete-state postrm 's|^    systemctl daemon-reload .*|    rm -rf /var/lib/custodio/\n&|'
mutant delete-state-private postrm 's|^    systemctl daemon-reload .*|    rm -rf /var/lib/private/custodio\n&|'
mutant remove-account postrm 's|^    systemctl daemon-reload .*|    userdel custodio\n&|'
mutant no-notice postrm 's|destroys the keys for good|is risky|'
mutant no-final-stop postrm 's|^        deb-systemd-invoke stop custodio.service.*|        :|'
mutant no-bus-reload postinst 's|^    deb-systemd-invoke reload dbus.service.*|    :|'
mutant no-catalog postinst 's|^    journalctl --update-catalog.*|    :|'
mutant purge-differs postrm 's|^remove \| purge)|remove)|'
mutant stdout-notice postrm 's|^    } >&2|    }|'

exit "$fail"
