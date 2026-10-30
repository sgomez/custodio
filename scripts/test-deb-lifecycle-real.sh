#!/usr/bin/env bash
# The real dpkg runs the maintainer scripts of the .deb (F43): install, upgrade from a package built to look like the last cargo-deb one
# (version 0.1.0-1, M1's files and M1's postinst only, no preinst, prerm or postrm), remove and purge, into a small root as root of a
# user namespace (scripts/lib/bus-fixtures.sh, bf_in_root), with the stubs of scripts/lib/lifecycle-fixtures.sh for systemctl,
# deb-systemd-invoke, systemd-sysusers, journalctl and busctl. A state directory with fixed content, modes and times is in the root.
# The account is created before the bus policy is unpacked: the systemd-sysusers stub records whether the policy file existed when it
# ran, and a fixture package whose account creation is moved to postinst makes it say "present" (the test must fail for that one).
# What the stubs cannot cover: a real systemd and bus (F45 and later).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
# shellcheck source=scripts/lib/bus-fixtures.sh
. "$ROOT/scripts/lib/bus-fixtures.sh"
# shellcheck source=scripts/lib/lifecycle-fixtures.sh
. "$ROOT/scripts/lib/lifecycle-fixtures.sh"

fx_init
bf_init
trap 'bf_cleanup; fx_cleanup' EXIT
fail=0
mutant_mode=0
mutant_hit=0
bad() {
    if [ "$mutant_mode" = 1 ]; then mutant_hit=1; else echo "test-deb-lifecycle-real: $*" >&2; fail=1; fi
}

SKELETON=$BF_DIR/skeleton
bf_mkroot "$SKELETON"
lc_stubs "$SKELETON"
bf_in_root "$SKELETON" true || { echo "test-deb-lifecycle-real: cannot make a user namespace for dpkg" >&2; exit 1; }

# The last cargo-deb package: M1's file list (the service in /usr/libexec) and M1's postinst, nothing else.
OLD_VERSION=0.1.0-1
old_deb=$BF_DIR/old/custodio_${OLD_VERSION}_amd64.deb
mkdir -p "$BF_DIR/old/tree/DEBIAN"
(
    cd "$BF_DIR/old/tree"
    mkdir -p usr/libexec usr/bin usr/lib/custodio usr/lib/systemd/system usr/lib/sysusers.d usr/share/dbus-1/system.d \
        usr/share/dbus-1/system-services usr/share/polkit-1/actions usr/share/p11-kit/modules usr/lib/systemd/catalog
    cp /bin/true usr/libexec/custodiod
    cp /bin/true usr/bin/custodio
    cp /bin/true usr/lib/custodio/libcustodio_pkcs11.so
    cp "$ROOT/data/custodio.service" usr/lib/systemd/system/custodio.service
    cp "$ROOT/data/sysusers.d/custodio.conf" usr/lib/sysusers.d/custodio.conf
    cp "$ROOT/data/com.rfirma.Custodio1.conf" usr/share/dbus-1/system.d/
    cp "$ROOT/data/com.rfirma.Custodio1.service" usr/share/dbus-1/system-services/
    cp "$ROOT/data/com.rfirma.custodio.policy" usr/share/polkit-1/actions/
    cp "$ROOT/data/custodio.module" usr/share/p11-kit/modules/
    cp "$ROOT/data/custodio.catalog" usr/lib/systemd/catalog/
    chmod 755 usr/libexec/custodiod usr/bin/custodio
    cat > DEBIAN/control <<CONTROL
Package: custodio
Version: $OLD_VERSION
Architecture: amd64
Maintainer: rFirma <info@rfirma.com>
Depends: libc6, dbus, polkitd, systemd, p11-kit
Description: Signing service for PKCS#12 keys
CONTROL
    # M1's postinst, as the last cargo-deb package shipped it.
    cat > DEBIAN/postinst <<'M1'
#!/bin/sh
# Create the static `custodio` account the D-Bus policy names, and let systemd see the new unit.
set -e
if [ "$1" = configure ]; then
    systemd-sysusers custodio.conf || true
    systemctl daemon-reload || true
    deb-systemd-invoke reload dbus.service || true
fi
M1
    chmod 755 DEBIAN/postinst
)
dpkg-deb --root-owner-group -b "$BF_DIR/old/tree" "$old_deb" > /dev/null

fx_build new 0.1.1 "" none
new_deb=$(fx_file new deb)

BUS='busctl --address=unix:path=/run/dbus/system_bus_socket call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionCredentials s org.freedesktop.DBus'
ACTIVE='systemctl is-active --quiet custodio.service'
RELOAD=$'systemctl daemon-reload\ndeb-systemd-invoke reload dbus.service'
CATALOG='journalctl --update-catalog'
SYSUSERS='systemd-sysusers -'

new_root() { # [none]
    root=$(mktemp -d "$BF_DIR/root.XXXXXX")
    cp -a "$SKELETON/." "$root/"
    mkdir -p "$root/var/lib"
    [ "${1:-}" = none ] || lc_populate "$root"
    before=$(lc_snapshot_state "$root")
}
# dp ARGS...: the real dpkg on the root; sets rc and out (stdout and stderr together).
dp() {
    rc=0
    out=$(bf_in_root "$root" env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket dpkg --root="$root" --log="$root/dpkg.log" \
        --force-depends --force-bad-path --no-triggers "$@" 2>&1) || rc=$?
}
# Paths of the package in the root, apart from the package databases and the state directory.
custodio_files() { find "$root" -mindepth 1 \( -iname '*custodio*' -o -name 'com.rfirma*' \) -not -path "$root/var/lib/*" -not -path "$root/dpkg.log" -not -path "$root/stub/*" -not -path "$root/scripts/*"; }
calls() { cat "$root/recorded-calls" 2> /dev/null || true; }
want_calls() { [ "$(calls)" = "$2" ] || bad "$1: calls were:"$'\n'"$(calls)"$'\n'"expected:"$'\n'"$2"; }
state_intact() {
    [ "$(lc_snapshot_state "$root")" = "$before" ] || bad "$1: the state directory changed:"$'\n'"$(diff <(echo "$before") <(lc_snapshot_state "$root") || true)"
    [ ! -e "$root/stub/violation" ] || bad "$1: a file tool was called on the state directory"
}
no_start() { if grep -qE '^(systemctl|deb-systemd-invoke|deb-systemd-helper) (enable|start|preset)' "$root/recorded-calls" 2> /dev/null; then bad "$1: enable or start: $(calls)"; fi; }

scenarios() {
    local state
    # ---- install, with and without a state directory ----
    for state in populated none; do
        if [ "$state" = none ]; then new_root none; else new_root; fi
        dp -i "$new_deb"
        [ "$rc" -eq 0 ] || bad "install ($state): dpkg exited $rc: $out"
        [ -x "$root/usr/lib/custodio/custodiod" ] || bad "install ($state): the files are missing"
        want_calls "install ($state)" "$BUS"$'\n'"$SYSUSERS"$'\n'"$RELOAD"$'\n'"$CATALOG"
        [ "$(cat "$root/stub/policy-at-sysusers" 2> /dev/null)" = absent ] || bad "install ($state): the bus policy was unpacked before the account was created: $(cat "$root/stub/policy-at-sysusers" 2> /dev/null)"
        grep -q '^custodio:' "$root/etc/passwd" || bad "install ($state): no account after unpack"
        no_start "install ($state)"
        [ ! -e "$root/stub/active" ] || bad "install ($state): the service runs"
        state_intact "install ($state)"
        if [ "$state" = none ] && [ -e "$root/var/lib/custodio" ]; then bad "install: the state directory was created"; fi
    done

    # ---- upgrade from the cargo-deb package, service running and not running ----
    for state in running stopped; do
        new_root
        dp -i "$old_deb"
        [ "$rc" -eq 0 ] || bad "upgrade ($state): the old package did not install: $out"
        [ -x "$root/usr/libexec/custodiod" ] || bad "upgrade ($state): the old files are missing"
        grep -q '^custodio:' "$root/etc/passwd" || bad "upgrade ($state): the old postinst created no account"
        uid_line=$(grep '^custodio:' "$root/etc/passwd")
        [ "$state" = stopped ] || : > "$root/stub/active"
        lc_reset "$root"
        dp -i "$new_deb"
        [ "$rc" -eq 0 ] || bad "upgrade ($state): dpkg exited $rc: $out"
        [ -x "$root/usr/lib/custodio/custodiod" ] || bad "upgrade ($state): the new files are missing"
        [ ! -e "$root/usr/libexec/custodiod" ] || bad "upgrade ($state): the old file is still there"
        expect="$BUS"$'\n'"$SYSUSERS"$'\n'"$ACTIVE"$'\n'"$RELOAD"$'\n'"$CATALOG"
        [ "$state" = stopped ] || expect+=$'\n''deb-systemd-invoke restart custodio.service'
        want_calls "upgrade ($state)" "$expect"
        [ "$(grep '^custodio:' "$root/etc/passwd")" = "$uid_line" ] || bad "upgrade ($state): the account changed"
        [ -e "$root/stub/active" ] || [ "$state" = stopped ] || bad "upgrade (running): the service is not running afterwards"
        [ ! -e "$root/stub/active" ] || [ "$state" = running ] || bad "upgrade (stopped): the service was started"
        [ ! -e "$root/run/custodio-restart-after-upgrade" ] || bad "upgrade ($state): the marker is left"
        no_start "upgrade ($state)"
        state_intact "upgrade ($state)"
    done

    # ---- remove, then purge; and purge of an installed package ----
    for state in remove purge; do
        new_root
        dp -i "$new_deb"
        : > "$root/stub/active"
        : > "$root/stub/reactivate-once"
        lc_reset "$root"
        if [ "$state" = remove ]; then dp -r custodio; else dp -P custodio; fi
        [ "$rc" -eq 0 ] || bad "$state: dpkg exited $rc: $out"
        [ -z "$(custodio_files)" ] || bad "$state: files are left: $(custodio_files)"
        grep -q '^custodio:' "$root/etc/passwd" || bad "$state: the account is gone"
        grep -qF '/var/lib/custodio' <<< "$out" || bad "$state: the notice is not in the output: $out"
        grep -qF 'destroys the keys for good' <<< "$out" || bad "$state: the warning is not in the output: $out"
        [ ! -e "$root/stub/active" ] || bad "$state: the service still runs"
        expect='deb-systemd-invoke stop custodio.service'$'\n'"$RELOAD"$'\n'"$ACTIVE"$'\n''deb-systemd-invoke stop custodio.service'
        [ "$state" = remove ] || expect+=$'\n'"$RELOAD"$'\n'"$ACTIVE"
        want_calls "$state" "$expect"
        state_intact "$state"
        if grep -qE '^(userdel|groupdel|deluser|delgroup|usermod)' "$root/recorded-calls"; then bad "$state: the account was changed"; fi
    done

    # ---- remove, then purge the removed package ----
    new_root
    dp -i "$new_deb"
    dp -r custodio
    lc_reset "$root"
    dp -P custodio
    [ "$rc" -eq 0 ] || bad "purge after remove: dpkg exited $rc: $out"
    want_calls "purge after remove" "$RELOAD"$'\n'"$ACTIVE"
    grep -qF 'destroys the keys for good' <<< "$out" || bad "purge after remove: no warning: $out"
    grep -q '^custodio:' "$root/etc/passwd" || bad "purge after remove: the account is gone"
    state_intact "purge after remove"
}

scenarios

# ---- the checks see a bad package: account creation moved from preinst to postinst ----
mutate_fixture() { # NAME FILE SED
    local before_dir=$FX_DIR/packaging/deb
    cp -r "$ROOT/packaging/deb/." "$before_dir/"
    sed -i "$3" "$before_dir/$2"
    if cmp -s "$before_dir/$2" "$ROOT/packaging/deb/$2"; then bad "mutant $1 changes nothing"; fi
    fx_build "$1" 0.1.1 "" none
    cp -r "$ROOT/packaging/deb/." "$before_dir/"
}
mutant_run() { # NAME FILE SED
    mutate_fixture "$1" "$2" "$3"
    new_deb=$(fx_file "$1" deb)
    mutant_mode=1
    mutant_hit=0
    scenarios
    mutant_mode=0
    new_deb=$(fx_file new deb)
    [ "$mutant_hit" = 1 ] || bad "mutant '$1' survived"
}
mutant_run account-in-postinst preinst 's|^        custodio_create_account .*|        :|'
mutant_run account-in-postinst-late postinst 's|^    systemctl daemon-reload.*|&\n    systemd-sysusers - < /dev/null|'
mutant_run enable-on-install postinst 's|^    journalctl --update-catalog .*|&\n    deb-systemd-invoke enable custodio.service|'
# shellcheck disable=SC2016 # a sed expression, not shell
mutant_run restart-always postinst 's|if \[ -n "\$2" \] \&\& \[ -e /run/custodio-restart-after-upgrade \]; then|if true; then|'
mutant_run delete-on-purge postrm 's|^    systemctl daemon-reload .*|    rm -rf /var/lib/private/custodio\n&|'

exit "$fail"
