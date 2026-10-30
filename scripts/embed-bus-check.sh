#!/usr/bin/env bash
# Writes the pre-install scripts of the three formats from packaging/bus-check.sh (the one source of the check, F42): the block between the
# markers is copied into each script, since a pre-install script cannot read a packaged file. scripts/check-bus-check-sync.sh fails when
# a script differs from what this would write. usage: embed-bus-check.sh [ROOT]; run it after editing the block. With OUT set the files go to that directory instead.
set -euo pipefail
ROOT=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
SRC=$ROOT/packaging/bus-check.sh

block() { sed -n '/^# >>> custodio-bus-check$/,/^# <<< custodio-bus-check$/p' "$SRC"; }
[ "$(block | wc -l)" -gt 2 ] || { echo "embed-bus-check: no marked block in $SRC" >&2; exit 1; }

# account_fn: the account creation shared by the deb preinst and the rpm %pre (F43, F44); scripts/check-sysusers-sync.sh reads its heredoc.
account_fn() {
    cat <<'TEXT'
custodio_create_account() {
    if ! command -v systemd-sysusers >/dev/null 2>&1; then
        printf '%s\n' "custodio: systemd-sysusers is not installed, so the custodio account cannot be created. Nothing was changed." >&2
        return 1
    fi
    if ! systemd-sysusers - <<'CUSTODIO_SYSUSERS'
u custodio - "Custodio signing service" -
CUSTODIO_SYSUSERS
    then
        printf '%s\n' "custodio: systemd-sysusers failed to create the custodio account. Nothing was changed." >&2
        return 1
    fi
}
TEXT
}

# render KIND: the whole script of one kind; the caller redirects it to the file.
render() {
    case $1 in
    deb)
        cat <<'TEXT'
#!/bin/sh
# Refuse to install while the system bus lacks ProcessFD (F42), then create the custodio account (F43) and, on an upgrade, note
# whether the service is running so that postinst restarts it only then. The check below is packaging/bus-check.sh, embedded by
# scripts/embed-bus-check.sh; it is the first thing this script does. abort-upgrade calls do nothing.
# The account comes from the sysusers text below (scripts/check-sysusers-sync.sh keeps it equal to data/sysusers.d/custodio.conf):
# it is created here, before unpacking, because dbus-daemon may load the bus policy that names the account as soon as it is unpacked,
# and a pre-install script cannot read a packaged file. The deb Pre-Depends on systemd, which provides systemd-sysusers.
set -e
TEXT
        block
        cat <<'TEXT'
TEXT
        account_fn
        cat <<'TEXT'
# The marker is in /run, never under the state directory; postinst removes it.
custodio_note_running() {
    rm -f /run/custodio-restart-after-upgrade
    if [ "$1" = upgrade ] && systemctl is-active --quiet custodio.service 2>/dev/null; then
        : > /run/custodio-restart-after-upgrade || true
    fi
}
case "$1" in
    install | upgrade)
        custodio_bus_check || exit 1
        custodio_create_account || exit 1
        custodio_note_running "$1"
        ;;
esac
TEXT
        ;;
    rpm)
        cat <<'TEXT'
#!/bin/sh
# Refuse to install while the system bus lacks ProcessFD (F42), then create the custodio account (F44) and, on an upgrade, note
# whether the service is running so that %post restarts it only then. The check below is packaging/bus-check.sh, embedded by
# scripts/embed-bus-check.sh; it is the first thing this scriptlet does. It runs on install ($1 = 1) and upgrade ($1 = 2).
# The account comes from the sysusers text below (scripts/check-sysusers-sync.sh keeps it equal to data/sysusers.d/custodio.conf):
# it is created here, before the package manager unpacks the bus policy, and a %pre scriptlet cannot read a packaged file. The package requires systemd,
# which provides systemd-sysusers, and a plain Requires is ordered before the %pre of the package that has it. The package has no user()
# provide: the package manager would create the account with it before this scriptlet, so before the check.
TEXT
        block
        account_fn
        cat <<'TEXT'
# The marker is in /run, never under the state directory; %post removes it. A failing write (read-only /run) is not an error: the
# subshell keeps a failed redirection from ending a sh that treats it as fatal.
custodio_note_running() {
    rm -f /run/custodio-restart-after-upgrade
    if [ "${1:-0}" -ge 2 ] && systemctl is-active --quiet custodio.service 2>/dev/null; then
        ( : > /run/custodio-restart-after-upgrade ) 2>/dev/null || true
    fi
}
custodio_bus_check || exit 1
custodio_create_account || exit 1
custodio_note_running "$1"
exit 0
TEXT
        ;;
    arch-install | arch-upgrade)
        cat <<'TEXT'
#!/bin/sh
# Warn while the system bus lacks ProcessFD (F42). The check below is packaging/bus-check.sh, embedded by
# scripts/embed-bus-check.sh. pacman ignores the status of this script and goes on, so it cannot refuse; the package hook
# custodio-bus-check.hook refuses a later upgrade or reinstall. Nothing is exposed: the service refuses to sign without ProcessFD.
TEXT
        block
        cat <<'TEXT'
if ! custodio_bus_check; then
    printf '%s\n' 'custodio: pacman ignores a failing pre-install script, so the installation goes on; custodiod refuses to sign until the bus provides ProcessFD.' >&2
    exit 1
fi
TEXT
        ;;
    hook)
        cat <<'TEXT'
#!/bin/sh
# Run by the PreTransaction hook custodio-bus-check.hook (F42): aborts an upgrade or reinstall of custodio while the system bus
# lacks ProcessFD. The check below is packaging/bus-check.sh, embedded by scripts/embed-bus-check.sh.
TEXT
        block
        echo 'custodio_bus_check || exit 1'
        ;;
    esac
}

# The output files, and the kind each one is rendered as.
while read -r kind file; do
    mkdir -p "$(dirname "${OUT:-$ROOT}/$file")"
    render "$kind" > "${OUT:-$ROOT}/$file"
done <<'LIST'
deb packaging/deb/preinst
rpm packaging/rpm/pre
arch-install packaging/arch/pre_install
arch-upgrade packaging/arch/pre_upgrade
hook packaging/arch/custodio-bus-check
LIST
