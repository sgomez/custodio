#!/usr/bin/env bash
# Writes the pre-install scripts of the three formats from packaging/bus-check.sh (the one source of the check, F42): the block between the
# markers is copied into each script, since a pre-install script cannot read a packaged file. scripts/check-bus-check-sync.sh fails when
# a script differs from what this would write. usage: embed-bus-check.sh [ROOT]; run it after editing the block. With OUT set the files go to that directory instead.
set -euo pipefail
ROOT=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
SRC=$ROOT/packaging/bus-check.sh

block() { sed -n '/^# >>> custodio-bus-check$/,/^# <<< custodio-bus-check$/p' "$SRC"; }
[ "$(block | wc -l)" -gt 2 ] || { echo "embed-bus-check: no marked block in $SRC" >&2; exit 1; }

# render KIND: the whole script of one kind; the caller redirects it to the file.
render() {
    case $1 in
    deb)
        cat <<'TEXT'
#!/bin/sh
# Refuse to install while the system bus lacks ProcessFD (F42). The check below is packaging/bus-check.sh, embedded by
# scripts/embed-bus-check.sh. It is the first thing this script does; abort-* calls do not run it.
set -e
TEXT
        block
        cat <<'TEXT'
case "$1" in
    install | upgrade) custodio_bus_check || exit 1 ;;
esac
TEXT
        ;;
    rpm)
        cat <<'TEXT'
#!/bin/sh
# Refuse to install while the system bus lacks ProcessFD (F42). The check below is packaging/bus-check.sh, embedded by
# scripts/embed-bus-check.sh. It is the first thing this scriptlet does; it runs on install ($1 = 1) and upgrade ($1 = 2).
TEXT
        block
        echo 'custodio_bus_check || exit 1'
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
