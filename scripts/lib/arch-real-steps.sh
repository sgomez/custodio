#!/bin/sh
# shellcheck disable=SC2086 # $PM is a command with options and is split on purpose
# Runs in the throw-away Arch container of scripts/test-arch-lifecycle-real.sh (F58). usage: arch-real-steps.sh SCENARIO PREFIX
# /pkg holds the packages, /stubs the stand-ins, /out the results: every step leaves NAME.{log,out,rc,passwd,state,active,files,version} there.
sh /stubs/arch-real-stubs.sh
PM="pacman --noconfirm --disable-sandbox -dd"
STATE=/var/lib/private/custodio
state_hash() {
    [ -d "$STATE" ] || { echo none; return; }
    find /var/lib/private /var/lib/custodio -printf '%p %y %m %u:%g %s %l %T@\n' 2>/dev/null | sort
    find "$STATE" -type f -exec sha256sum {} + | sort
}
# The state directory as systemd lays it out under DynamicUser=: a key (0600), a hidden file, a symlink, a subdirectory.
populate() {
    mkdir -p "$STATE/sub"; chmod 700 /var/lib/private "$STATE" "$STATE/sub"
    printf 'PKCS12-key-material-1\n' > "$STATE/key-1.p12"; printf 'hidden\n' > "$STATE/.hidden"; chmod 600 "$STATE/key-1.p12" "$STATE/.hidden"
    ln -sfn key-1.p12 "$STATE/link"; ln -sfn private/custodio /var/lib/custodio
    touch -h -d '2026-01-02 03:04:05' "$STATE/key-1.p12" "$STATE/.hidden" "$STATE/link" "$STATE/sub" "$STATE" /var/lib/private /var/lib/custodio
}
step() { # NAME COMMAND...
    name=$1; shift
    : > /tmp/calls
    "$@" > "/out/$name.out" 2>&1; echo $? > "/out/$name.rc"
    cp /tmp/calls "/out/$name.log"
    getent passwd custodio > "/out/$name.passwd" 2>&1 || true
    state_hash > "/out/$name.state"
    if [ -e /tmp/stub/active ]; then echo active; else echo inactive; fi > "/out/$name.active"
    { ls /usr/lib/custodio/custodiod /usr/share/dbus-1/system.d/com.rfirma.Custodio1.conf /usr/lib/systemd/system/custodio.service 2>/dev/null || true; } > "/out/$name.files"
    pacman -Q custodio > "/out/$name.version" 2>&1 || true
}
P=${2:-v1}
A=/pkg/$P-a.pkg.tar.zst; B=/pkg/$P-b.pkg.tar.zst
if [ "$P" = v1 ]; then A=/pkg/v1.pkg.tar.zst; B=/pkg/v2.pkg.tar.zst; fi
case "$1" in
flow)
    step install $PM -U "$A"
    populate; state_hash > /out/state-before
    : > /tmp/stub/active
    step upgrade-active $PM -U "$B"
    rm -f /tmp/stub/active
    step upgrade-inactive $PM -U /pkg/v3.pkg.tar.zst
    : > /tmp/stub/active
    step remove $PM -R custodio
    step reinstall $PM -U "$A"
    : > /tmp/stub/active
    step purge $PM -Rns custodio
    ;;
f42era)
    step install $PM -U /pkg/old.pkg.tar.zst
    populate; state_hash > /out/state-before
    : > /tmp/stub/active
    step upgrade-active $PM -U /pkg/v2.pkg.tar.zst
    rm -f /tmp/stub/active
    step upgrade-inactive $PM -U /pkg/v3.pkg.tar.zst
    ;;
refusing) step install $PM -U /pkg/v1.pkg.tar.zst ;;
nosysusers)
    mv /usr/bin/systemd-sysusers /usr/bin/systemd-sysusers.off; mv /usr/bin/systemd-sysusers.real /usr/bin/systemd-sysusers.real.off
    step install $PM -U /pkg/v1.pkg.tar.zst
    ;;
failsysusers)
    : > /tmp/stub/fail-sysusers
    step install $PM -U /pkg/v1.pkg.tar.zst
    ;;
failsysusers-upgrade)
    step install $PM -U /pkg/v1.pkg.tar.zst
    : > /tmp/stub/fail-sysusers
    step upgrade $PM -U /pkg/v2.pkg.tar.zst
    ;;
esac
