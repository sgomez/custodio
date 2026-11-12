# Shared by the static tests of the maintainer scripts (F173). The socket of the Firefox snap, custodio-firefox.socket, is enabled and
# restarted on install, and stopped before the service on removal (a socket left listening starts a stopped service again).
# shellcheck shell=bash

# The only systemctl lines on the socket that the forbidden-command gates let through (anything else on the unit stays forbidden).
# shellcheck disable=SC2034 # read by the scripts that source this file
SOCKET_OK='^[[:space:]]*systemctl +(enable|restart|stop|disable) +custodio-firefox\.socket +\|\| +true$'

# socket_install_problems FILE: prints what is missing from an install script (the socket enabled, then restarted).
socket_install_problems() {
    local f=$1 action
    for action in enable restart; do
        grep -qE "^[[:space:]]*systemctl +$action +custodio-firefox\\.socket +\\|\\| +true\$" "$f" || echo "$f does not $action custodio-firefox.socket"
    done
}

# socket_stop_problems FILE SERVICE-STOP-REGEX: prints a problem unless the socket is stopped on a line before the service's.
socket_stop_problems() {
    local f=$1 svc=$2 sock service
    sock=$(grep -nE '^[[:space:]]*systemctl +stop +custodio-firefox\.socket +\|\| +true$' "$f" | head -n 1 | cut -d: -f1 || true)
    service=$(grep -nE "$svc" "$f" | head -n 1 | cut -d: -f1 || true)
    [ -n "$sock" ] || { echo "$f never stops custodio-firefox.socket"; return; }
    [ -n "$service" ] || { echo "$f never stops custodio.service"; return; }
    [ "$sock" -lt "$service" ] || echo "$f stops custodio.service before custodio-firefox.socket"
}
