#!/usr/bin/env bash
# Test of the M2 parts of docs/manual-acceptance.md (F52): each machine's part (found by its heading) holds the commands SPEC.md
# acceptance 12 to 15 ask for, in order, and they match docs/install.md, docs/audit.md and e2e/refusal-lib.sh. Each kind of check has a
# negative control: a fixture copy with the claim broken must fail and must differ from the real page.
# Usage: scripts/test-docs-manual.sh   (DOC and INSTALL override the real files; CHECK_ONLY=1 only checks DOC).
set -euo pipefail
cd "$(dirname "$0")/.."
DOC=${DOC:-docs/manual-acceptance.md}
INSTALL=${INSTALL:-docs/install.md}

section() { # section DOC HEADING_REGEX: the heading that matches up to the next heading of the same or a higher level
    awk -v re="$2" '
        /^```/ { fence = !fence }
        !fence && /^#+ / { match($0, /^#+/); lvl = RLENGTH; if (on && lvl <= on) on = 0; if (!on && $0 ~ re) on = lvl }
        on { sub(/^[ \t]+/, ""); print }' "$1"
}

# The base query of docs/audit.md: the line that lists all entries of the service.
audit_query() { grep -E '^journalctl _SYSTEMD_UNIT=custodio.service _UID=\$\(id -u custodio\) MESSAGE_ID=[0-9a-f]+$' docs/audit.md | head -n 1; }
REFUSAL=$(sed -n "s/^REFUSAL_PHRASE='\(.*\)'$/\1/p" e2e/refusal-lib.sh)

check() {
    local doc=$1 install=$2 fail=0 m part
    bad() { echo "manual-acceptance: $*" >&2; fail=1; }
    need() { grep -Eq -- "$1" <<< "$part" || bad "$m: $2"; } # need REGEX WHAT, on $part
    needF() { grep -qF -- "$1" <<< "$part" || bad "$m: $2"; }
    [ -n "$REFUSAL" ] || bad "no refusal phrase in e2e/refusal-lib.sh"
    local q; q=$(audit_query); [ -n "$q" ] || bad "no base query in docs/audit.md"

    for m in fedora44 bazzite omarchy ubuntu2404; do
        part=$(section "$doc" "^## .*$m")
        [ -n "$part" ] || { bad "$m: no part with that heading"; continue; }
        need '/etc/os-release' "no OS release command"
        need 'uname -r' "no kernel command"
        need '(dbus-broker|dbus-daemon) --version' "no bus daemon version command"
        need 'pkaction --version' "no polkit version command"
        # Every install command of the part also appears, whole, in docs/install.md.
        printf '%s\n' "$part" | grep -E '^(sudo )?(dnf install|rpm-ostree install|pacman -U|dpkg -i|apt-get install) ' | sed 's/^sudo //;s/^/sudo /' |
            while IFS= read -r cmd; do grep -qF -- "$cmd" "$install" || { echo "manual-acceptance: $m: '$cmd' is not in docs/install.md" >&2; exit 1; }; done || fail=1
    done

    m=fedora44; part=$(section "$doc" "^## .*$m")
    need '^sudo dnf install \./custodio-' "no dnf install of the .rpm"
    needF 'getenforce' "no getenforce"; need 'Enforcing' "does not require Enforcing"
    needF 'custodio import' "no .p12 import"
    need 'ausearch -m AVC' "no ausearch for AVC denials"
    need 'ausearch.*(--start|-ts)' "ausearch has no time window"
    local au; au=$(printf '%s\n' "$part" | grep -E 'ausearch.*(--start|-ts)|grep -E.*libcustodio' | tr '\n' ' ')
    for w in custodio polkit libcustodio_pkcs11; do grep -qF -- "$w" <<< "$au" || bad "$m: the ausearch denial check does not name '$w'"; done
    grep -qFx -- "$q" <<< "$(awk '{ sub(/ \\$/, "") } 1' <<< "$part")" || bad "$m: the journalctl line is not the base query of docs/audit.md"
    need 'CUSTODIO_OUTCOME=denied' "no query for cancellations"

    m=bazzite; part=$(section "$doc" "^## .*$m")
    need '^sudo rpm-ostree install \./custodio-' "no rpm-ostree install"
    need 'reboot' "no reboot"; need 'rpm-ostree status' "no check of the booted deployment"
    need 'rpm-ostree uninstall custodio --install' "no replace of the layered package"
    needF 'rpm-ostree upgrade' "no OS update"
    need 'ausearch -m AVC' "no ausearch for AVC denials"; needF 'getenforce' "no getenforce"
    # The order: the OS update step is followed by a reboot step.
    awk '/rpm-ostree upgrade/ { u = 1 } u && /reboot/ { ok = 1 } END { exit !ok }' <<< "$part" || bad "$m: no reboot after the OS update"

    m=omarchy; part=$(section "$doc" "^## .*$m")
    need '^sudo pacman -U custodio-.*pkg\.tar\.zst' "no pacman -U"

    m=ubuntu2404; part=$(section "$doc" "^## .*$m")
    need '^sudo dpkg -i \./?custodio_|^sudo dpkg -i custodio_' "no dpkg -i"
    needF "$REFUSAL" "the refusal phrase is not the one of e2e/refusal-lib.sh"
    need 'sudo apt-get install dbus-broker' "no switch command"; need 'reboot' "no reboot"
    need 'loginctl' "no logind check"
    need 'custodio import' "no import"

    return $fail
}

check "$DOC" "$INSTALL" || { echo "test-docs-manual: the page fails its checks" >&2; exit 1; }
[ -z "${CHECK_ONLY:-}" ] || exit 0

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
control() { # control NAME SED_EXPR
    sed -E -e "$2" "$DOC" > "$tmp/doc.md"
    if cmp -s "$DOC" "$tmp/doc.md"; then echo "control '$1': the fixture equals the page, the control is void" >&2; exit 1; fi
    if check "$tmp/doc.md" "$INSTALL" 2> /dev/null; then echo "control '$1': a broken page passed" >&2; exit 1; fi
}
# Control on one machine's part only (the sed expression applies between that heading and the next "## ").
control_in() { # control_in NAME MACHINE SED_EXPR
    awk -v m="$2" '/^## /{ on = ($0 ~ m) } { print (on ? "@@" : "") $0 }' "$DOC" | sed -E "/^@@/ { s/^@@//; $3 }; s/^@@//" > "$tmp/doc.md"
    if cmp -s "$DOC" "$tmp/doc.md"; then echo "control '$1': the fixture equals the page, the control is void" >&2; exit 1; fi
    if check "$tmp/doc.md" "$INSTALL" 2> /dev/null; then echo "control '$1': a broken page passed" >&2; exit 1; fi
}

control_in 'no kernel command (bazzite)' bazzite 's/uname -r/uname/g'
control_in 'no polkit version (omarchy)' omarchy 's/pkaction --version/pkaction/g'
control_in 'no bus daemon version (fedora44)' fedora44 's/dbus-broker --version/dbus-broker/g'
control 'no ausearch' 's/ausearch -m AVC/grep AVC/g'
control 'no getenforce' 's/getenforce/sestatus/g'
control_in 'no time window' fedora44 's/--start/--since/g'
control_in 'altered query' fedora44 's/MESSAGE_ID=/MESSAGE_ID=0/'
control_in 'no cancellation query' fedora44 's/CUSTODIO_OUTCOME=denied/CUSTODIO_OUTCOME=signed/'
control_in 'wrong dnf command' fedora44 's#sudo dnf install \./custodio-0.1.0-1.x86_64.rpm#sudo dnf install ./custodio-9.rpm#'
control_in 'wrong rpm-ostree command' bazzite 's#sudo rpm-ostree install \./custodio-0.1.0-1.x86_64.rpm#sudo rpm-ostree install ./custodio-9.rpm#'
control_in 'wrong pacman command' omarchy 's#sudo pacman -U custodio-0.1.0-1-x86_64.pkg.tar.zst#sudo pacman -U custodio-9.pkg.tar.zst#'
control_in 'no replace step' bazzite 's/rpm-ostree uninstall custodio --install/rpm-ostree status/'
control_in 'no OS update' bazzite 's/rpm-ostree upgrade/rpm-ostree status/g'
control_in 'no reboot after the OS update' bazzite '/rpm-ostree upgrade/,$ s/reboot/restart/g'
control_in 'no SELinux check (bazzite)' bazzite 's/ausearch -m AVC/grep AVC/g'
control_in 'wrong refusal phrase' ubuntu2404 "s/$REFUSAL/is refused/g"
control_in 'no logind check' ubuntu2404 's/loginctl/who/g'
control_in 'no dbus-broker switch' ubuntu2404 's/sudo apt-get install dbus-broker/true/'

echo "test-docs-manual: ok"
