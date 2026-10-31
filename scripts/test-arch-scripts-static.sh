#!/usr/bin/env bash
# Static gates on the six install-script functions of the Arch package and on its restart hook (F58), read as text and as the built package says
# them (the .INSTALL): no script names the state directory outside the notice, none changes the bus policy, the polkit action or the unit,
# none removes the account or creates one another way, none enables, starts, presets or restarts the unit, and none repeats a call a hook of
# systemd or dbus already does (daemon-reload, the bus reload, the catalog update, sysusers outside pre_*). The runs are in
# scripts/test-arch-lifecycle.sh; the stubs there fail the test on any call with a state path. The real pacman: test-arch-lifecycle-real.sh.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
SRC=$ROOT/packaging/arch
fx_init
trap fx_cleanup EXIT
fail=0
bad() { echo "test-arch-scripts-static: $*" >&2; fail=1; }
SCRIPTS=(pre_install pre_upgrade post_install post_upgrade pre_remove post_remove)
HOOKS=(zz-custodio-restart.hook custodio-bus-check.hook)

# Every line that names the state directory is on this list, with the file, the exact text and the reason (a pattern would hide a new use).
ALLOW_STATE=(
    'post_remove|    echo "custodio: the signing keys are still on disk in /var/lib/custodio (the real directory is /var/lib/private/custodio)."|the notice names where the keys are; it prints a path and never opens it'
)
# state_hits DIR: lines of the scripts and hooks in DIR that name the state directory and are not on the allowlist.
state_hits() {
    local f line entry a_file a_text a_why found
    for f in "${SCRIPTS[@]}" "${HOOKS[@]}" custodio-bus-check; do
        while IFS= read -r line; do
            found=0
            for entry in "${ALLOW_STATE[@]}"; do
                IFS='|' read -r a_file a_text a_why <<< "$entry"
                if [ "$a_file" = "$f" ] && [ "$a_text" = "$line" ] && [ -n "$a_why" ]; then found=1; fi
            done
            [ "$found" = 1 ] || echo "$f: $line"
        done < <(grep -E '/var/lib|StateDirectory|STATE_DIRECTORY' "$1/$f" | grep -Ev '^[[:space:]]*#' || true)
    done
}
# forbidden_hits DIR: commands and paths no script or hook may use (the embedded F42 check holds none of them, so any hit is new).
forbidden_hits() {
    local f
    for f in "${SCRIPTS[@]}" "${HOOKS[@]}" custodio-bus-check; do
        grep -Ev '^[[:space:]]*(#|$)' "$1/$f" \
            | grep -E 'dbus-1|polkit-1|/lib/systemd|/etc/|custodio\.service\.d|systemctl +(--[a-z-]+ +)*(edit|set-property|mask|enable|preset|start|restart|try-restart|reload|daemon-reload)|systemd-hook +(restart|reload)|try-reload|systemd-run|useradd|adduser|groupadd|usermod|userdel|groupdel|deluser|rm +-[a-zA-Z]*r|chown|chmod|chgrp|sed +-i|\btee\b|\bcp\b|\bmv\b|\binstall +-|update-catalog' \
            | grep -v "^Exec = /usr/share/libalpm/scripts/systemd-hook restart custodio.service\$" \
            | sed "s|^|$f: |" || true
    done
}
# sysusers_hits DIR: a call to systemd-sysusers outside pre_install and pre_upgrade (the sysusers hook runs it at the end already).
sysusers_hits() {
    local f
    for f in post_install post_upgrade pre_remove post_remove "${HOOKS[@]}"; do
        grep -Ev '^[[:space:]]*#' "$1/$f" | grep -E 'systemd-sysusers' | sed "s|^|$f: |" || true
    done
}

[ -z "$(state_hits "$SRC")" ] || bad "a script names the state directory in a line that is not on the allowlist: $(state_hits "$SRC")"
for entry in "${ALLOW_STATE[@]}"; do
    IFS='|' read -r a_file a_text _ <<< "$entry"
    grep -qxF "$a_text" "$SRC/$a_file" || bad "the allowlist entry for $a_file matches no line: $a_text"
done
[ -z "$(forbidden_hits "$SRC")" ] || bad "a script or hook has a forbidden command or path: $(forbidden_hits "$SRC")"
[ -z "$(sysusers_hits "$SRC")" ] || bad "systemd-sysusers is called outside pre_install and pre_upgrade: $(sysusers_hits "$SRC")"
for f in "${SCRIPTS[@]}" custodio-bus-check; do
    head -n 1 "$SRC/$f" | grep -qx '#!/bin/sh' || bad "$f does not start with #!/bin/sh"
    sh -n "$SRC/$f" || bad "$f: sh -n failed"
    shellcheck "$SRC/$f" || bad "$f: shellcheck failed"
done
# Nothing prints on success but the notice (stderr) and the F42 messages; no script writes to stdout.
[ "$(grep -c 'echo' "$SRC/post_remove")" -eq 3 ] || bad "post_remove prints other than the three lines of the notice"
for f in post_install post_upgrade pre_remove; do ! grep -E 'echo|printf' "$SRC/$f" > /dev/null || bad "$f prints"; done
# post_install and post_upgrade must stay a valid function body in the .INSTALL of pacman (a comment alone is a syntax error in bash).
for f in post_install post_upgrade; do grep -qx ':' "$SRC/$f" || bad "$f has no command (an empty function body is a syntax error in the .INSTALL)"; done
# The restart hook is in the package list with mode 0644, next to the check hook.
grep -q 'src: packaging/arch/zz-custodio-restart.hook' "$ROOT/packaging/nfpm.yaml" || bad "nfpm.yaml does not ship the restart hook"
sed -n '/zz-custodio-restart.hook$/,/file_info/p' "$ROOT/packaging/nfpm.yaml" | grep -q 'mode: 0644' || bad "the restart hook is not mode 0644 in nfpm.yaml"

# ---- the same gates on the built package ----
fx_build real 0.1.0 "" none
tmp=$FX_DIR/arch-scripts
fx_scripts real archlinux "$tmp"
for fn in pre_install post_install pre_upgrade post_upgrade pre_remove post_remove; do
    grep -qE "^(function )?$fn\\(\\)" "$tmp/INSTALL" || bad "the .INSTALL of the built package does not define $fn"
done
bash -n "$tmp/INSTALL" || bad "the .INSTALL: bash -n failed"
pkg=$(fx_file real archlinux)
listing=$(bsdtar -tvf "$pkg")
grep -qE '^-rw-r--r-- .* usr/share/libalpm/hooks/zz-custodio-restart.hook$' <<< "$listing" || bad "the package does not hold zz-custodio-restart.hook with mode 0644"
cmp -s <(bsdtar -xOf "$pkg" usr/share/libalpm/hooks/zz-custodio-restart.hook) "$SRC/zz-custodio-restart.hook" || bad "the packaged restart hook is not packaging/arch/zz-custodio-restart.hook"
cmp -s <(bsdtar -xOf "$pkg" usr/share/libalpm/hooks/custodio-bus-check.hook) "$SRC/custodio-bus-check.hook" || bad "the packaged check hook is not packaging/arch/custodio-bus-check.hook"
# The functions of the .INSTALL hold the source files' commands (the wrapper adds only the function line and the closing brace).
for fn in pre_install pre_upgrade post_install post_upgrade pre_remove post_remove; do
    body=$(awk -v fn="$fn" '$0 ~ "^function " fn "\\(\\)" { on = 1; next } /^function / { on = 0 } on { print }' "$tmp/INSTALL" | tac | sed '0,/^}$/d' | tac)
    [ "$body" = "$(cat "$SRC/$fn")" ] || bad "the $fn of the built .INSTALL is not packaging/arch/$fn"
done

# ---- the gates see what they are meant to see (fixtures with one bad line each) ----
mkdir -p "$FX_DIR/bad"
try() { # LABEL SCRIPT BODY: a copy of the arch files with BODY appended to SCRIPT; the gate named by the label must see it
    rm -rf "$FX_DIR/bad/arch"
    cp -r "$SRC" "$FX_DIR/bad/arch"
    printf '%s\n' "$3" >> "$FX_DIR/bad/arch/$2"
    case $1 in
    state) [ -n "$(state_hits "$FX_DIR/bad/arch")" ] || bad "control '$3' in $2: the state gate did not see it" ;;
    forbidden) [ -n "$(forbidden_hits "$FX_DIR/bad/arch")" ] || bad "control '$3' in $2: the forbidden gate did not see it" ;;
    sysusers) [ -n "$(sysusers_hits "$FX_DIR/bad/arch")" ] || bad "control '$3' in $2: the sysusers gate did not see it" ;;
    esac
}
for f in "${SCRIPTS[@]}"; do
    try state "$f" 'rm -f /var/lib/custodio/key-1.p12'
    try state "$f" 'echo x > /var/lib/private/custodio/new'
    # shellcheck disable=SC2016 # the line is text for the gate
    try state "$f" 'ls $STATE_DIRECTORY'
    try forbidden "$f" 'sed -i s/x/y/ /usr/share/dbus-1/system.d/com.rfirma.Custodio1.conf'
    try forbidden "$f" 'systemctl enable custodio.service'
    try forbidden "$f" 'systemctl start custodio.service'
    try forbidden "$f" 'systemctl restart custodio.service'
    try forbidden "$f" 'systemctl daemon-reload'
    try forbidden "$f" 'systemctl reload dbus.service'
    try forbidden "$f" 'journalctl --update-catalog'
    try forbidden "$f" 'systemd-run --unit x true'
    try forbidden "$f" 'userdel custodio'
    try forbidden "$f" 'useradd custodio'
    try forbidden "$f" 'cp x /usr/share/polkit-1/actions/com.rfirma.custodio.policy'
    try forbidden "$f" 'systemctl edit custodio.service'
    try forbidden "$f" 'systemctl set-property custodio.service Markers=needs-restart'
    case $f in pre_install | pre_upgrade) ;; *) try sysusers "$f" 'systemd-sysusers custodio.conf' ;; esac
done
try state zz-custodio-restart.hook 'Exec = /usr/bin/ls /var/lib/custodio'
try forbidden zz-custodio-restart.hook 'Exec = /usr/bin/systemctl enable custodio.service'
try forbidden zz-custodio-restart.hook 'Exec = /usr/share/libalpm/scripts/systemd-hook reload dbus.service'
exit "$fail"
