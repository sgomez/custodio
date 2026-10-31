#!/usr/bin/env bash
# Helpers of scripts/test-arch-lifecycle.sh (F58); sourced, uses its $SKELETON, $root, $calls, bad().
# shellcheck disable=SC2154,SC2153 # rc, err, ROOT and calls are set by the sourcing test
new_root() {
    root=$(mktemp -d "$BF_DIR/root.XXXXXX")
    cp -a "$SKELETON/." "$root/"
    mkdir -p "$root/var/lib"
    [ "${1:-}" = none ] || lc_populate "$root"
    before=$(lc_snapshot "$root")
}
run() { # SCRIPT [ARGS]: one function of $SRC in the current root; resets the call log first
    lc_reset "$root"
    lc_run "$root" "$SRC/$1" "${@:2}"
    calls=$(lc_calls "$root")
}
run_offline() {
    lc_reset "$root"
    lc_run_offline "$root" "$SRC/$1" "${@:2}"
    calls=$(lc_calls "$root")
}
# run_hook: the Exec of the hook file as pacman would run it (in the root), after the same reset.
run_hook() {
    local exec_line
    exec_line=$(sed -n 's/^Exec = //p' "$SRC/$HOOK")
    printf '#!/bin/sh\nexec %s\n' "$exec_line" > "$BF_DIR/hook-exec"
    lc_reset "$root"
    lc_run "$root" "$BF_DIR/hook-exec"
    calls=$(lc_calls "$root")
}
want_calls() { [ "$calls" = "$2" ] || bad "$1: calls were:"$'\n'"$calls"$'\n'"expected:"$'\n'"$2"; }
want_ok() { [ "$rc" -eq 0 ] || bad "$1: exit status $rc: $err"; }
state_intact() { # LABEL: the state directory (if any) is exactly as it was and no tool was called on its path
    local after
    after=$(lc_snapshot "$root")
    [ "$after" = "$before" ] || bad "$1: the state directory changed:"$'\n'"$(diff <(echo "$before") <(echo "$after") || true)"
    [ ! -e "$root/stub/violation" ] || bad "$1: a file tool was called with a path under the state directory: $(cat "$root/fs-calls" 2> /dev/null)"
    if grep -qE '/var/lib/(custodio|private)' <<< "$calls"; then bad "$1: a call names the state directory: $calls"; fi
    if grep -qE '/var/lib/(custodio|private)' "$root/fs-calls" 2> /dev/null; then bad "$1: a file tool names the state directory: $(cat "$root/fs-calls" 2> /dev/null)"; fi
}
no_account_removal() {
    if grep -qE '^(userdel|groupdel|deluser|delgroup|usermod) ' <<< "$calls"; then bad "$1: the account was changed: $calls"; fi
    grep -qE '^custodio:' "$root/etc/passwd" || [ ! -e "$root/stub/had-account" ] || bad "$1: the account is gone"
}
no_enable() { if grep -E '(^| )(enable|start|restart|preset|mask|daemon-reload|reload)( |$)|--update-catalog' <<< "$calls" > /dev/null; then bad "$1: enable, start, restart, preset or a hook's call was made: $calls"; fi; }
active() { [ -e "$root/stub/active" ]; }
restarts() { if [ -e "$root/stub/restarts" ]; then wc -l < "$root/stub/restarts"; else echo 0; fi; }
# root_snapshot: every file of the root outside the recorders, with mode, size and content hash (a script that writes anywhere shows).
root_snapshot() {
    (cd "$root" && find . -path ./recorded-calls -prune -o -path ./fs-calls -prune -o -path ./scripts -prune -o -path ./stub -prune -o \
        -printf '%p\t%y\t%m\t%s\t%l\n' | sort; find . -type f -not -path ./recorded-calls -not -path ./fs-calls -not -path './scripts/*' -not -path './stub/*' -exec sha256sum {} + | sort)
}
want_notice() { # LABEL: stderr holds the three lines, stdout is empty
    [ "$err" = "$NOTICE" ] || bad "$1: the notice on stderr was:"$'\n'"$err"$'\n'"expected:"$'\n'"$NOTICE"
    [ -z "$out" ] || bad "$1: output on stdout: $out"
}
notice_of() { grep -E '^ +echo "custodio: ' "$1" | sed -E 's/^ +echo "//; s/"$//'; }
NOTICE=$(notice_of "$ROOT/packaging/deb/postrm")
bus_without_processfd() { lc_bus_without_processfd "$root"; }
bus_down() { lc_bus_down "$root"; }

# hook_ok NAME FILE: the hook is a PostTransaction hook on Upgrade only, for the package, no AbortOnFail, and its name runs after the
# hooks that daemon-reload (30-systemd-daemon-reload-system) and reload the bus (dbus-reload.hook), which pacman orders by file name.
hook_ok() {
    local name=$1 file=$2 ops
    ops=$(sed -n 's/^Operation = //p' "$file" | tr '\n' ' ')
    [ "$ops" = "Upgrade " ] || { echo "operations: $ops"; return 1; }
    [ "$(sed -n 's/^When = //p' "$file")" = PostTransaction ] || { echo "not PostTransaction"; return 1; }
    [ "$(sed -n 's/^Target = //p' "$file")" = custodio ] || { echo "target"; return 1; }
    [ "$(sed -n 's/^Type = //p' "$file")" = Package ] || { echo "type"; return 1; }
    if grep -q '^AbortOnFail' "$file"; then echo "AbortOnFail"; return 1; fi
    [ "$(sed -n 's/^Exec = //p' "$file")" = '/usr/share/libalpm/scripts/systemd-hook restart custodio.service' ] || { echo "Exec"; return 1; }
    for before in 30-systemd-daemon-reload-system.hook 35-systemd-enqueue-marked.hook 35-systemd-update.hook dbus-reload.hook; do
        [[ "$name" > "$before" ]] || { echo "$name does not sort after $before"; return 1; }
    done
}
