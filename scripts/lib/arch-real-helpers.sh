#!/usr/bin/env bash
# Log readers and assertions of scripts/test-arch-lifecycle-real.sh (F58); sourced, uses its $OUT and bad().
# ---- reading the logs ----
L() { cat "$OUT/$1.log"; }
count() { L "$1" | grep -cE -- "$2" || true; }
seq_of() { L "$1" | { grep -E -- "$2" || true; } | head -n 1 | cut -d" " -f1; }
rc_of() { cat "$OUT/$1.rc"; }
DR=' systemctl --system daemon-reload '
BR=' systemctl try-reload-or-restart dbus.service '
CAT=' journalctl --update-catalog '
RS=' systemctl try-restart custodio.service '
EFFECT_RESTART=' EFFECT restarted'
FROM_SCRIPT=':: .*(pre|post)_(install|upgrade|remove)'
# calls_of_scripts STEP: the calls the hooks make (reloads, catalog) when an install script function made them
calls_of_scripts() { L "$1" | grep -E "$FROM_SCRIPT" | grep -E ' (systemctl (--system )?(daemon-reload|reload|try-reload-or-restart)|journalctl --update-catalog)' || true; }

# hooks_once STEP FILES: daemon-reload, bus reload and catalog update happen exactly once, from hooks, in that order, and see the unit file as FILES.
hooks_once() {
    local s=$1 want=$2 what d b
    for what in "$DR" "$BR" "$CAT"; do
        [ "$(count "$s" "$what")" = 1 ] || bad "$s: '${what# }' did not happen exactly once: $(count "$s" "$what") times"
        L "$s" | grep -F -- "$what" | grep -q ":: .*systemd-hook" || bad "$s: '${what# }' was not made by a hook"
        L "$s" | grep -F -- "$what" | grep -q "files=$want " || bad "$s: '${what# }' did not see the unit file $want"
    done
    d=$(seq_of "$s" "$DR")
    b=$(seq_of "$s" "$BR")
    { [ -n "$d" ] && [ -n "$b" ] && [ "$d" -lt "$b" ]; } || bad "$s: the bus reload ($b) does not come after the daemon reload ($d)"
    [ -z "$(calls_of_scripts "$s")" ] || bad "$s: a script made a call that a hook makes: $(calls_of_scripts "$s")"
}
never_enable() { # STEP
    if L "$1" | grep -E ' (systemctl|journalctl) (enable|start|preset|mask|disable|edit|set-property)' > /dev/null; then bad "$1: enable, start or preset was called"; fi
    if L "$1" | grep -E ' EFFECT started' > /dev/null; then bad "$1: the service was started"; fi
}
state_same() { # STEP: the state tree is the one before the first upgrade
    cmp -s "$OUT/state-before" "$OUT/$1.state" || bad "$1: the state directory changed:"$'\n'"$(diff "$OUT/state-before" "$OUT/$1.state" || true)"
}
account_uid() { cut -d: -f3 "$OUT/$1.passwd"; }
# restart_after_reloads STEP LABEL: exactly one try-restart and one restart, from the hook, after both reloads and after unpacking
restart_after_reloads() {
    local s=$1 d b r
    [ "$(count "$s" "$RS")" = 1 ] || bad "$s: try-restart was not made exactly once"
    [ "$(count "$s" "$EFFECT_RESTART")" = 1 ] || bad "$s: the running service was restarted $(count "$s" "$EFFECT_RESTART") times"
    d=$(seq_of "$s" "$DR")
    b=$(seq_of "$s" "$BR")
    r=$(seq_of "$s" "$RS")
    { [ -n "$r" ] && [ -n "$d" ] && [ -n "$b" ] && [ "$r" -gt "$d" ] && [ "$r" -gt "$b" ]; } || bad "$s: the restart ($r) does not come after the daemon reload ($d) and the bus reload ($b)"
    L "$s" | grep -F -- "$RS" | grep -q "files=present " || bad "$s: the restart was made before the new files were there"
    L "$s" | grep -F -- "$RS" | grep -q ":: .*systemd-hook" || bad "$s: the restart was not made by the hook"
    if L "$s" | grep -E ' systemctl stop|EFFECT stopped' > /dev/null; then bad "$s: the service was stopped during an upgrade"; fi
}
