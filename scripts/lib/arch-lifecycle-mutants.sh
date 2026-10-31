#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154 # the variables are set and read by the test that sources this file
# The controls and the mutants of the Arch install scripts for scripts/test-arch-lifecycle.sh (F58), sourced by it after `cases`. The controls
# prove that the state check sees a bad script; each mutant is a copy of packaging/arch with one sed edit, run through all the cases with SRC
# pointing at it; the test fails when a mutant survives or changes nothing.
bad_script() { # NAME BODY
    mkdir -p "$BF_DIR/bad"
    { printf '#!/bin/sh\n'; printf '%s\n' "$2"; } > "$BF_DIR/bad/$1"
}
control() { # LABEL BODY: the state check must fail for a script with that body
    bad_script ctl "$2"
    new_root
    lc_run "$root" "$BF_DIR/bad/ctl"
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
# The hook checks see a hook that sorts too early, fires on installs, aborts, or runs before the transaction.
control_hook() { # LABEL NAME SED
    local f=$BF_DIR/ctl-hook
    cp "$SRC/$HOOK" "$f"
    sed -i "$3" "$f"
    hook_ok "$2" "$f" > /dev/null && bad "hook control '$1': hook_ok accepted it"
    return 0
}
control_hook "name before dbus-reload" custodio-restart.hook 's|^$||'
control_hook "name before the systemd hooks" 20-custodio-restart.hook 's|^$||'
control_hook "install too" "$HOOK" 's|^Operation = Upgrade|Operation = Install\nOperation = Upgrade|'
control_hook "removal" "$HOOK" 's|^Operation = Upgrade|Operation = Remove|'
control_hook "PreTransaction" "$HOOK" 's|^When = PostTransaction|When = PreTransaction|'
control_hook "AbortOnFail" "$HOOK" 's|^Exec = .*|&\nAbortOnFail|'
control_hook "another package" "$HOOK" 's|^Target = custodio|Target = *|'
control_hook "unconditional restart" "$HOOK" 's|^Exec = .*|Exec = /usr/bin/systemctl restart custodio.service|'

mutant() { # NAME SCRIPT SED-EXPRESSION
    local dir=$BF_DIR/mutant-$1
    rm -rf "$dir"
    cp -r "$ROOT/packaging/arch" "$dir"
    sed -i "$3" "$dir/$2"
    cmp -s "$dir/$2" "$ROOT/packaging/arch/$2" && { bad "mutant $1 changes nothing"; return; }
    SRC=$dir
    mutant_mode=1
    mutant_hit=0
    cases
    mutant_mode=0
    SRC=$ROOT/packaging/arch
    [ "$mutant_hit" = 1 ] || bad "mutant '$1' survived"
}
# The pre-install scripts (both).
for ms in pre_install pre_upgrade; do
    mutant "$ms-account-failure-ignored" "$ms" 's|custodio_create_account \|\| custodio_status=1|custodio_create_account \|\| true|'
    mutant "$ms-exit-after-check" "$ms" 's|^    custodio_status=1$|    exit 1|'
    mutant "$ms-account-before-check" "$ms" 's|^custodio_status=0$|custodio_create_account\ncustodio_status=0|'
    mutant "$ms-no-account" "$ms" 's|^custodio_create_account \|\| custodio_status=1|:|'
    mutant "$ms-check-ignored" "$ms" 's|if ! custodio_bus_check; then|if ! custodio_bus_check \|\| true; then|'
    # shellcheck disable=SC2016 # sed expression
    mutant "$ms-status-lost" "$ms" 's|^exit "\$custodio_status"|exit 0|'
    mutant "$ms-account-exit-lost" "$ms" 's|^        return 1$|        return 0|'
    mutant "$ms-useradd-fallback" "$ms" 's|^        return 1$|        useradd custodio; return 1|'
    mutant "$ms-enable" "$ms" 's|^custodio_status=0$|custodio_status=0\nsystemctl enable custodio.service|'
    mutant "$ms-delete-state" "$ms" 's|^custodio_status=0$|custodio_status=0\nrm -rf /var/lib/custodio/|'
    # shellcheck disable=SC2016 # sed expression
    mutant "$ms-reload" "$ms" 's|^exit "\$custodio_status"|systemctl daemon-reload\nexit "$custodio_status"|'
done
# The post scripts do nothing; anything added is a duplicate of a hook, a forbidden call or a state change.
for ms in post_install post_upgrade; do
    mutant "$ms-sysusers" "$ms" 's|^:$|systemd-sysusers custodio.conf \|\| true|'
    mutant "$ms-daemon-reload" "$ms" 's|^:$|systemctl daemon-reload \|\| true|'
    mutant "$ms-bus-reload" "$ms" 's|^:$|systemctl reload dbus.service \|\| true|'
    mutant "$ms-catalog" "$ms" 's|^:$|journalctl --update-catalog \|\| true|'
    mutant "$ms-enable" "$ms" 's|^:$|systemctl enable custodio.service|'
    mutant "$ms-start" "$ms" 's|^:$|systemctl start custodio.service|'
    mutant "$ms-preset" "$ms" 's|^:$|systemctl preset custodio.service|'
    mutant "$ms-restart" "$ms" 's|^:$|systemctl restart custodio.service|'
    mutant "$ms-try-restart" "$ms" 's|^:$|systemctl try-restart custodio.service|'
    mutant "$ms-delete-state" "$ms" 's|^:$|rm -rf /var/lib/custodio/|'
    mutant "$ms-stdout" "$ms" 's|^:$|echo hello|'
done
mutant pre_remove-no-stop pre_remove 's|^systemctl stop custodio.service.*|:|'
mutant pre_remove-no-tolerance pre_remove 's|^systemctl stop custodio.service.*|systemctl stop custodio.service|'
mutant pre_remove-disable pre_remove 's|^systemctl stop custodio.service.*|&\nsystemctl disable custodio.service|'
mutant pre_remove-remove-account pre_remove 's|^systemctl stop custodio.service.*|&\nuserdel custodio|'
mutant pre_remove-delete-state pre_remove 's|^systemctl stop custodio.service.*|&\nrm -rf /var/lib/private/custodio|'
mutant post_remove-no-final-stop post_remove 's|^    systemctl stop custodio.service.*|    :|'
mutant post_remove-unconditional-stop post_remove 's|^if systemctl is-active.*|systemctl stop custodio.service\n&|'
mutant post_remove-no-notice post_remove 's|destroys the keys for good|is risky|'
mutant post_remove-notice-word post_remove 's|the signing keys are still|the signing keys are yet|'
mutant post_remove-stdout-notice post_remove 's|^} >&2|}|'
mutant post_remove-delete-state post_remove 's|^if systemctl is-active.*|rm -rf /var/lib/custodio/\n&|'
mutant post_remove-delete-state-private post_remove 's|^if systemctl is-active.*|rm -rf /var/lib/private/custodio\n&|'
mutant post_remove-remove-account post_remove 's|^if systemctl is-active.*|userdel custodio\n&|'
mutant post_remove-daemon-reload post_remove 's|^if systemctl is-active.*|systemctl daemon-reload\n&|'
mutant post_remove-bus-reload post_remove 's|^if systemctl is-active.*|systemctl reload dbus.service\n&|'
mutant post_remove-chmod post_remove 's|^if systemctl is-active.*|chmod 755 /var/lib/custodio\n&|'
# The restart hook.
mutant hook-unconditional-restart "$HOOK" 's|^Exec = .*|Exec = /usr/bin/systemctl restart custodio.service|'
mutant hook-start "$HOOK" 's|^Exec = .*|Exec = /usr/bin/systemctl start custodio.service|'
mutant hook-on-install "$HOOK" 's|^Operation = Upgrade|Operation = Install\nOperation = Upgrade|'
mutant hook-on-remove "$HOOK" 's|^Operation = Upgrade|Operation = Upgrade\nOperation = Remove|'
mutant hook-pre-transaction "$HOOK" 's|^When = PostTransaction|When = PreTransaction|'
mutant hook-abort "$HOOK" 's|^When = .*|&\nAbortOnFail|'
mutant hook-all-packages "$HOOK" 's|^Target = custodio|Target = *|'
