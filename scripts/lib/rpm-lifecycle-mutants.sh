#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154 # the variables are set and read by the test that sources this file
# The controls and the mutants of the rpm scriptlets for scripts/test-rpm-lifecycle.sh (F44), sourced by it after `cases`. The controls prove that the
# state check sees a bad scriptlet; each mutant is a copy of packaging/rpm with one sed edit, run through all the cases with SRC pointing at it;
# the test fails when a mutant survives or changes nothing.
# ---- the stubs are checked: a bad scriptlet is seen ----
bad_script() { # NAME BODY
    mkdir -p "$BF_DIR/bad"
    { printf '#!/bin/sh\n'; printf '%s\n' "$2"; } > "$BF_DIR/bad/$1"
}
control() { # LABEL BODY: the state check must fail for a scriptlet with that body
    bad_script ctl "$2"
    new_root
    lc_run "$root" "$BF_DIR/bad/ctl" 0
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

mutant() { # NAME SCRIPT SED-EXPRESSION
    local dir=$BF_DIR/mutant-$1
    rm -rf "$dir"
    cp -r "$ROOT/packaging/rpm" "$dir"
    sed -i "$3" "$dir/$2"
    cmp -s "$dir/$2" "$ROOT/packaging/rpm/$2" && { bad "mutant $1 changes nothing"; return; }
    SRC=$dir
    mutant_mode=1
    mutant_hit=0
    cases
    mutant_mode=0
    SRC=$ROOT/packaging/rpm
    [ "$mutant_hit" = 1 ] || bad "mutant '$1' survived"
}
mutant enable-in-post post 's|^journalctl --update-catalog .*|&\nsystemctl enable custodio.service|'
mutant preset-in-post post 's|^journalctl --update-catalog .*|&\nsystemctl preset custodio.service|'
mutant start-in-post post 's|^journalctl --update-catalog .*|&\nsystemctl start custodio.service|'
# shellcheck disable=SC2016 # sed expressions
mutant restart-always post 's|if \[ "\${1:-0}" -ge 2 \] && \[ -e /run/custodio-restart-after-upgrade \]; then|if [ "${1:-0}" -ge 2 ]; then|'
# shellcheck disable=SC2016
mutant restart-on-install post 's|-ge 2 \] && \[ -e /run|-ge 1 ] \&\& [ -e /run|'
# shellcheck disable=SC2016
mutant restart-no-count post 's|if \[ "\${1:-0}" -ge 2 \] && |if |'
# shellcheck disable=SC2016
mutant restart-eq-1 post 's|-ge 2 \] && \[ -e /run|-eq 1 ] \&\& [ -e /run|'
mutant restart-before-reload post 's|^systemctl daemon-reload .*|systemctl restart custodio.service\n&|'
mutant restart-before-bus-reload post 's|^systemctl reload dbus.service .*|systemctl restart custodio.service\n&|'
mutant restart-before-catalog post 's|^journalctl --update-catalog .*|systemctl restart custodio.service\n&|'
mutant restart-twice post 's|^exit 0|systemctl restart custodio.service\nexit 0|'
# shellcheck disable=SC2016
mutant restart-also-in-postun postun 's|^if \[ "\${1:-1}" -eq 0 \]; then|[ "${1:-1}" -ge 1 ] \&\& systemctl restart custodio.service\n&|'
# shellcheck disable=SC2016
mutant restart-only-in-postun-old post '/^if \[ "\${1:-0}" -ge 2 \]/,/^fi/d'
mutant no-bus-reload post 's|^systemctl reload dbus.service.*|:|'
mutant no-daemon-reload post 's|^systemctl daemon-reload.*|:|'
mutant no-catalog post 's|^journalctl --update-catalog.*|:|'
mutant reload-order post 's|^systemctl daemon-reload .*|systemctl reload dbus.service \|\| true\n&|'
mutant sysusers-ignored-failure pre 's|custodio_create_account \|\| exit 1|custodio_create_account \|\| true|'
mutant sysusers-return0 pre 's|^        return 1$|        return 0|'
mutant account-before-check pre 's|^custodio_bus_check \|\| exit 1|custodio_create_account \|\| exit 1\n&|'
mutant account-not-in-pre pre 's|^custodio_create_account \|\| exit 1|:|'
# shellcheck disable=SC2016
mutant marker-always pre 's|\[ "\${1:-0}" -ge 2 \] \&\& ||'
# shellcheck disable=SC2016
mutant marker-on-install pre 's|-ge 2 \] \&\& systemctl|-ge 1 ] \&\& systemctl|'
mutant marker-write-fatal pre 's|( : > /run/custodio-restart-after-upgrade ) 2>/dev/null \|\| true|: > /run/custodio-restart-after-upgrade|'
mutant bus-check-exit-lost pre 's|^custodio_bus_check \|\| exit 1|custodio_bus_check \|\| true|'
mutant stop-on-upgrade preun 's|-eq 0 \]|-ge 0 ]|'
mutant stop-on-upgrade-eq1 preun 's|-eq 0 \]|-eq 1 ]|'
mutant no-stop-on-erase preun 's|^    systemctl stop custodio.service.*|    :|'
mutant notice-on-upgrade postun 's|-eq 0 \]|-ge 0 ]|'
mutant notice-eq1 postun 's|-eq 0 \]|-eq 1 ]|'
mutant delete-state postun 's|^    systemctl daemon-reload .*|    rm -rf /var/lib/custodio/\n&|'
mutant delete-state-private postun 's|^    systemctl daemon-reload .*|    rm -rf /var/lib/private/custodio\n&|'
mutant remove-account postun 's|^    systemctl daemon-reload .*|    userdel custodio\n&|'
mutant no-notice postun 's|destroys the keys for good|is risky|'
mutant notice-word postun 's|the signing keys are still|the signing keys are yet|'
mutant no-final-stop postun 's|^        systemctl stop custodio.service.*|        :|'
mutant no-reload-in-postun postun 's|^    systemctl reload dbus.service.*|    :|'
mutant stdout-notice postun 's|^    } >&2|    }|'
mutant stop-in-post post 's|^journalctl --update-catalog .*|&\nsystemctl stop custodio.service|'
