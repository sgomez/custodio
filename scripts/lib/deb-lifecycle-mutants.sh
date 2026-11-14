#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154 # the variables are set and read by the test that sources this file
# The mutants of the deb maintainer scripts for scripts/test-deb-lifecycle.sh, sourced by it after the controls: each is a copy of
# packaging/deb with one sed edit, run through all the cases; the test fails when a mutant survives or changes nothing.
# ---- mutants of the scripts: each must be caught by the cases above ----
mutant() { # NAME SCRIPT SED-EXPRESSION
    local dir=$BF_DIR/mutant-$1
    rm -rf "$dir"
    cp -r "$ROOT/packaging/deb" "$dir"
    sed -i "$3" "$dir/$2"
    cmp -s "$dir/$2" "$ROOT/packaging/deb/$2" && { bad "mutant $1 changes nothing"; return; }
    SRC=$dir
    mutant_mode=1
    mutant_hit=0
    cases
    mutant_mode=0
    SRC=$ROOT/packaging/deb
    [ "$mutant_hit" = 1 ] || bad "mutant '$1' survived"
}
mutant enable-in-postinst postinst 's|^    journalctl --update-catalog .*|&\n    systemctl enable custodio.service|'
# shellcheck disable=SC2016 # sed expressions
mutant restart-always postinst 's|if \[ -n "\$2" \] && \[ -e /run/custodio-restart-after-upgrade \]; then|if [ -n "$2" ]; then|'
# shellcheck disable=SC2016
mutant restart-on-install postinst 's|if \[ -n "\$2" \] && \[ -e /run/custodio-restart-after-upgrade \]; then|if [ -e /run/custodio-restart-after-upgrade ]; then|'
mutant restart-before-reload postinst 's|^    systemctl daemon-reload .*|    deb-systemd-invoke restart custodio.service\n&|'
mutant start-in-postinst postinst 's|^    journalctl --update-catalog .*|&\n    deb-systemd-invoke start custodio.service|'
mutant sysusers-ignored-failure preinst 's|custodio_create_account \|\| exit 1|custodio_create_account \|\| true|'
mutant sysusers-pipe-true preinst 's|^        return 1$|        return 0|'
# shellcheck disable=SC2016
mutant marker-always preinst 's|\[ "\$1" = upgrade \] && ||'
mutant stop-on-upgrade prerm 's|^remove)|remove \| upgrade)|'
mutant no-stop-on-remove prerm 's|^    deb-systemd-invoke stop custodio.service.*|    :|'
mutant delete-state postrm 's|^    systemctl daemon-reload .*|    rm -rf /var/lib/custodio/\n&|'
mutant delete-state-private postrm 's|^    systemctl daemon-reload .*|    rm -rf /var/lib/private/custodio\n&|'
mutant remove-account postrm 's|^    systemctl daemon-reload .*|    userdel custodio\n&|'
mutant no-notice postrm 's|destroys the keys for good|is risky|'
mutant no-final-stop postrm 's|^        deb-systemd-invoke stop custodio.service.*|        :|'
mutant no-bus-reload postinst 's|^    deb-systemd-invoke reload dbus.service.*|    :|'
mutant no-socket-enable postinst 's|^    systemctl enable custodio-firefox.socket.*|    :|'
mutant no-socket-stop prerm 's|^    deb-systemd-invoke stop custodio-firefox.socket.*|    :|'
mutant no-socket-disable prerm 's|^    systemctl disable custodio-firefox.socket.*|    :|'
mutant no-socket-final-stop postrm 's|^        deb-systemd-invoke stop custodio-firefox.socket.*|        :|'
mutant no-catalog postinst 's|^    journalctl --update-catalog.*|    :|'
mutant purge-differs postrm 's|^remove \| purge)|remove)|'
mutant stdout-notice postrm 's|^    } >&2|    }|'
