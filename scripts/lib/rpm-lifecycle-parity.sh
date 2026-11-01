#!/usr/bin/env bash
# shellcheck disable=SC2154 # root and err are set by the test that sources this file
# The parity cases of scripts/test-rpm-lifecycle.sh (F44), sourced by it: the deb scripts and the rpm scriptlets run in equal roots, scenario by
# scenario, and the observable decisions (calls in order, what is printed, the notice text) must be equal.
parity_cases() {
    # ---- parity with the deb: the same observable decisions, scenario by scenario ----
    # Each scenario runs the deb scripts and the rpm scriptlets in fresh equal roots and compares the normalized call lists.
    parity() { # LABEL ACTIVE(yes|no) DEBSTEPS RPMSTEPS: steps are "script:args" separated by spaces; sets deb_calls rpm_calls
        local label=$1 act=$2 step
        for fmt in deb rpm; do
            new_root
            printf 'custodio:x:996:996:Custodio:/:/usr/sbin/nologin\n' >> "$root/etc/passwd"
            [ "$act" = no ] || : > "$root/stub/active"
            lc_reset "$root"
            local dir=$DEB steps=$3
            [ "$fmt" = deb ] || { dir=$SRC; steps=$4; }
            for step in $steps; do
                read -ra step_args <<< "$(tr ',' ' ' <<< "${step#*:}")"
                lc_run "$root" "$dir/${step%%:*}" "${step_args[@]}"
            done
            if [ "$fmt" = deb ]; then deb_calls=$(lc_calls "$root" | normalize); deb_err=$err; else rpm_calls=$(lc_calls "$root" | normalize); rpm_err=$err; fi
            state_intact "parity $label ($fmt)"
        done
        [ "$deb_calls" = "$rpm_calls" ] || bad "parity $label: the deb calls were:"$'\n'"$deb_calls"$'\n'"the rpm calls were:"$'\n'"$rpm_calls"
        [ "$deb_err" = "$rpm_err" ] || bad "parity $label: the deb printed:"$'\n'"$deb_err"$'\n'"the rpm printed:"$'\n'"$rpm_err"
    }
    parity "install" no "preinst:install postinst:configure" "pre:1 post:1"
    parity "upgrade, running" yes "preinst:upgrade,0.1.0-1 prerm:upgrade,0.2.0-1 postinst:configure,0.1.0-1 postrm:upgrade,0.2.0-1" "pre:2 post:2 preun:1 postun:1"
    parity "upgrade, stopped" no "preinst:upgrade,0.1.0-1 postinst:configure,0.1.0-1" "pre:2 post:2 preun:1 postun:1"
    parity "removal" yes "prerm:remove postrm:remove" "preun:0 postun:0"
    # The deb's postrm is not part of the call comparison above for the notice alone, but its text is: one comparison of the three lines.
    notice_of() { grep -E '^ +echo "custodio: ' "$1" | sed -E 's/^ +echo //'; }
    [ -n "$(notice_of "$DEB/postrm")" ] || bad "parity: no notice found in the deb postrm"
    [ "$(notice_of "$DEB/postrm")" = "$(notice_of "$SRC/postun")" ] || bad "parity: the notice of the rpm %postun differs from the deb postrm"
}
