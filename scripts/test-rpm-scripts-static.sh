#!/usr/bin/env bash
# Static gates on the four scriptlets of the .rpm (F44), read as text and as the built package says them (`rpm -qp --scripts`): no
# scriptlet names the state directory outside the notice, none changes the bus policy, the polkit action or the unit, none removes the
# account, deletes recursively or creates an account another way, none leaves an rpm macro unexpanded (nfpm writes the text as it is), and
# all four are plain executable sh. The runs are in scripts/test-rpm-lifecycle.sh; the stubs there fail the test on any call with a state path.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
SRC=$ROOT/packaging/rpm
fx_init
trap fx_cleanup EXIT
fail=0
bad() { echo "test-rpm-scripts-static: $*" >&2; fail=1; }
SCRIPTS=(pre post preun postun)

# Every line that names the state directory is on this list, with the file, the exact text and the reason (a pattern would hide a new use).
ALLOW_STATE=(
    'postun|        echo "custodio: the signing keys are still on disk in /var/lib/custodio (the real directory is /var/lib/private/custodio)."|the notice names where the keys are; it prints a path and never opens it'
)
# state_hits DIR: lines of the scriptlets in DIR that name the state directory and are not on the allowlist.
state_hits() {
    local f line entry a_file a_text a_why found
    for f in "${SCRIPTS[@]}"; do
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
# forbidden_hits DIR: commands and paths no scriptlet may use (the embedded F42 check holds none of them, so any hit is new).
forbidden_hits() {
    local f
    for f in "${SCRIPTS[@]}"; do
        grep -Ev '^[[:space:]]*(#|$)' "$1/$f" \
            | grep -E 'dbus-1|polkit-1|/lib/systemd|/etc/|custodio\.service\.d|systemctl +(edit|set-property|mask|enable|preset|start)|systemd-run|systemd-update-helper|useradd|groupadd|usermod|userdel|groupdel|rm +-[a-zA-Z]*r|chown|chmod|chgrp|sed +-i|\btee\b|\bcp\b|\bmv\b|\binstall +-' \
            | sed "s|^|$f: |" || true
    done
}
# macro_hits TEXT: an rpm macro left in a scriptlet text.
macro_hits() { grep -E '%\{|%systemd_|%sysusers_|%tmpfiles_' <<< "$1" || true; }

[ -z "$(state_hits "$SRC")" ] || bad "a scriptlet names the state directory in a line that is not on the allowlist: $(state_hits "$SRC")"
for entry in "${ALLOW_STATE[@]}"; do
    IFS='|' read -r a_file a_text _ <<< "$entry"
    grep -qxF "$a_text" "$SRC/$a_file" || bad "the allowlist entry for $a_file matches no line: $a_text"
done
[ -z "$(forbidden_hits "$SRC")" ] || bad "a scriptlet has a forbidden command or path: $(forbidden_hits "$SRC")"
for f in "${SCRIPTS[@]}"; do
    [ -z "$(macro_hits "$(cat "$SRC/$f")")" ] || bad "$f holds an rpm macro: $(macro_hits "$(cat "$SRC/$f")")"
    head -n 1 "$SRC/$f" | grep -qx '#!/bin/sh' || bad "$f does not start with #!/bin/sh"
    [ -x "$SRC/$f" ] || bad "$f is not executable"
    sh -n "$SRC/$f" || bad "$f: sh -n failed"
    shellcheck "$SRC/$f" || bad "$f: shellcheck failed"
done
# The marker path is the same in the two scriptlets that use it; the notice is the only output of %postun and nothing else prints on success.
for f in pre post; do grep -q '/run/custodio-restart-after-upgrade' "$SRC/$f" || bad "$f does not use the marker path"; done
[ "$(grep -c 'echo' "$SRC/postun")" -eq 3 ] || bad "postun prints other than the three lines of the notice"
! grep -E 'echo|printf' "$SRC/preun" > /dev/null || bad "preun prints"

# ---- the same gates on the built package ----
fx_build real 0.1.0 "" none
pkg=$(fx_file real rpm)
scripts=$(fx_rpm -qp --scripts "$pkg")
for tag in preinstall postinstall preuninstall postuninstall; do grep -q "^$tag scriptlet" <<< "$scripts" || bad "the built rpm has no $tag scriptlet"; done
[ -z "$(macro_hits "$scripts")" ] || bad "the built rpm has an unexpanded macro: $(macro_hits "$scripts")"
for tag in PRETRANS POSTTRANS; do [ -z "$(fx_rpm -qp --qf "%{$tag}" "$pkg" | grep -v '(none)' || true)" ] || bad "the built rpm has a $tag scriptlet"; done
# The scriptlets in the package are the source files.
for pair in PREIN:pre POSTIN:post PREUN:preun POSTUN:postun; do
    [ "$(fx_rpm -qp --qf "%{${pair%%:*}}" "$pkg")" = "$(cat "$SRC/${pair##*:}")" ] || bad "rpm ${pair%%:*} is not packaging/rpm/${pair##*:}"
done
[ -z "$(fx_rpm -qp --triggers "$pkg" | grep -v '^$' || true)" ] || bad "the built rpm has a trigger"

# ---- the gates see what they are meant to see (fixtures with one bad line each) ----
mkdir -p "$FX_DIR/bad"
try() { # LABEL BODY: a copy of the scriptlets with BODY appended to postun; the gate named by the label must see it
    rm -rf "$FX_DIR/bad/rpm"
    cp -r "$SRC" "$FX_DIR/bad/rpm"
    printf '%s\n' "$2" >> "$FX_DIR/bad/rpm/postun"
    case $1 in
    state) [ -n "$(state_hits "$FX_DIR/bad/rpm")" ] || bad "control '$2': the state gate did not see it" ;;
    forbidden) [ -n "$(forbidden_hits "$FX_DIR/bad/rpm")" ] || bad "control '$2': the forbidden gate did not see it" ;;
    macro) [ -n "$(macro_hits "$(cat "$FX_DIR/bad/rpm/postun")")" ] || bad "control '$2': the macro gate did not see it" ;;
    esac
}
try state 'rm -f /var/lib/custodio/key-1.p12'
try state 'echo x > /var/lib/private/custodio/new'
# shellcheck disable=SC2016 # the line is text for the gate
try state 'ls $STATE_DIRECTORY'
try forbidden 'sed -i s/x/y/ /usr/share/dbus-1/system.d/com.rfirma.Custodio1.conf'
try forbidden 'systemctl enable custodio.service'
try forbidden 'systemctl start custodio.service'
try forbidden 'systemd-run --unit x true'
try forbidden 'userdel custodio'
try forbidden 'useradd custodio'
try forbidden 'cp x /usr/share/polkit-1/actions/com.rfirma.custodio.policy'
try forbidden 'systemctl edit custodio.service'
try macro '%systemd_postun_with_restart custodio.service'
try macro '%sysusers_create_package custodio custodio.conf'
try macro 'echo %{_bindir}'
# A package built with a macro in a scriptlet is seen in `rpm -qp --scripts`.
{ cat "$SRC/postun"; echo '%systemd_postun_with_restart custodio.service'; } > "$FX_DIR/postun-macro"
python3 -I "$ROOT/scripts/lib/nfpm_edit.py" "$ROOT/packaging/nfpm.yaml" "$FX_DIR/nfpm-macro.yaml" script-set rpm postremove postun-macro
(cd "$FX_DIR" && NFPM_VERSION=0.1.0 NFPM_PRERELEASE='' nfpm package -f nfpm-macro.yaml -p rpm -t "$FX_DIR/out" > /dev/null)
macro_pkg=$(ls "$FX_DIR"/out/*.rpm)
[ -n "$(macro_hits "$(fx_rpm -qp --scripts "$macro_pkg")")" ] || bad "control: the macro gate did not see a macro in a built rpm"

exit "$fail"
