#!/usr/bin/env bash
# The PAM and notice rules of the package gate (scripts/check-packages.sh), on fixture packages built with nfpm: a clean set the gate accepts and one negative
# control per rule and format: a file under /etc/pam.d or /usr/lib/pam.d (the fixture config lists it, so only that rule can fail), a script that is not the
# install script naming /etc/pam.d, and an install script lacking either phrase of the notice. The cases build and run in parallel.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"

fx_init
trap fx_cleanup EXIT
fail=0

GATE=$ROOT/scripts/check-packages.sh
ENABLE='sudo custodio fingerprint enable'
DOCTOR='custodio doctor'

# script_case NAME KIND: $FX_DIR/cases/NAME holds, for each format, the install script (KIND no-enable or no-doctor: the notice lacks that phrase) or
# the post-removal script (KIND pam: it names the PAM directory), both made from the real scripts.
script_case() {
    local name=$1 kind=$2 fmt dir
    mkdir -p "$FX_DIR/cases/$name"
    for fmt in deb rpm archlinux; do
        dir=$FX_DIR/packaging/${fmt/archlinux/arch}
        case $fmt:$kind in
        deb:*) inst=postinst rem=postrm ;;
        rpm:*) inst=post rem=postun ;;
        archlinux:*) inst=post_install rem=post_remove ;;
        esac
        case $kind in
        no-enable) sed "s|$ENABLE|sudo custodio fingerprint enabl|" "$dir/$inst" > "$FX_DIR/cases/$name/$fmt-postinstall" ;;
        no-doctor) sed "s|$DOCTOR|custodio docto|" "$dir/$inst" > "$FX_DIR/cases/$name/$fmt-postinstall" ;;
        pam) { cat "$dir/$rem"; echo '# /etc/pam.d/polkit-1'; } > "$FX_DIR/cases/$name/$fmt-postremove" ;;
        esac
    done
}

# run_case NAME EXPECT WORD... -- OP [ARG...]: build the packages of an edited list and run the gate on them and that list. With yes the gate must pass; with no it
# must fail, and for each WORD (FORMAT|TEXT) a line starting with the format label must hold the text.
run_case() {
    local name=$1 want=$2 word fmt
    shift 2
    local words=()
    while [ "$1" != -- ]; do words+=("$1"); shift; done
    shift
    fx_build "$name" 0.1.0 '' "$@" || { echo "$name: build failed"; return 0; }
    if "$GATE" "$FX_DIR/out/$name" "$FX_DIR/nfpm-$name.yaml" > "$FX_DIR/$name.out" 2>&1; then
        [ "$want" = yes ] || echo "$name: the gate passed"
        return 0
    fi
    [ "$want" = no ] || { echo "$name: the gate failed: $(cat "$FX_DIR/$name.out")"; return 0; }
    for word in "${words[@]}"; do
        fmt=${word%%|*}
        grep -E "FAIL $fmt: " "$FX_DIR/$name.out" | grep -qF -- "${word#*|}" || echo "$name: no '$fmt:' line with '${word#*|}': $(cat "$FX_DIR/$name.out")"
    done
}

script_case no-enable no-enable
script_case no-doctor no-doctor
script_case names-pam pam

pids=()
launch() { run_case "$@" > "$FX_DIR/result-$1.txt" 2>&1 & pids+=($!); }
launch clean yes -- none
launch pam-usr no 'deb|PAM directory' 'deb|/usr/lib/pam.d/x' 'rpm|PAM directory' 'rpm|/usr/lib/pam.d/x' 'arch|PAM directory' 'arch|/usr/lib/pam.d/x' -- add /usr/lib/pam.d/x
launch pam-etc no 'deb|PAM directory' 'deb|/etc/pam.d/x' 'rpm|PAM directory' 'rpm|/etc/pam.d/x' 'arch|PAM directory' 'arch|/etc/pam.d/x' -- add /etc/pam.d/x
launch names-pam no 'deb|postrm' 'deb|/etc/pam.d' 'rpm|postun' 'rpm|/etc/pam.d' 'arch|.INSTALL' 'arch|/etc/pam.d' -- scripts-dir "$FX_DIR/cases/names-pam"
launch no-enable no "deb|postinst" "deb|$ENABLE" "rpm|post" "rpm|$ENABLE" "arch|.INSTALL" "arch|$ENABLE" -- scripts-dir "$FX_DIR/cases/no-enable"
launch no-doctor no "deb|postinst" "deb|$DOCTOR" "rpm|post" "rpm|$DOCTOR" "arch|.INSTALL" "arch|$DOCTOR" -- scripts-dir "$FX_DIR/cases/no-doctor"
for p in "${pids[@]}"; do wait "$p" || true; done
for f in "$FX_DIR"/result-*.txt; do
    [ ! -s "$f" ] || { sed 's/^/test-check-packages-pam: /' "$f" >&2; fail=1; }
done
exit "$fail"
