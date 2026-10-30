#!/usr/bin/env bash
# The file-list part of the package gate (scripts/check-packages.sh), on fixture packages built with nfpm:
# files, modes, owners, paths outside /usr, duplicates, the explicit list and the override allow-list.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"

fx_init
trap fx_cleanup EXIT
fail=0
bad() { echo "test-check-packages: $*" >&2; fail=1; }

CLI=/usr/bin/custodio
GATE=$ROOT/scripts/check-packages.sh
REAL=$ROOT/packaging/nfpm.yaml
LABELS=(deb rpm arch)

# gate DIR CONFIG: run the gate, output in $FX_DIR/gate.out, status in $?.
gate() { "$GATE" "$1" "$2" > "$FX_DIR/gate.out" 2>&1; }

# expect_ok LABEL DIR CONFIG
expect_ok() {
    gate "$2" "$3" || bad "$1: the gate failed: $(cat "$FX_DIR/gate.out")"
}
# expect_fail LABEL DIR CONFIG WORD...: non-zero exit and every WORD in the output.
expect_fail() {
    local label=$1 dir=$2 config=$3 word
    shift 3
    if gate "$dir" "$config"; then bad "$label: the gate passed"; return; fi
    for word in "$@"; do
        grep -qF -- "$word" "$FX_DIR/gate.out" || bad "$label: output lacks '$word': $(cat "$FX_DIR/gate.out")"
    done
}

fx_build good 0.1.0 '' none
expect_ok "good set" "$FX_DIR/out/good" "$REAL"

# Whole package missing, each format in turn.
for i in 0 1 2; do
    fmt=${FORMATS[$i]}
    fx_mix "nopkg-$fmt" good "$fmt" good
    rm -f "$(fx_file "nopkg-$fmt" "$fmt")"
    expect_fail "missing $fmt package" "$FX_DIR/out/nopkg-$fmt" "$REAL" "${LABELS[$i]}:"
done

# A file missing from one package only (a mode changed, an owner changed in one package), each format in turn.
fx_build nofile 0.1.0 '' drop $CLI
fx_build mode 0.1.0 '' mode $CLI 644
fx_build owner 0.1.0 '' owner $CLI custodio
fx_build group 0.1.0 '' group /usr/lib/custodio/custodiod custodio
for i in 0 1 2; do
    fmt=${FORMATS[$i]}
    fx_mix "m-$fmt" good "$fmt" nofile
    expect_fail "file missing from $fmt" "$FX_DIR/out/m-$fmt" "$REAL" "${LABELS[$i]}:" $CLI
    fx_mix "w-$fmt" good "$fmt" mode
    expect_fail "wrong mode in $fmt" "$FX_DIR/out/w-$fmt" "$REAL" "${LABELS[$i]}:" $CLI
    # nfpm writes numeric 0/0 for every Arch file whatever file_info says, so there the configuration is what fails.
    label=${LABELS[$i]}
    config=$REAL
    if [ "$fmt" = archlinux ]; then label=nfpm.yaml; config=
    fi
    fx_mix "o-$fmt" good "$fmt" owner
    expect_fail "wrong owner in $fmt" "$FX_DIR/out/o-$fmt" "${config:-$FX_DIR/nfpm-owner.yaml}" "$label:" $CLI custodio
    fx_mix "g-$fmt" good "$fmt" group
    expect_fail "wrong group in $fmt" "$FX_DIR/out/g-$fmt" "${config:-$FX_DIR/nfpm-group.yaml}" "$label:" /usr/lib/custodio/custodiod custodio
done

# Cases whose nfpm.yaml itself is wrong: the gate's explicit list is the reference, and all three formats fail.
config_case() { # NAME WORD... -- OP [ARG...]
    local name=$1 words=()
    shift
    while [ "$1" != -- ]; do words+=("$1"); shift; done
    shift
    fx_build "$name" 0.1.0 '' "$@"
    expect_fail "$name" "$FX_DIR/out/$name" "$FX_DIR/nfpm-$name.yaml" "${words[@]}"
}
config_case omit-entry /usr/share/p11-kit/modules/custodio.module -- drop /usr/share/p11-kit/modules/custodio.module
config_case cli-0644 $CLI deb: rpm: arch: -- mode $CLI 644
config_case extra-file /usr/share/extra deb: rpm: arch: -- add /usr/share/extra
config_case etc-file /etc/x deb: rpm: arch: -- add /etc/x
config_case var-file /var/x deb: rpm: arch: -- add /var/x
config_case config-entry config deb: rpm: arch: -- type /usr/share/p11-kit/modules/custodio.module config\|noreplace
fx_build dup-base 0.1.0 '' none # nfpm itself refuses to build a duplicate, so the gate gets the good packages and the bad list
python3 -I "$ROOT/scripts/lib/nfpm_edit.py" "$REAL" "$FX_DIR/nfpm-dup.yaml" dup $CLI
expect_fail duplicate "$FX_DIR/out/dup-base" "$FX_DIR/nfpm-dup.yaml" "listed twice" $CLI
config_case override-contents contents -- override-contents deb
config_case override-unknown suggests -- override-unknown rpm
exit "$fail"
