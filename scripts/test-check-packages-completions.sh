#!/usr/bin/env bash
# The completion rules of the package gate (scripts/check-packages.sh), on fixture packages built with nfpm from the real packaging/nfpm.yaml: a clean set the
# gate accepts, with the three files at the places docs/findings/F191.md decided (mode 0644, root:root); each of the three files dropped from each format (nine cases)
# and the .deb's zsh file placed in site-functions, each failing with a line that names the format and the path; and the parity rule, which fails on the zsh paths when
# their exceptions are missing from a copy of packaging/parity-exceptions.txt. The cases build and run in parallel.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"

fx_init
trap fx_cleanup EXIT
fail=0

GATE=$ROOT/scripts/check-packages.sh
BASH_F=/usr/share/bash-completion/completions/custodio
FISH_F=/usr/share/fish/vendor_completions.d/custodio.fish
ZSH_VENDOR=/usr/share/zsh/vendor-completions/_custodio
ZSH_SITE=/usr/share/zsh/site-functions/_custodio

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

# listing NAME FORMAT PATH MODE: the package of that format holds PATH as a regular file of that mode owned by root:root.
listing() {
    local name=$1 fmt=$2 path=$3 mode=$4 line re
    case $fmt in
    deb) line=$(dpkg-deb --contents "$(fx_file "$name" deb)" | grep -F " .$path" || true) ;;
    rpm) line=$(fx_rpm -qp --qf '[%{FILENAMES} %{FILEMODES:perms} %{FILEUSERNAME} %{FILEGROUPNAME}\n]' "$(fx_file "$name" rpm)" | grep -F "$path " || true) ;;
    archlinux) line=$(bsdtar -tvf "$(fx_file "$name" archlinux)" | grep -F " ${path#/}" || true) ;;
    esac
    case $fmt in
    deb) [[ $line == "-$mode root/root"* ]] ;;
    rpm) [[ $line == "$path -$mode root root" ]] ;;
    archlinux) re="^-${mode}[[:space:]]+[0-9]+[[:space:]]+(root|0)[[:space:]]+(root|0)[[:space:]]"; [[ $line =~ $re ]] ;;
    esac || echo "$name: $fmt lacks $path with mode $mode root:root: '$line'"
}

# The clean set: the gate accepts it and the three listings hold.
clean() {
    run_case clean yes -- none
    local fmt zsh
    for fmt in deb rpm archlinux; do
        zsh=$ZSH_SITE
        [ "$fmt" != deb ] || zsh=$ZSH_VENDOR
        listing clean "$fmt" "$BASH_F" rw-r--r--
        listing clean "$fmt" "$FISH_F" rw-r--r--
        listing clean "$fmt" "$zsh" rw-r--r--
    done
}

# parity: the gate on the clean set (fixture of case clean) with the committed exceptions passes, and fails without the zsh ones.
parity() {
    local exc=$ROOT/packaging/parity-exceptions.txt
    "$ROOT/scripts/check-parity.sh" "$FX_DIR/out/clean" "$exc" > "$FX_DIR/parity-yes.out" 2>&1 || { echo "parity: failed with the committed exceptions: $(cat "$FX_DIR/parity-yes.out")"; return 0; }
    grep -vF "$ZSH_VENDOR" "$exc" > "$FX_DIR/exceptions-without-zsh.txt"
    if "$ROOT/scripts/check-parity.sh" "$FX_DIR/out/clean" "$FX_DIR/exceptions-without-zsh.txt" > "$FX_DIR/parity-no.out" 2>&1; then
        echo "parity: passed without the exception for $ZSH_VENDOR"
    elif ! grep -qF "$ZSH_VENDOR" "$FX_DIR/parity-no.out"; then
        echo "parity: failed without naming $ZSH_VENDOR: $(cat "$FX_DIR/parity-no.out")"
    fi
}

pids=()
launch_case() { run_case "$@" > "$FX_DIR/result-$1.txt" 2>&1 & pids+=($!); }
for fmt in deb rpm archlinux; do
    label=${fmt/archlinux/arch}
    zsh=$ZSH_SITE
    [ "$fmt" != deb ] || zsh=$ZSH_VENDOR
    launch_case "no-bash-$label" no "$label|$BASH_F" -- drop-for "$fmt" "$BASH_F"
    launch_case "no-fish-$label" no "$label|$FISH_F" -- drop-for "$fmt" "$FISH_F"
    launch_case "no-zsh-$label" no "$label|$zsh" -- drop-for "$fmt" "$zsh"
done
launch_case deb-zsh-in-site-functions no "deb|$ZSH_VENDOR" "deb|$ZSH_SITE" -- redst deb "$ZSH_VENDOR" "$ZSH_SITE"
# The listings and the parity rule use the clean set, built here once.
( clean; parity ) > "$FX_DIR/result-listings.txt" 2>&1 &
pids+=($!)
for p in "${pids[@]}"; do wait "$p" || true; done
for f in "$FX_DIR"/result-*.txt; do
    [ ! -s "$f" ] || { sed 's/^/test-check-packages-completions: /' "$f" >&2; fail=1; }
done
exit "$fail"
