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
fx_build group 0.1.0 '' group /usr/libexec/custodio/custodiod custodio
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
    expect_fail "wrong group in $fmt" "$FX_DIR/out/g-$fmt" "${config:-$FX_DIR/nfpm-group.yaml}" "$label:" /usr/libexec/custodio/custodiod custodio
done

# The daemon where each distribution wants it (F61): /usr/libexec/custodio in the .deb and the .rpm, /usr/lib/custodio in the Arch package. A package with
# the daemon at the path of another format fails with a message naming the path; so does a unit whose ExecStart is not the daemon of its own package.
fx_build deb-lib 0.1.0 '' daemon deb /usr/lib/custodio/custodiod
fx_build rpm-lib 0.1.0 '' daemon rpm /usr/lib/custodio/custodiod
fx_build arch-libexec 0.1.0 '' daemon archlinux /usr/libexec/custodio/custodiod
fx_mix wrong-deb good deb deb-lib
expect_fail "a .deb with the daemon at the Arch path" "$FX_DIR/out/wrong-deb" "$REAL" "deb:" "/usr/libexec/custodio/custodiod is missing" "/usr/lib/custodio/custodiod is not in the expected file list"
fx_mix wrong-rpm good rpm rpm-lib
expect_fail "an .rpm with the daemon at the Arch path" "$FX_DIR/out/wrong-rpm" "$REAL" "rpm:" "/usr/libexec/custodio/custodiod is missing" "/usr/lib/custodio/custodiod is not in the expected file list"
fx_mix wrong-arch good archlinux arch-libexec
expect_fail "an Arch package with the daemon at the libexec path" "$FX_DIR/out/wrong-arch" "$REAL" "arch:" "/usr/lib/custodio/custodiod is missing" "/usr/libexec/custodio/custodiod is not in the expected file list"
# The same, as a mistake of nfpm.yaml.
for fmt in deb rpm; do
    expect_fail "nfpm.yaml: the $fmt daemon at the Arch path" "$FX_DIR/out/good" "$FX_DIR/nfpm-$fmt-lib.yaml" "nfpm.yaml:" "/usr/libexec/custodio/custodiod is missing from the file list of $fmt" "/usr/lib/custodio/custodiod is not in the expected file list of $fmt"
done
expect_fail "nfpm.yaml: the Arch daemon at the libexec path" "$FX_DIR/out/good" "$FX_DIR/nfpm-arch-libexec.yaml" "nfpm.yaml:" "/usr/lib/custodio/custodiod is missing from the file list of arch"
# ExecStart: a unit that names the other format's path, in each package.
for fmt in deb rpm archlinux; do
    other=$FX_DIR/unit-other-$fmt
    mkdir -p "$other"
    case $fmt in
    archlinux) sed 's#^ExecStart=.*#ExecStart=/usr/libexec/custodio/custodiod#' "$ROOT/data/custodio.service" > "$other/custodio.service" ;;
    *) cp "$ROOT/data/custodio.service" "$other/custodio.service" ;; # still the Arch path
    esac
    fx_build "unit-$fmt" 0.1.0 '' unit-src "$fmt" "$other/custodio.service"
    label=${fmt/archlinux/arch}
    case $fmt in archlinux) path=/usr/libexec/custodio/custodiod ;; *) path=/usr/lib/custodio/custodiod ;; esac
    fx_mix "unit-mix-$fmt" good "$fmt" "unit-$fmt"
    expect_fail "the unit of the $label package names $path" "$FX_DIR/out/unit-mix-$fmt" "$FX_DIR/nfpm-unit-$fmt.yaml" "$label:" "ExecStart of the unit is ['$path']"
done
# The derivation: the three units come from the one source and differ in the ExecStart line only; a source that the derivation cannot rewrite is refused.
DERIVE=$ROOT/scripts/derive-units.sh
"$DERIVE" "$ROOT/data/custodio.service" "$FX_DIR/units-ok" || bad "derive-units failed on the repository's unit"
for fmt in deb rpm archlinux; do
    [ "$(diff "$ROOT/data/custodio.service" "$FX_DIR/units-ok/$fmt/custodio.service" | grep -c '^>')" -le 1 ] || bad "derive-units: the $fmt unit differs in more than one line"
done
grep -qx 'ExecStart=/usr/libexec/custodio/custodiod' "$FX_DIR/units-ok/deb/custodio.service" || bad "derive-units: the .deb unit lacks the libexec ExecStart"
grep -qx 'ExecStart=/usr/libexec/custodio/custodiod' "$FX_DIR/units-ok/rpm/custodio.service" || bad "derive-units: the .rpm unit lacks the libexec ExecStart"
cmp -s "$ROOT/data/custodio.service" "$FX_DIR/units-ok/archlinux/custodio.service" || bad "derive-units: the Arch unit is not the source"
derive_fails() { # NAME WORD SRC_DIR: the derivation refuses the unit in SRC_DIR
    if "$DERIVE" "$3/custodio.service" "$FX_DIR/units-$1" > "$FX_DIR/derive.out" 2>&1; then bad "derive-units accepted: $1"; return; fi
    grep -qF -- "$2" "$FX_DIR/derive.out" || bad "derive-units ($1): output lacks '$2': $(cat "$FX_DIR/derive.out")"
}
mkdir -p "$FX_DIR/src-twice" "$FX_DIR/src-hard" "$FX_DIR/src-second" "$FX_DIR/src-other" "$FX_DIR/src-libexec"
{ cat "$ROOT/data/custodio.service"; echo 'ExecStartPost=/usr/lib/custodio/custodiod --check'; } > "$FX_DIR/src-hard/custodio.service"
derive_fails hard-coded-path "outside the ExecStart line" "$FX_DIR/src-hard"
{ cat "$ROOT/data/custodio.service"; echo 'ExecStart=/bin/true'; } > "$FX_DIR/src-twice/custodio.service"
derive_fails two-execstart "exactly one ExecStart" "$FX_DIR/src-twice"
sed 's#^ExecStart=.*#ExecStart=/usr/bin/other#' "$ROOT/data/custodio.service" > "$FX_DIR/src-other/custodio.service"
derive_fails other-execstart "is not /usr/lib/custodio/custodiod" "$FX_DIR/src-other"
sed 's#^ExecStart=.*#ExecStart=/usr/libexec/custodio/custodiod#' "$ROOT/data/custodio.service" > "$FX_DIR/src-libexec/custodio.service"
derive_fails libexec-source "is not /usr/lib/custodio/custodiod" "$FX_DIR/src-libexec"
cp "$ROOT/data/custodio.service" "$FX_DIR/src-second/custodio.service"
cp "$ROOT/data/custodio.service" "$FX_DIR/src-second/custodio-libexec.service"
derive_fails second-unit-file "a second unit file" "$FX_DIR/src-second"

# The rpm-only directories (F49: rpm owns no directory it is not told about, so `dnf remove` would leave them behind).
fx_build nodir 0.1.0 '' drop /usr/lib/custodio
expect_fail "rpm without an owned directory" "$FX_DIR/out/nodir" "$REAL" "rpm:" "the directory /usr/lib/custodio is missing from the package"
expect_fail "nfpm.yaml without an owned directory" "$FX_DIR/out/good" "$FX_DIR/nfpm-nodir.yaml" "the rpm-only directory /usr/lib/custodio is missing"
fx_build nolibexecdir 0.1.0 '' drop /usr/libexec/custodio
expect_fail "rpm without the libexec directory" "$FX_DIR/out/nolibexecdir" "$REAL" "rpm:" "the directory /usr/libexec/custodio is missing from the package"
fx_build dirmode 0.1.0 '' mode /usr/share/doc/custodio 700
expect_fail "a wrong directory mode in rpm" "$FX_DIR/out/dirmode" "$REAL" "rpm:" "the directory /usr/share/doc/custodio has mode 700, expected 755"
fx_build dirall 0.1.0 '' unpackager /usr/lib/custodio
expect_fail "an owned directory for every format" "$FX_DIR/out/good" "$FX_DIR/nfpm-dirall.yaml" "the directory /usr/lib/custodio is not one of the rpm-only directories"
fx_build dirextra 0.1.0 '' dir /usr/share/custodio-extra 755
expect_fail "an extra directory" "$FX_DIR/out/dirextra" "$FX_DIR/nfpm-dirextra.yaml" "the directory /usr/share/custodio-extra is not one of the rpm-only directories"

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
# e2e/run.sh finds the package in target/packages with a `find` line: run that line from the script in a temp tree holding one fixture
# .deb, and a copy of the script without the line must be seen as lacking it.
bash -n "$ROOT/e2e/run.sh" || { echo "FAIL: e2e/run.sh syntax" >&2; fail=1; }
e2e_tmp=$(mktemp -d)
mkdir -p "$e2e_tmp/target/packages"
cp "$(fx_file dup-base deb)" "$e2e_tmp/target/packages/"
# shellcheck disable=SC2016 # the line is text to find in the script and to run in a child shell
find_line='found=$(find "$packages" -name "$pattern" | sort | tail -n 1)'
grep -qF "$find_line" "$ROOT/e2e/run.sh" || { echo "FAIL: e2e/run.sh find line" >&2; fail=1; }
grep -vF "$find_line" "$ROOT/e2e/run.sh" > "$e2e_tmp/run-without-find.sh"
if grep -qF "$find_line" "$e2e_tmp/run-without-find.sh"; then echo "FAIL: control for the e2e/run.sh find line" >&2; fail=1; fi
e2e_pattern=$(head -n 1 "$ROOT/e2e/targets/debian13/package.pattern")
e2e_found=$(cd "$e2e_tmp" && packages=target/packages pattern=$e2e_pattern bash -c "$find_line; echo \"\$found\"")
rm -rf "$e2e_tmp"
case $e2e_found in target/packages/custodio_*.deb) ;; *) echo "FAIL: e2e/run.sh found '$e2e_found'" >&2; fail=1 ;; esac
exit "$fail"
