#!/usr/bin/env bash
# Tests of scripts/check-glibc-ceiling.sh on fixture packages (scripts/lib/package-fixtures.sh) carrying real fixture ELF files.
# The host glibc differs between machines, so no case depends on it relative to the committed ceiling: the fixture's real
# highest version V is read with readelf, and the cases use their own ceiling files set around V.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"

command -v gcc >/dev/null || { echo "test-glibc-ceiling: required tool 'gcc' is not installed" >&2; exit 1; }
fx_init
trap fx_cleanup EXIT
fail=0
bad() { echo "test-glibc-ceiling: $*" >&2; fail=1; }

GATE=$ROOT/scripts/check-glibc-ceiling.sh
COMMITTED=$ROOT/packaging/glibc-ceiling.txt
REL=$FX_DIR/target/release
SRC=$FX_DIR/src
mkdir -p "$SRC"

gate() { "$GATE" "$@" > "$FX_DIR/gate.out" 2>&1; }
expect_ok() { # LABEL ARG...
    local label=$1
    shift
    gate "$@" || bad "$label: the gate failed: $(cat "$FX_DIR/gate.out")"
}
expect_fail() { # LABEL WORD... -- ARG...
    local label=$1 words=() word
    shift
    while [ "$1" != -- ]; do words+=("$1"); shift; done
    shift
    if gate "$@"; then bad "$label: the gate passed"; return; fi
    for word in "${words[@]}"; do
        grep -qF -- "$word" "$FX_DIR/gate.out" || bad "$label: output lacks '$word': $(cat "$FX_DIR/gate.out")"
    done
}
ceiling_file() { printf 'ceiling = %s\n' "$2" > "$FX_DIR/$1.txt"; }
# set_elf FILE...: the fixture ELF used for the three binaries of the next fx_build.
set_elf() { cp "$1" "$REL/custodiod"; cp "$1" "$REL/custodio-cli"; cp "$1" "$REL/libcustodio_pkcs11.so"; }
highest() { readelf -W -V "$1" | sed -n 's/.*Name: GLIBC_\([0-9][0-9.]*\) .*/\1/p' | sort -V | tail -n 1; }
needs() { readelf -W -V "$1" | sed -n 's/.*Name: \(GLIBC_[^ ]*\) .*/\1/p'; }

# The fixture ELF files.
echo 'int main(void) { return 0; }' > "$SRC/plain.c"
gcc -s -o "$SRC/plain" "$SRC/plain.c"
gcc -static -o "$SRC/static" "$SRC/plain.c"
V=$(highest "$SRC/plain")
IFS=. read -ra parts <<< "$V"
last=$((${#parts[@]} - 1))
[ "${parts[$last]}" -ge 1 ] || bad "the fixture's highest version $V has no previous minor"
prefix=$(IFS=.; echo "${parts[*]:0:last}")${last:+.}
BELOW=$prefix$((parts[last] - 1))
ABOVE=$prefix$((parts[last] + 1))

# GLIBC_PRIVATE: a real .symver reference to a GLIBC_PRIVATE object of the host libc. If the linker refuses it (for
# example the binutils of the ubuntu-24.04 CI runner) the test fails: there is no skip and no fallback. The CI run on
# ubuntu-24.04 is what proves the fixture links there.
libc=$(gcc -print-file-name=libc.so.6)
privs=$(readelf -W --dyn-syms "$libc" | sed -n 's/.* OBJECT .* \([A-Za-z_0-9]*\)@GLIBC_PRIVATE.*/\1/p')
[ -n "$privs" ] || bad "no GLIBC_PRIVATE object found in $libc"
priv=$(grep -x '__libc_enable_secure' <<< "$privs" || head -n 1 <<< "$privs")
cat > "$SRC/private.c" <<EOC
extern int pv;
__asm__(".symver pv, ${priv}@GLIBC_PRIVATE");
int main(void) { return pv; }
EOC
gcc -o "$SRC/private" "$SRC/private.c" || bad "the linker refused the GLIBC_PRIVATE fixture reference to $priv"

# Byte-patched copies: assert the patch took, so a broken patch cannot pass vacuously.
patch() { # VERSION: SRC/patched-VERSION from plain
    python3 -I "$ROOT/scripts/lib/elf_patch.py" "$SRC/plain" "$SRC/patched-$1" "$1" || bad "patching $1 failed"
    [ "$(needs "$SRC/patched-$1" | grep -c "^GLIBC_$1\$")" -eq 1 ] || bad "readelf does not show GLIBC_$1 exactly once"
    ! needs "$SRC/patched-$1" | grep -qx 'GLIBC_2.34' || bad "readelf still shows GLIBC_2.34 after patching $1"
}
for v in 2.0 2.9 2.10 2.99; do patch "$v"; done

# deb_add NAME DEST SRC: add a file to the deb of case NAME only.
deb_add() {
    local deb tree=$FX_DIR/debtree-$1
    deb=$(fx_file "$1" deb)
    rm -rf "$tree"
    dpkg-deb -R "$deb" "$tree"
    mkdir -p "$(dirname "$tree$2")"
    cp "$3" "$tree$2"
    dpkg-deb --root-owner-group -b "$tree" "$deb" > /dev/null
}

# Ceiling around V: below fails, equal and above pass.
set_elf "$SRC/plain"
fx_build plain 0.1.0 '' none
D=$FX_DIR/out/plain
ceiling_file below "$BELOW"; ceiling_file equal "$V"; ceiling_file above "$ABOVE"
expect_fail "ceiling below $V" "GLIBC_$V" "$BELOW" deb rpm arch /usr/bin/custodio -- "$D" "$FX_DIR/below.txt"
expect_ok "ceiling equal to $V" "$D" "$FX_DIR/equal.txt"
expect_ok "ceiling above $V" "$D" "$FX_DIR/above.txt"
n=$(grep -c ' highest ' "$FX_DIR/gate.out")
[ "$n" -eq 9 ] || bad "expected 9 ELF lines (three per package), got $n"
for f in /usr/bin/custodio /usr/lib/custodio/libcustodio_pkcs11.so; do
    [ "$(grep -c " $f highest $V" "$FX_DIR/gate.out")" -eq 3 ] || bad "$f is not listed once per package with highest $V"
done
# the daemon: at /usr/libexec in the .deb and the .rpm (two lines), at /usr/lib in the Arch package (one) (F61)
[ "$(grep -c " /usr/libexec/custodio/custodiod highest $V" "$FX_DIR/gate.out")" -eq 2 ] || bad "the daemon is not listed in the .deb and the .rpm at /usr/libexec with highest $V"
[ "$(grep -c " /usr/lib/custodio/custodiod highest $V" "$FX_DIR/gate.out")" -eq 1 ] || bad "the daemon is not listed in the Arch package at /usr/lib with highest $V"

# Without a ceiling argument the committed file is used (the patched 2.0 still needs GLIBC_2.2.5 from the plain fixture).
committed=$(sed -n 's/^ceiling = //p' "$COMMITTED")
set_elf "$SRC/patched-2.99"; fx_build v299 0.1.0 '' none
expect_fail "2.99 against the committed ceiling" "GLIBC_2.99" "$committed" -- "$FX_DIR/out/v299"
set_elf "$SRC/patched-2.0"; fx_build v20 0.1.0 '' none
expect_ok "2.0 against the committed ceiling" "$FX_DIR/out/v20"
grep -qF " highest 2.2.5 (ceiling $committed)" "$FX_DIR/gate.out" || bad "output does not show the highest version and the committed ceiling"

# Numeric comparison: 2.10 is above 2.9 and 2.9 is below 2.10 (a string comparison gets both wrong).
set_elf "$SRC/patched-2.10"; fx_build v210 0.1.0 '' none
ceiling_file c29 2.9; ceiling_file c210 2.10
expect_fail "2.10 against ceiling 2.9" "GLIBC_2.10" -- "$FX_DIR/out/v210" "$FX_DIR/c29.txt"
set_elf "$SRC/patched-2.9"; fx_build v29 0.1.0 '' none
expect_ok "2.9 against ceiling 2.10" "$FX_DIR/out/v29" "$FX_DIR/c210.txt"

# GLIBC_PRIVATE always fails.
set_elf "$SRC/private"; fx_build private 0.1.0 '' none
ceiling_file high 99.0
expect_fail "GLIBC_PRIVATE" "GLIBC_PRIVATE" -- "$FX_DIR/out/private" "$FX_DIR/high.txt"

# A static ELF without GLIBC_ requirements passes, shows "none" and counts as an ELF file.
set_elf "$SRC/static"; fx_build static 0.1.0 '' none
expect_ok "static ELF" "$FX_DIR/out/static" "$FX_DIR/equal.txt"
grep -qF " highest none " "$FX_DIR/gate.out" || bad "the static ELF is not shown with 'none'"

# An ELF at a path on no list, in the deb only, is found; a text file named .so is ignored.
set_elf "$SRC/plain"
fx_build extra 0.1.0 '' add /usr/lib/custodio/libfake.so
deb_add extra /opt/odd/helper "$SRC/patched-2.99"
expect_fail "too-new ELF off the lists" "deb" "/opt/odd/helper" "GLIBC_2.99" -- "$FX_DIR/out/extra" "$FX_DIR/equal.txt"
if grep -q 'libfake' "$FX_DIR/gate.out"; then bad "the non-ELF .so was reported"; fi
rm -rf "${FX_DIR:?}/debtree-extra"
fx_build fake 0.1.0 '' add /usr/lib/custodio/libfake.so
expect_ok "text file named .so" "$FX_DIR/out/fake" "$FX_DIR/equal.txt"
if grep -q 'libfake' "$FX_DIR/gate.out"; then bad "the non-ELF .so was reported"; fi

# Fail closed.
expect_fail "missing DIR" "does not exist" -- "$FX_DIR/nowhere" "$FX_DIR/equal.txt"
mkdir -p "$FX_DIR/empty"
expect_fail "empty DIR" "no deb package" -- "$FX_DIR/empty" "$FX_DIR/equal.txt"
for fmt in deb rpm archlinux; do
    fx_mix "no-$fmt" plain "$fmt" plain
    rm -f "$(fx_file "no-$fmt" "$fmt")"
    expect_fail "no $fmt package" "no ${fmt/archlinux/arch} package" -- "$FX_DIR/out/no-$fmt" "$FX_DIR/equal.txt"
done
fx_mix twice plain deb plain
cp "$(fx_file plain deb)" "$FX_DIR/out/twice/second_amd64.deb"
expect_fail "deb twice" "more than one deb" -- "$FX_DIR/out/twice" "$FX_DIR/equal.txt"
printf '#!/bin/sh\n' > "$SRC/script"
set_elf "$SRC/script"; fx_build noelf 0.1.0 '' none
expect_fail "no ELF file" "holds no ELF file" -- "$FX_DIR/out/noelf" "$FX_DIR/equal.txt"
head -c 64 "$SRC/plain" > "$SRC/truncated"
set_elf "$SRC/truncated"; fx_build truncated 0.1.0 '' none
expect_fail "truncated ELF" "readelf failed" -- "$FX_DIR/out/truncated" "$FX_DIR/equal.txt"
mkdir -p "$FX_DIR/stub"
printf '#!/bin/sh\necho boom >&2\nexit 1\n' > "$FX_DIR/stub/readelf"
chmod +x "$FX_DIR/stub/readelf"
PATH=$FX_DIR/stub:$PATH expect_fail "readelf failing" "readelf failed" -- "$D" "$FX_DIR/equal.txt"
expect_fail "no ceiling file" "cannot read the ceiling file" -- "$D" "$FX_DIR/none.txt"
printf 'ceiling = two\n' > "$FX_DIR/badceil.txt"
expect_fail "bad ceiling file" "exactly one" -- "$D" "$FX_DIR/badceil.txt"

# The committed file: the ceiling is the minimum of the six targets, three of them are required, Arch is not the minimum.
mapfile -t targets < <(sed -n 's/^target = //p' "$COMMITTED")
[ "${#targets[@]}" -eq 6 ] || bad "$COMMITTED lists ${#targets[@]} targets, expected 6"
for t in "${targets[@]}"; do
    [ "$(awk -F' [|] ' '{print NF}' <<< "$t")" -eq 3 ] || bad "target line without name, version and source: $t"
done
min=$(for t in "${targets[@]}"; do awk -F' [|] ' '{print $2}' <<< "$t"; done | sort -V | head -n 1)
[ "$min" = "$committed" ] || bad "the ceiling $committed is not the minimum of the targets ($min)"
for name in 'Ubuntu 24.04' 'Alma 10' 'Arch'; do
    printf '%s\n' "${targets[@]}" | grep -q "^$name | " || bad "$name is not listed in $COMMITTED"
done
arch=$(printf '%s\n' "${targets[@]}" | sed -n 's/^Arch | \([0-9.]*\) | .*/\1/p')
if [ -z "$arch" ] || [ "$arch" = "$min" ] || [ "$(printf '%s\n%s\n' "$min" "$arch" | sort -V | head -n 1)" != "$min" ]; then
    bad "Arch ($arch) must be newer than the minimum $min"
fi
printf '%s\n' "${targets[@]}" | grep -q '^Arch | .* 20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]' || bad "the Arch line has no date"

exit "$fail"
