#!/usr/bin/env bash
# Tests of scripts/check-snap-base.sh (F184, acceptance 13) on real `gcc` fixture ELF files and on fixture package directories
# (scripts/lib/package-fixtures.sh); never on the real target/packages. Also checks packaging/snap-bases.txt against F171's table.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"

command -v gcc > /dev/null || { echo "test-snap-base-fit: required tool 'gcc' is not installed" >&2; exit 1; }
fx_init
trap fx_cleanup EXIT
fail=0
bad() { echo "test-snap-base-fit: $*" >&2; fail=1; }

GATE=$ROOT/scripts/check-snap-base.sh
BASES=$ROOT/packaging/snap-bases.txt
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

# --- packaging/snap-bases.txt against F171's own table line (data, not prose) ---
recorded=$(sed -n 's/^base = core26 | \([0-9.]*\) | .*/\1/p' "$BASES")
cell=$(sed -n 's/^| glibc | \([^|]*\) |.*/\1/p' "$ROOT/docs/findings/F171.md")
f171=$(sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' <<< "$cell")
f171_base=$(sed -n 's/^| base | \(core[0-9]*\) rev.*/\1/p' "$ROOT/docs/findings/F171.md")
[ -n "$recorded" ] || bad "snap-bases.txt has no core26 base line"
[ -n "$f171" ] || bad "F171's glibc row has no MAJOR.MINOR: '$cell'"
[ "$recorded" = "$f171" ] || bad "snap-bases.txt records glibc '$recorded', F171 recorded '$f171'"
[ "$f171_base" = core26 ] || bad "F171 recorded the base '$f171_base', snap-bases.txt has core26"
[ "$recorded" = 2.43 ] || bad "the recorded glibc is '$recorded', not 2.43"
[ "$(grep -c '^base = ' "$BASES")" -eq 1 ] || bad "snap-bases.txt must hold exactly one base line"

# --- the bases file itself: a fixture without glibc or source, and other malformed lines, is refused ---
elf_ok=$SRC/plain
echo 'int main(void) { return 0; }' > "$SRC/plain.c"
gcc -s -o "$elf_ok" "$SRC/plain.c"
bases_case() { # NAME LINE...: a bases file of the given lines
    local name=$1
    shift
    printf '%s\n' "$@" > "$FX_DIR/$name.txt"
}
bases_case nosource 'base = core26 | 2.43 |' 'library = core26 | libc.so.6 | verified | x'
expect_fail "base without a source" "each field filled" -- "$elf_ok" "$FX_DIR/nosource.txt"
bases_case noglibc 'base = core26 | | src' 'library = core26 | libc.so.6 | verified | x'
expect_fail "base without a glibc" "each field filled" -- "$elf_ok" "$FX_DIR/noglibc.txt"
bases_case longglibc 'base = core26 | 2.43-2ubuntu2 | src'
expect_fail "glibc that is not MAJOR.MINOR" "not MAJOR.MINOR" -- "$elf_ok" "$FX_DIR/longglibc.txt"
bases_case orphan 'base = core26 | 2.43 | src' 'library = core24 | libc.so.6 | verified | x'
expect_fail "library of an unknown base" "core24" -- "$elf_ok" "$FX_DIR/orphan.txt"
bases_case nostatus 'base = core26 | 2.43 | src' 'library = core26 | libc.so.6 | maybe | x'
expect_fail "library with another status" "STATUS" -- "$elf_ok" "$FX_DIR/nostatus.txt"
bases_case empty '# nothing'
expect_fail "no base" "lists no base" -- "$elf_ok" "$FX_DIR/empty.txt"
expect_fail "no bases file" "cannot read" -- "$elf_ok" "$FX_DIR/none.txt"

# --- fixture ELF files: versions are patched into a real binary (as test-glibc-ceiling.sh does) ---
patch() { # VERSION: SRC/patched-VERSION from plain, asserted with readelf
    python3 -I "$ROOT/scripts/lib/elf_patch.py" "$SRC/plain" "$SRC/patched-$1" "$1" || bad "patching $1 failed"
    [ "$(readelf -W -V "$SRC/patched-$1" | grep -c "Name: GLIBC_$1 ")" -eq 1 ] || bad "readelf does not show GLIBC_$1 exactly once"
}
for v in 2.9 2.43 2.44 2.99; do patch "$v"; done
# A module needing a library: stub shared libraries carry the soname.
needing() { # NAME SONAME: SRC/NAME needs SONAME besides libc
    echo 'void stub(void) {}' > "$SRC/stub.c"
    mkdir -p "$SRC/lib-$1"
    gcc -shared -o "$SRC/lib-$1/$2" -Wl,-soname,"$2" "$SRC/stub.c"
    gcc -o "$SRC/$1" "$SRC/plain.c" -L"$SRC/lib-$1" -Wl,--no-as-needed -Wl,-rpath,/nonexistent "-l:$2"
    readelf -d "$SRC/$1" | grep -qF "[$2]" || bad "$1 does not need $2"
}
needing needs-lib libnotinbase.so.1
needing needs-tss libtss2-esys.so.0

# The ELF path form.
expect_ok "fits: plain" "$elf_ok"
grep -qF "fits core26 (glibc 2.43)" "$FX_DIR/gate.out" || bad "the output does not name the base: $(cat "$FX_DIR/gate.out")"
expect_ok "fits: GLIBC_2.9" "$SRC/patched-2.9"
expect_ok "fits: GLIBC_2.43, equal to the base" "$SRC/patched-2.43"
expect_fail "above the base by one minor" "GLIBC_2.44" "glibc 2.43" "core26" -- "$SRC/patched-2.44"
expect_fail "far above the base" "GLIBC_2.99" "core26" -- "$SRC/patched-2.99"
expect_fail "a library the base lacks" "libnotinbase.so.1" "core26" -- "$SRC/needs-lib"
expect_fail "a TPM library the base lacks" "libtss2-esys.so.0" -- "$SRC/needs-tss"
# Numeric comparison: 2.9 against a base at 2.10 fits, 2.10 against a base at 2.9 does not.
bases_case b210 'base = core26 | 2.10 | src' 'library = core26 | libc.so.6 | verified | x'
bases_case b29 'base = core26 | 2.9 | src' 'library = core26 | libc.so.6 | verified | x'
python3 -I "$ROOT/scripts/lib/elf_patch.py" "$SRC/plain" "$SRC/patched-2.10" 2.10
expect_ok "2.9 against base 2.10" "$SRC/patched-2.9" "$FX_DIR/b210.txt"
expect_fail "2.10 against base 2.9" "GLIBC_2.10" -- "$SRC/patched-2.10" "$FX_DIR/b29.txt"
# A listed library passes: the same file against a bases file that provides it.
bases_case withlib 'base = core26 | 2.43 | src' 'library = core26 | libc.so.6 | verified | x' 'library = core26 | libnotinbase.so.1 | inferred | x'
expect_ok "a listed library" "$SRC/needs-lib" "$FX_DIR/withlib.txt"
# Input errors.
expect_fail "missing ELF" "no such file" -- "$FX_DIR/nowhere"
printf '#!/bin/sh\n' > "$SRC/script"
expect_fail "not an ELF" "not an ELF" -- "$SRC/script"

# The package directory form: the module of the .deb, on a fixture directory.
module_case() { # NAME ELF
    cp "$2" "$REL/libcustodio_pkcs11.so"
    fx_build "$1" 0.1.0 '' none
}
module_case pk-fits "$elf_ok"
expect_ok "package that fits" "$FX_DIR/out/pk-fits"
module_case pk-above "$SRC/patched-2.44"
expect_fail "package above the base" "GLIBC_2.44" "core26" -- "$FX_DIR/out/pk-above"
module_case pk-lib "$SRC/needs-lib"
expect_fail "package with a library the base lacks" "libnotinbase.so.1" -- "$FX_DIR/out/pk-lib"
mkdir -p "$FX_DIR/empty"
expect_fail "no .deb" "found 0" -- "$FX_DIR/empty"

exit "$fail"
