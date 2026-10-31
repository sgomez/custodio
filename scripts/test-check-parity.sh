#!/usr/bin/env bash
# Tests of scripts/check-parity.sh on fixture packages (scripts/lib/package-fixtures.sh): a difference in path, mode,
# owner, symlink target or directory makes the gate fail; metadata, the directory rule, the exceptions file and the
# fail-closed inputs. A format with a difference is taken from another fixture case with fx_mix.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"

fx_init
trap fx_cleanup EXIT
fail=0
bad() { echo "test-check-parity: $*" >&2; fail=1; }

GATE=$ROOT/scripts/check-parity.sh
CLI=/usr/bin/custodio
NONE=$FX_DIR/none.txt
# The exceptions of the cases below: the committed ones, which excuse the two Arch-only hook files (F42) and nothing else.
cp "$ROOT/packaging/parity-exceptions.txt" "$NONE"

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
# mixed NAME BASE FORMAT OTHER: case NAME is BASE with the package of FORMAT from case OTHER.
mixed() { fx_mix "$@"; }

fx_build good 0.1.0 '' none
expect_ok "good set" "$FX_DIR/out/good" "$NONE"
grep -q ' 3 differences, 3 exceptions' "$FX_DIR/gate.out" || bad "the good set reports differences"
expect_ok "default exceptions file is the committed one" "$FX_DIR/out/good"
bare=$FX_DIR/bare.txt
printf '# no exceptions\n' > "$bare"
expect_fail "the Arch hook files without their exceptions" "libalpm" "presence differs" -- "$FX_DIR/out/good" "$bare"

# Path: a file missing from one format, an extra file in one format.
fx_build nofile 0.1.0 '' drop $CLI
fx_build extra 0.1.0 '' add /usr/share/custodio/extra
for fmt in deb rpm archlinux; do
    label=${fmt/archlinux/arch}
    mixed "nofile-$fmt" good "$fmt" nofile
    expect_fail "$label lacks $CLI" "$CLI" "presence" "$label absent" -- "$FX_DIR/out/nofile-$fmt" "$NONE"
    mixed "extra-$fmt" good "$fmt" extra
    expect_fail "$label has an extra file" /usr/share/custodio/extra "presence" "$label f 0644" -- "$FX_DIR/out/extra-$fmt" "$NONE"
done

# Mode and owner, one format at a time.
fx_build mode 0.1.0 '' mode $CLI 644
fx_build owner 0.1.0 '' owner /usr/lib/custodio/custodiod custodio
fx_build group 0.1.0 '' group /usr/lib/custodio/custodiod custodio
fx_build numeric 0.1.0 '' owner /usr/lib/custodio/custodiod 1000
for fmt in deb rpm archlinux; do
    label=${fmt/archlinux/arch}
    mixed "mode-$fmt" good "$fmt" mode
    expect_fail "$label mode 0644" "$CLI" "mode differs" "$label 0644" "0755" -- "$FX_DIR/out/mode-$fmt" "$NONE"
done
for fmt in deb rpm; do # nfpm writes numeric 0/0 for every Arch file, so Arch owners are tested below by repacking
    mixed "owner-$fmt" good "$fmt" owner
    expect_fail "$fmt owner custodio" /usr/lib/custodio/custodiod "owner differs" "$fmt custodio" -- "$FX_DIR/out/owner-$fmt" "$NONE"
    mixed "group-$fmt" good "$fmt" group
    expect_fail "$fmt group custodio" "group differs" "$fmt custodio" -- "$FX_DIR/out/group-$fmt" "$NONE"
    mixed "numeric-$fmt" good "$fmt" numeric
    expect_fail "$fmt owner 1000" "owner differs" "$fmt 1000" -- "$FX_DIR/out/numeric-$fmt" "$NONE"
done

# arch_repack NAME UID GID [UNAME GNAME]: the Arch package of case NAME with every entry owned by UID:GID.
arch_repack() {
    local pkg tree=$FX_DIR/archtree-$1
    pkg=$(fx_file "$1" archlinux)
    rm -rf "$tree"
    mkdir "$tree"
    bsdtar -xf "$pkg" -C "$tree"
    (cd "$tree" && bsdtar --uid "$2" --gid "$3" --uname "${4:-}" --gname "${5:-}" --zstd -cf "$pkg" .PKGINFO .MTREE .INSTALL usr)
    rm -rf "$tree"
}
# Arch numeric 0 0 against root root passes (the good set is that); numeric 1000 1000 fails; named root passes.
mixed arch1000 good archlinux good
arch_repack arch1000 1000 1000
expect_fail "arch owner 1000:1000" "owner differs" "arch 1000" -- "$FX_DIR/out/arch1000" "$NONE"
mixed archroot good archlinux good
arch_repack archroot 0 0 root root
expect_ok "arch named root" "$FX_DIR/out/archroot" "$NONE"
mixed arch0 good archlinux good
arch_repack arch0 0 0
expect_ok "arch numeric 0:0" "$FX_DIR/out/arch0" "$NONE"

# Symlink target.
fx_build linka 0.1.0 '' link /usr/share/custodio/link /usr/bin/a
fx_build linkb 0.1.0 '' link /usr/share/custodio/link /usr/bin/b
expect_ok "equal symlinks" "$FX_DIR/out/linka" "$NONE"
for fmt in deb rpm archlinux; do
    mixed "link-$fmt" linka "$fmt" linkb
    expect_fail "$fmt symlink target" /usr/share/custodio/link "target differs" /usr/bin/b -- "$FX_DIR/out/link-$fmt" "$NONE"
done

# Directory rule. An explicit directory is in every format; the mode differs in one.
fx_build dir755 0.1.0 '' dir /usr/share/custodio 755
fx_build dir700 0.1.0 '' dir /usr/share/custodio 700
fx_build dirown 0.1.0 '' dir /usr/share/custodio 755 1000
expect_ok "equal explicit directories" "$FX_DIR/out/dir755" "$NONE"
for fmt in deb rpm archlinux; do
    mixed "dirmode-$fmt" dir755 "$fmt" dir700
    expect_fail "$fmt directory 0700" /usr/share/custodio "mode differs" "0700" -- "$FX_DIR/out/dirmode-$fmt" "$NONE"
done
# In the deb only (rpm and Arch from the good set, which has no such directory): 0755 root root passes, others fail.
mixed dironly755 good deb dir755
expect_ok "deb-only directory 0755 root root" "$FX_DIR/out/dironly755" "$NONE"
mixed dironly700 good deb dir700
expect_fail "deb-only directory 0700" /usr/share/custodio "deb d 0700" -- "$FX_DIR/out/dironly700" "$NONE"
mixed dironlyown good deb dirown
expect_fail "deb-only directory owner 1000" /usr/share/custodio "1000:1000" -- "$FX_DIR/out/dironlyown" "$NONE"

# Metadata present only in one format is not compared: .PKGINFO, .MTREE and .INSTALL are in the Arch fixture only.
bsdtar -tf "$(fx_file good archlinux)" | grep -qx '.INSTALL' || bad "the Arch fixture has no .INSTALL"
if grep -q 'PKGINFO\|MTREE\|INSTALL' "$FX_DIR/gate.out"; then bad "metadata appears in the output"; fi

# Exceptions: each has a reason and applies to one path, field and the named packages only.
exc() { { grep -v "^[[:space:]]*#" "$NONE"; printf "%s\n" "$2"; } > "$FX_DIR/$1.txt"; } # the committed entries plus the case's
mixed m1 good rpm mode
exc ok "$CLI | rpm | mode | rpm packs the binary 0644 for a test"
expect_ok "exception with a reason" "$FX_DIR/out/m1" "$FX_DIR/ok.txt"
exc noreason "$CLI | rpm | mode | "
expect_fail "exception without a reason" "no reason" -- "$FX_DIR/out/m1" "$FX_DIR/noreason.txt"
exc stale "/usr/bin/nothing | rpm | mode | stale"
expect_fail "stale exception" "stale" -- "$FX_DIR/out/good" "$FX_DIR/stale.txt"
exc stale2 "$CLI | rpm | mode | nothing differs here"
expect_fail "stale exception (no difference)" "stale" -- "$FX_DIR/out/good" "$FX_DIR/stale2.txt"
for bad_line in "this is not an entry" "$CLI | rpm | mode" "$CLI | pip | mode | r" "$CLI | rpm | colour | r" "relative | rpm | mode | r" \
    "$CLI | deb,rpm,arch | mode | r"; do
    exc malformed "$bad_line"
    expect_fail "malformed line '$bad_line'" "$FX_DIR/malformed.txt" -- "$FX_DIR/out/m1" "$FX_DIR/malformed.txt"
done
exc wrongfield "$CLI | rpm | owner | wrong field"
expect_fail "mode difference under an owner exception" "mode differs" "stale" -- "$FX_DIR/out/m1" "$FX_DIR/wrongfield.txt"
exc wrongpkg "$CLI | deb | mode | wrong package"
expect_fail "mode difference in a package the entry does not name" "mode differs" "stale" -- "$FX_DIR/out/m1" "$FX_DIR/wrongpkg.txt"
exc wrongpath "/usr/lib/custodio/custodiod | rpm | mode | wrong path"
expect_fail "same field on another path" "mode differs" "stale" -- "$FX_DIR/out/m1" "$FX_DIR/wrongpath.txt"
# The same path and field with two differing packages: naming one of them is not enough.
fx_build mode2 0.1.0 '' mode $CLI 600
mixed m2 m1 archlinux mode2
expect_fail "two packages differ, one is named" "mode differs" -- "$FX_DIR/out/m2" "$FX_DIR/ok.txt"
exc both "$CLI | rpm,arch | mode | two named"
expect_ok "both differing packages named" "$FX_DIR/out/m2" "$FX_DIR/both.txt"
# An owner difference on the same path is not hidden by the mode exception.
fx_build ownmode 0.1.0 '' owner $CLI custodio
mixed m3 m1 rpm ownmode
expect_fail "owner under a mode exception" "owner differs" -- "$FX_DIR/out/m3" "$FX_DIR/ok.txt"

# The committed file holds the Arch-only hook files of F42 and F58 and nothing else, each with a reason; the real fixtures pass with it.
entries=$(grep -v '^[[:space:]]*\(#\|$\)' "$ROOT/packaging/parity-exceptions.txt" | cut -d' ' -f1-5 | sort)
want=$'/usr/share/libalpm/hooks/custodio-bus-check.hook | arch | presence\n/usr/share/libalpm/hooks/zz-custodio-restart.hook | arch | presence\n/usr/share/libalpm/scripts/custodio-bus-check | arch | presence'
[ "$entries" = "$want" ] || bad "packaging/parity-exceptions.txt holds other entries than the Arch hook files: $entries"
if grep -v '^[[:space:]]*\(#\|$\)' "$ROOT/packaging/parity-exceptions.txt" | awk -F' [|] ' 'length($4) < 20 { bad = 1 } END { exit !bad }'; then bad "a parity exception has no reason"; fi
expect_ok "real fixtures with the committed exceptions" "$FX_DIR/out/good" "$ROOT/packaging/parity-exceptions.txt"

# Fail closed.
expect_fail "missing DIR" "does not exist" -- "$FX_DIR/nowhere" "$NONE"
mkdir -p "$FX_DIR/empty"
expect_fail "empty DIR" "no deb package" -- "$FX_DIR/empty" "$NONE"
for fmt in deb rpm archlinux; do
    mixed "no-$fmt" good "$fmt" good
    rm -f "$(fx_file "no-$fmt" "$fmt")"
    expect_fail "no $fmt package" "no ${fmt/archlinux/arch} package" -- "$FX_DIR/out/no-$fmt" "$NONE"
done
mixed twice good rpm good
cp "$(fx_file good rpm)" "$FX_DIR/out/twice/second.x86_64.rpm"
expect_fail "rpm twice" "more than one rpm" -- "$FX_DIR/out/twice" "$NONE"
expect_fail "missing exceptions file" "cannot read the exceptions file" -- "$FX_DIR/out/good" "$FX_DIR/none-here.txt"

exit "$fail"
