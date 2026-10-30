#!/usr/bin/env bash
# Tests of scripts/package-lint.sh with stub linters and a stub podman/docker that print canned output in the real tools' formats
# (copies of real runs are in scripts/lib/package-lint-fixtures). The real linters run in `just package-lint` itself.
# Host stubs live in $T/host, the stubs "inside the container" in $T/cont; the stub runtime runs the command with $T/cont first on PATH.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"

fx_init
trap fx_cleanup EXIT
fail=0
bad() { echo "test-package-lint: $*" >&2; fail=1; }

T=$FX_DIR/lint-test
GATE=$ROOT/scripts/package-lint.sh
mkdir -p "$T/tools" "$T/host" "$T/cont" "$T/rt"
# A PATH holding only what the gate needs, so that the real podman and linters of the machine never leak in.
for tool in bash sh env dirname basename cat grep sed id python3 dpkg-deb tr tar gzip xz zstd; do
    ln -s "$(command -v "$tool")" "$T/tools/$tool"
done

fx_build good 0.1.0 '' none
fx_build overrides 0.1.0 '' add /usr/share/lintian/overrides/custodio
PKG=$FX_DIR/out/good
LINT=$T/lintdir

pin() { grep "^$1 " "$ROOT/packaging/lint/pins.txt" | sed 's/^[^=]*= *//'; }

# mkstub DIR NAME: a linter that prints DIR/NAME.out, exits with DIR/NAME.status and records the arguments of its main call.
mkstub() {
    cat > "$1/$2" <<EOF
#!/bin/sh
case "\$1" in --version|--print-version) cat "$1/$2.version"; exit 0;; esac
echo "\$*" >> "$1/$2.calls"
cat "$1/$2.out" 2>/dev/null
exit "\$(cat "$1/$2.status" 2>/dev/null || echo 0)"
EOF
    chmod +x "$1/$2"
}
mkdpkgquery() { # DIR: dpkg-query printing DIR/lintian.profile
    printf '#!/bin/sh\ncat "%s/lintian.profile"\n' "$1" > "$1/dpkg-query"
    chmod +x "$1/dpkg-query"
}
# mkrt NAME: a stub podman or docker; `run` executes the command that follows the image with $T/cont first on PATH.
mkrt() {
    cat > "$T/rt/$1" <<EOF
#!/bin/sh
echo "$1 \$*" >> "$T/rt.calls"
case "\$1" in
image) [ ! -f "$T/image.missing" ]; exit \$?;;
build) if [ -f "$T/build.fail" ]; then echo "package not found" >&2; exit 1; fi; exit 0;;
run)
    shift
    while :; do
        case "\$1" in
        --rm) shift;;
        --network|--user|-e|-v) shift 2;;
        *) break;;
        esac
    done
    shift
    PATH="$T/cont:\$PATH" exec "\$@";;
esac
EOF
    chmod +x "$T/rt/$1"
}

reset() { # [HOSTLINTERS...]: fresh lists, stubs at the pinned versions; the named linters exist on the host, all three in the container
    rm -rf "$T/host" "$T/cont" "$T/rt" "$T/rt.calls" "$T/image.missing" "$T/build.fail" "$LINT"
    mkdir -p "$T/host" "$T/cont" "$T/rt" "$LINT"
    cp "$ROOT"/packaging/lint/pins.txt "$ROOT"/packaging/lint/rpmlint-empty.toml "$ROOT"/packaging/lint/*.Containerfile "$LINT/"
    local l d
    for l in lintian rpmlint namcap; do printf '# empty\n' > "$LINT/$l.txt"; done
    for d in cont host; do
        printf '%s\n' "$(pin lintian)" > "$T/$d/lintian.version"
        printf '%s\n' "$(pin lintian_profile)" > "$T/$d/lintian.profile"
        pin rpmlint | sed 's/-.*//' > "$T/$d/rpmlint.version"
        pin namcap | sed 's/-.*//' > "$T/$d/namcap.version"
        rpm_out "$T/$d/rpmlint.out"
        : > "$T/$d/lintian.out"
        : > "$T/$d/namcap.out"
    done
    for l in lintian rpmlint namcap; do mkstub "$T/cont" "$l"; done
    mkdpkgquery "$T/cont"
    for l in "$@"; do
        mkstub "$T/host" "$l"
    done
    mkdpkgquery "$T/host"
    mkrt podman
    FORCE=
}

# rpm_out FILE [CONFIG] LINE...: an rpmlint session with the given configs (default: the built-in defaults) and findings.
RPM_CONF=/usr/lib/python3.14/site-packages/rpmlint/configdefaults.toml
rpm_out() {
    local file=$1 conf=$RPM_CONF e=0 w=0 line
    shift || true
    if [ "${1:-}" = --conf ]; then conf=$2; shift 2; fi
    for line in "$@"; do
        case $line in *": E: "*) e=$((e + 1));; *": W: "*) w=$((w + 1));; esac
    done
    {
        echo "============================ rpmlint session starts ============================"
        echo "rpmlint: 2.8.0"
        echo "configuration:"
        printf '    %s\n' "$conf"
        echo "checks: 27, packages: 1"
        echo
        for line in "$@"; do echo "$line"; done
        echo " 1 packages and 0 specfiles checked; $e errors, $w warnings, 0 filtered, $e badness; has taken 0.3 s "
    } > "$file"
}

OUT=$T/gate.out
# gate [PKG_DIR LINT_DIR]: runs the gate with only the stubs on PATH.
gate() {
    local path="$T/host:$T/rt:$T/tools"
    if [ $# -eq 0 ]; then set -- "$PKG" "$LINT"; fi
    PATH=$path PACKAGE_LINT_FORCE_CONTAINER=$FORCE "$GATE" "$@" > "$OUT" 2>&1
}
ok() { local label=$1; shift; gate "$@" || bad "$label: the gate failed: $(tail -n 5 "$OUT")"; }
no() {
    local label=$1 words=() word
    shift
    while [ "$1" != -- ]; do words+=("$1"); shift; done
    shift
    if gate "$@"; then bad "$label: the gate passed"; return; fi
    for word in "${words[@]}"; do
        grep -qF -- "$word" "$OUT" || bad "$label: output lacks '$word': $(tail -n 5 "$OUT")"
    done
}

# ---- arguments, "ran" lines, the host path ----------------------------------------------------------------------------------
reset lintian rpmlint namcap
ok "host linters at the pin"
for l in lintian rpmlint namcap; do
    [ "$(wc -l < "$T/host/$l.calls")" = 1 ] || bad "$l was not called exactly once"
    [ ! -e "$T/cont/$l.calls" ] || bad "$l ran in the container although the host one has the pin"
done
grep -qx -- "--no-cfg --profile debian/main --display-info --display-experimental --pedantic --show-overrides --tag-display-limit 0 $PKG/custodio_0.1.0-1_amd64.deb" "$T/host/lintian.calls" \
    || bad "lintian arguments: $(cat "$T/host/lintian.calls")"
grep -qx -- "-c $LINT/rpmlint-empty.toml $PKG/custodio-0.1.0-1.x86_64.rpm" "$T/host/rpmlint.calls" || bad "rpmlint arguments: $(cat "$T/host/rpmlint.calls")"
grep -qx -- "-i -m $PKG/custodio-0.1.0-1-x86_64.pkg.tar.zst" "$T/host/namcap.calls" || bad "namcap arguments: $(cat "$T/host/namcap.calls")"
for l in lintian rpmlint namcap; do grep -q "ran $l .* host" "$OUT" || bad "no 'ran $l ... host' line: $(cat "$OUT")"; done
grep -q "ran lintian $(pin lintian) host profile $(pin lintian_profile)" "$OUT" || bad "the lintian line lacks the version and profile"
[ ! -e "$T/rt.calls" ] || bad "a container was started for host linters"

# ---- the container path ---------------------------------------------------------------------------------------------------
reset
touch "$T/image.missing"
ok "container, podman"
for l in lintian rpmlint namcap; do
    [ "$(wc -l < "$T/cont/$l.calls")" = 1 ] || bad "$l was not called once in the container"
    grep -q "ran $l .* container" "$OUT" || bad "no 'ran $l ... container' line"
done
grep -q -- "--network none" "$T/rt.calls" || bad "container run without --network none"
grep -q -- ":/pkg:ro" "$T/rt.calls" || bad "the package directory is not mounted read-only"
user=$(grep -m1 -o -- '--user [0-9:]*' "$T/rt.calls" | cut -d' ' -f2)
if [ "$user" = 0:0 ] && [ "$(id -u)" != 0 ] && ! grep -q "^$(id -u):\|^$(id -un):" /etc/subuid 2>/dev/null; then : # nested rootless podman
elif [ "$user" != "$(id -u):$(id -g)" ]; then bad "--user is '$user', expected the caller's ids"
fi
[ "$user" != 0:0 ] || [ "$(id -u)" != 0 ] || bad "the container runs as root"
grep -q "BASE=docker.io/library/$(pin base_debian13)" "$T/rt.calls" || bad "the lintian image is not built from the pinned base"
grep -q "BASE=docker.io/library/$(pin base_fedora44)" "$T/rt.calls" || bad "the rpmlint image is not built from the pinned base"
grep -q "BASE=docker.io/library/$(pin base_arch)" "$T/rt.calls" || bad "the namcap image is not built from the pinned base"
grep -q "NAMCAP=$(pin namcap)" "$T/rt.calls" || bad "the namcap image does not take its pin from pins.txt"
rm -f "$T/rt.calls"
mkrt docker
rm "$T/rt/podman"
ok "container, docker only"
grep -q '^docker run ' "$T/rt.calls" || bad "docker was not used"
grep -q -- "--user $(id -u):$(id -g)" "$T/rt.calls" || bad "docker run without the caller's --user"

# 0:0 is only for a non-root caller with no subuid range under podman; never for docker or a caller with a range.
rm -f "$T/rt.calls"
mkrt podman
printf '%s:100000:65536\n' "$(id -u)" > "$T/subuid"
PACKAGE_LINT_SUBUID=$T/subuid ok "container, podman, subuid range"
if [ "$(id -u)" != 0 ]; then
    grep -q -- "--user $(id -u):$(id -g)" "$T/rt.calls" || bad "podman with a subuid range lacks the caller's --user"
    grep -q -- "--user 0:0" "$T/rt.calls" && bad "0:0 passed to a caller with a subuid range"
    rm -f "$T/rt.calls"
    : > "$T/subuid"
    PACKAGE_LINT_SUBUID=$T/subuid ok "container, podman, no subuid range"
    grep -q -- "--user 0:0" "$T/rt.calls" || bad "podman without a subuid range lacks --user 0:0"
fi

reset
rm -f "$T/rt/podman"
no "no host linter and no runtime" "no container runtime" lintian -- "$PKG" "$LINT"

reset lintian rpmlint namcap
FORCE=1
ok "forced container"
{ [ ! -e "$T/host/lintian.calls" ] && [ -e "$T/cont/lintian.calls" ]; } || bad "PACKAGE_LINT_FORCE_CONTAINER=1 still used the host linter"

# A host linter at another version is not used.
reset lintian rpmlint namcap
echo 2.0.0 > "$T/host/lintian.version"
ok "host lintian with another version"
{ [ ! -e "$T/host/lintian.calls" ] && [ -e "$T/cont/lintian.calls" ]; } || bad "a host lintian at the wrong version was used"
grep -q "ran lintian .* container" "$OUT" || bad "no container line after a host version mismatch"
reset lintian rpmlint namcap
echo 1.9.9 > "$T/host/namcap.version"
echo 2.7.0 > "$T/host/rpmlint.version"
ok "host rpmlint and namcap with other versions"
{ [ ! -e "$T/host/namcap.calls" ] && [ ! -e "$T/host/rpmlint.calls" ]; } || bad "a host linter at the wrong version was used"
# ... and without a runtime that is a failure.
rm -f "$T/rt/podman"
no "wrong host version, no runtime" "no container runtime" -- "$PKG" "$LINT"

# The lintian profile version must equal lintian_profile.
reset lintian
echo 9.9.9 > "$T/host/lintian.profile"
ok "host lintian with another profile"
[ ! -e "$T/host/lintian.calls" ] || bad "a host lintian with another profile version was used"
reset
echo 9.9.9 > "$T/cont/lintian.profile"
no "container lintian profile" lintian 9.9.9 "$(pin lintian_profile)" -- "$PKG" "$LINT"

# Versions in the container equal the pins.
for l in lintian rpmlint namcap; do
    reset
    echo 0.0.1 > "$T/cont/$l.version"
    no "container $l version" "$l" 0.0.1 -- "$PKG" "$LINT"
done
reset
ok "container versions at the pin"

# rpmlint configs: the host one is used with only its defaults and the committed empty config; otherwise the container.
reset rpmlint
rpm_out "$T/host/rpmlint.out" --conf /etc/xdg/rpmlint/foo.toml
ok "host rpmlint with a foo.toml"
grep -q "ran rpmlint .* container" "$OUT" || bad "a host rpmlint that loads /etc/xdg/rpmlint/foo.toml was used"
reset rpmlint
rpm_out "$T/host/rpmlint.out" --conf "$LINT/rpmlint-empty.toml"
ok "host rpmlint with the committed empty config"
grep -q "ran rpmlint .* host" "$OUT" || bad "a host rpmlint with only the committed config was not used"
reset
rpm_out "$T/cont/rpmlint.out" --conf /etc/xdg/rpmlint/fedora.toml
no "container rpmlint with fedora.toml" rpmlint /etc/xdg/rpmlint/fedora.toml -- "$PKG" "$LINT"

# A container image that cannot be built (pin not installable) fails and runs nothing.
reset
touch "$T/image.missing" "$T/build.fail"
no "image build fails" lintian "$(pin lintian)" "no other version" -- "$PKG" "$LINT"
[ ! -e "$T/cont/lintian.calls" ] || bad "a linter ran after the image build failed"
rm -f "$T/build.fail"
ok "image missing but buildable"
grep -q '^podman build ' "$T/rt.calls" || bad "the missing image was not built"

# ---- findings -------------------------------------------------------------------------------------------------------------
reset lintian rpmlint namcap
for sev in E W I P X; do
    printf '%s: custodio: some-tag [usr/bin/x]\n' "$sev" > "$T/host/lintian.out"
    no "lintian $sev" lintian some-tag usr/bin/x -- "$PKG" "$LINT"
done
printf 'O: custodio: some-tag [usr/bin/x]\n' > "$T/host/lintian.out"
no "lintian O" lintian some-tag -- "$PKG" "$LINT"
printf 'some-tag | usr/bin/x | the reason\n' > "$LINT/lintian.txt"
no "lintian O is not coverable by the list" lintian some-tag -- "$PKG" "$LINT"
: > "$T/host/lintian.out"
: > "$LINT/lintian.txt"
for sev in E W; do
    rpm_out "$T/host/rpmlint.out" "custodio.x86_64: $sev: some-tag detail"
    no "rpmlint $sev" rpmlint some-tag detail -- "$PKG" "$LINT"
done
rpm_out "$T/host/rpmlint.out"
for sev in E W I; do
    printf 'custodio %s: some-tag detail\n' "$sev" > "$T/host/namcap.out"
    no "namcap $sev" namcap some-tag detail -- "$PKG" "$LINT"
done
: > "$T/host/namcap.out"
ok "clean again"

# Output that is not understood, a status that hides findings, a summary that disagrees.
printf 'this is not a finding\n' > "$T/host/lintian.out"
no "unknown lintian line" lintian "not understood" -- "$PKG" "$LINT"
: > "$T/host/lintian.out"
printf 'custodio: nonsense\n' > "$T/host/namcap.out"
no "unknown namcap line" namcap "not understood" -- "$PKG" "$LINT"
: > "$T/host/namcap.out"
{ cat "$T/host/rpmlint.out"; echo "garbage line"; } > "$T/x" && mv "$T/x" "$T/host/rpmlint.out"
no "unknown rpmlint line" rpmlint "not understood" -- "$PKG" "$LINT"
rpm_out "$T/host/rpmlint.out" "custodio.x86_64: W: some-tag detail"
sed -i 's/0 errors, 1 warnings/0 errors, 0 warnings/' "$T/host/rpmlint.out"
no "rpmlint summary differs" rpmlint summary -- "$PKG" "$LINT"
rpm_out "$T/host/rpmlint.out"
sed -i 's/0 filtered/2 filtered/' "$T/host/rpmlint.out"
no "rpmlint filtered" rpmlint filtered -- "$PKG" "$LINT"
rpm_out "$T/host/rpmlint.out"
sed -i '/ packages and /d' "$T/host/rpmlint.out"
no "rpmlint without summary" rpmlint summary -- "$PKG" "$LINT"
rpm_out "$T/host/rpmlint.out"
echo 2 > "$T/host/lintian.status"
no "findings status with no finding" lintian "no finding was parsed" -- "$PKG" "$LINT"
echo 127 > "$T/host/lintian.status"
no "lintian crash 127" lintian "status 127" -- "$PKG" "$LINT"
echo 2 > "$T/host/namcap.status"; echo 0 > "$T/host/lintian.status"
no "namcap crash 2" namcap "status 2" -- "$PKG" "$LINT"
echo 0 > "$T/host/namcap.status"
echo 2 > "$T/host/rpmlint.status"
no "rpmlint crash 2" rpmlint "status 2" -- "$PKG" "$LINT"
echo 64 > "$T/host/rpmlint.status"
no "rpmlint findings status without findings" rpmlint "no finding was parsed" -- "$PKG" "$LINT"
echo 0 > "$T/host/rpmlint.status"
# A finding with a clean status is still a finding.
printf 'W: custodio: some-tag [usr/bin/x]\n' > "$T/host/lintian.out"
echo 0 > "$T/host/lintian.status"
no "finding with status 0" lintian some-tag -- "$PKG" "$LINT"
: > "$T/host/lintian.out"
ok "reset to clean"

# Overrides cannot bypass the lists.
no "a .deb with a lintian override" "override" -- "$FX_DIR/out/overrides" "$LINT"

# ---- the exception lists ---------------------------------------------------------------------------------------------------
printf 'W: custodio: some-tag [usr/bin/x]\n' > "$T/host/lintian.out"
echo 0 > "$T/host/lintian.status"
printf 'some-tag | usr/bin/x | because\n' > "$LINT/lintian.txt"
ok "a listed finding passes"
grep -q "some-tag | usr/bin/x" "$OUT" || bad "a listed finding is not printed"
printf 'some-tag | usr/bin/* | because\n' > "$LINT/lintian.txt"
ok "a glob covers"
printf 'some-tag | usr/bin/x | \n' > "$LINT/lintian.txt"
no "no reason" "lintian.txt:1" "no reason" -- "$PKG" "$LINT"
printf '# a comment\n\nsome-tag usr/bin/x because\n' > "$LINT/lintian.txt"
no "unparsable" "lintian.txt:3" -- "$PKG" "$LINT"
printf 'some-tag | usr/bin/x | because\nother-tag | usr/bin/y | stale\n' > "$LINT/lintian.txt"
no "stale" "lintian.txt:2" stale -- "$PKG" "$LINT"
printf 'some-tag | usr/bin/x | because\n' > "$LINT/rpmlint.txt"
: > "$LINT/lintian.txt"
no "listed only in the rpmlint list" "lintian | some-tag" "stale exception" -- "$PKG" "$LINT"
printf 'some-tag | usr/bin/y | because\n' > "$LINT/lintian.txt"
no "subject does not match" "lintian | some-tag | usr/bin/x" -- "$PKG" "$LINT"
printf '* | usr/bin/x | because\n' > "$LINT/lintian.txt"
no "a * tag covers nothing" "lintian | some-tag | usr/bin/x" -- "$PKG" "$LINT"
printf 'some-tag | * | because\n' > "$LINT/lintian.txt"
no "a * subject is rejected" "lintian.txt:1" -- "$PKG" "$LINT"
printf 'some-tag | usr/bin | because\n' > "$LINT/lintian.txt"
no "the glob is anchored" "lintian | some-tag | usr/bin/x" -- "$PKG" "$LINT"
printf 'some-tag | bin/x | because\n' > "$LINT/lintian.txt"
no "a suffix does not match" "lintian | some-tag | usr/bin/x" -- "$PKG" "$LINT"
printf 'some-tag | usr/bin/x | because\n' > "$LINT/lintian.txt"
: > "$LINT/rpmlint.txt"

# ---- fail closed -----------------------------------------------------------------------------------------------------------
: > "$T/host/lintian.out"
: > "$LINT/lintian.txt"
no "DIR missing" "does not exist" -- "$T/nowhere" "$LINT"
mkdir -p "$T/empty"
no "no package at all" "no deb package" -- "$T/empty" "$LINT"
for pair in "lintian:deb:*.deb" "rpmlint:rpm:*.rpm" "namcap:arch:*.pkg.tar.zst"; do
    IFS=: read -r l fmt pat <<< "$pair"
    rm -rf "$T/two" "$T/none"
    cp -r "$PKG" "$T/two"
    cp -r "$PKG" "$T/none"
    # shellcheck disable=SC2086
    rm -f "$T/none"/$pat
    # shellcheck disable=SC2086
    f=$(ls "$T/two"/$pat)
    cp "$f" "$T/two/second-$(basename "$f")"
    no "no $fmt package" "$l" "no $fmt package" -- "$T/none" "$LINT"
    no "two $fmt packages" "$l" "more than one $fmt package" -- "$T/two" "$LINT"
done
no "pins file missing" "pins file" -- "$PKG" "$T/nowhere"

exit "$fail"
