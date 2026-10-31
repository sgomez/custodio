#!/usr/bin/env bash
# F45: the host script e2e/run.sh with a stub `podman` on PATH that logs its arguments; no container is started. Checked here: the order
# and shape of the engine calls, the target choice and `all`, the read-only package mount, the record, the case accounting and the skip
# enforcement as wired in the host, the Containerfiles (no package copied, real polkit and bus daemon), the lint file list.
# NOT checked here: that a real container boots and the suite passes in it; that is the real run of `just e2e debian13`.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
fail=0
bad() { echo "test-e2e-host: $*" >&2; fail=1; }

# Real (small) packages: the host checks that N+1 is N with only the version raised (e2e/check-next.sh), which needs the contents.
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
fx_init
trap 'fx_cleanup; rm -rf "$tmp"' EXIT
fx_build cur 0.1.0 '' none
fx_build next 0.1.1 '' none
mkdir -p "$tmp/bin" "$tmp/pkgs" "$tmp/next" "$tmp/old"
# the old package (F60) is a third file, distinct from N and N+1; only its name matters to the host
cp "$(fx_file cur deb)" "$tmp/old/custodio_0.0.9-1_amd64.deb"
export E2E_PACKAGES_OLD=$tmp/old
for f in deb rpm archlinux; do
    cp "$(fx_file cur "$f")" "$tmp/pkgs/"
    cp "$(fx_file next "$f")" "$tmp/next/"
done
export E2E_PACKAGES_NEXT=$tmp/next
cat > "$tmp/bin/podman" <<'STUB'
#!/usr/bin/env bash
# Logs the arguments; `exec ... guest.sh` prints what the fake guest would, from STUB_* variables.
echo "$*" >> "$STUB_LOG"
case $1 in
run)
    sed -n 's|.*:/pkg/\([^: ]*\):ro.*|\1|p' <<< "$*" > "$STUB_LOG.pkg"
    sed -n 's|.*:/pkg-next/\([^: ]*\):ro.*|\1|p' <<< "$*" > "$STUB_LOG.next"
    sed -n 's|.*:/pkg-old/\([^: ]*\):ro.*|\1|p' <<< "$*" > "$STUB_LOG.old"
    ;;
exec)
    case "$*" in
    *"is-system-running"*) echo running ;;
    *"/e2e/guest.sh"*)
        mode=main
        t=${*: -1}
        if [ "$t" = old ]; then mode=old; t=${*: -2:1}; fi
        if [ "$mode" = old ]; then
            echo "e2e: installed $(cat "$STUB_LOG.old") from the mounted file"
            list=${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/cases.list
            [ "$t" != "${STUB_FAIL_OLD:-}" ] || { echo "e2e: FAIL: stubbed (old)"; exit 1; }
        else
            echo "e2e: installed $(cat "$STUB_LOG.pkg") from the mounted file"
            # the main run reports the common cases and the target's own, except the ones of the old-package run (F60)
            list=$STUB_LOG.main
            : > "$list"
            [ -f "${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/refusal-only" ] || cat "$STUB_ROOT/e2e/cases.list" > "$list" # F50: a refusal-only target owes none of them
            grep -v '^upgrade-cargo-deb-' "${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/cases.list" >> "$list" 2> /dev/null || true
        fi
        while IFS= read -r c; do
            case $c in '' | '#'*) continue ;; esac
            if [ "$mode" = old ]; then case $c in upgrade-cargo-deb-*) ;; *) continue ;; esac; fi
            [ "$c" = "${STUB_OMIT:-}" ] && continue
            if [ "$c" = "${STUB_SKIP:-}" ]; then echo "E2E-CASE skipped $c"; else echo "E2E-CASE run $c"; fi
            [ "$c" = "${STUB_DUP:-}" ] && echo "E2E-CASE run $c"
        done < "$list"
        [ "$mode" = old ] && exit 0
        [ -z "${STUB_EXTRA:-}" ] || echo "E2E-CASE run $STUB_EXTRA"
        if [ -z "${STUB_NOPROBE:-}" ]; then
            echo "E2E-RECORD bus-daemon=dbus-daemon"
            echo "E2E-RECORD polkit-version=126"
        fi
        [ "$t" != "${STUB_FAIL:-}" ] || { echo "e2e: FAIL: stubbed"; exit 1; }
        echo "e2e: all checks passed"
        ;;
    esac
    ;;
esac
STUB
chmod +x "$tmp/bin/podman"
export STUB_ROOT=$ROOT

# run_host NAME ARGS...: runs e2e/run.sh with the stub; the log of the engine in $tmp/log, the output in $tmp/out.
run_host() {
    : > "$tmp/log"
    rm -rf "$tmp/o"
    STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" "$@" > "$tmp/out" 2>&1
}
expect_ok() { local n=$1; shift; run_host "$@" || { bad "$n: failed: $(tail -n 5 "$tmp/out")"; return 1; }; }
expect_fail() { local n=$1; shift; if run_host "$@"; then bad "$n: passed"; return 1; fi; }

# --- every real target: the order and shape of the calls
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    expect_ok "$T" "$T" || true
    b=$(grep -n '^build ' "$tmp/log" | head -n 1 | cut -d: -f1)
    r=$(grep -n '^run ' "$tmp/log" | head -n 1 | cut -d: -f1)
    x=$(grep -n 'guest.sh' "$tmp/log" | head -n 1 | cut -d: -f1)
    { [ -n "$b" ] && [ -n "$r" ] && [ -n "$x" ] && [ "$b" -lt "$r" ] && [ "$r" -lt "$x" ]; } || bad "build, run, exec of the guest are not in this order: $(cat "$tmp/log")"
    grep '^build ' "$tmp/log" | grep -q -- "-f e2e/targets/$T/Containerfile" || bad "the build does not use the target's Containerfile"
    grep '^run ' "$tmp/log" | grep -q -- '--privileged' || bad "the container is not privileged"
    pkg=$(find "$tmp/pkgs" -name "$(head -n 1 "$ROOT/e2e/targets/$T/package.pattern")" -exec basename {} \; | sort | tail -n 1)
    [ -n "$pkg" ] || bad "$T: package.pattern matches none of the fake packages"
    grep '^run ' "$tmp/log" | grep -q -- "$tmp/pkgs/$pkg:/pkg/$pkg:ro" || bad "the package is not mounted read-only"
    if [ -f "$ROOT/e2e/targets/$T/refusal-only" ]; then
        # F50: the package never installs on this target; no N+1 and no old package, one read-only mount
        [ "$(grep -o -- '-v [^ ]*:/pkg[^ ]*:ro' "$tmp/log" | sort -u | wc -l)" -eq 1 ] || bad "$T: a refusal-only target mounts more than the package"
        grep -q 'pkg-next\|pkg-old' "$tmp/log" && bad "$T: a refusal-only target mounts N+1 or the old package"
        continue
    fi
    nxt=$(find "$tmp/next" -name "$(head -n 1 "$ROOT/e2e/targets/$T/package.pattern")" -exec basename {} \; | sort | tail -n 1)
    [ -n "$nxt" ] || bad "$T: package.pattern matches none of the fake N+1 packages"
    grep '^run ' "$tmp/log" | grep -q -- "$tmp/next/$nxt:/pkg-next/$nxt:ro" || bad "$T: N+1 is not mounted read-only at /pkg-next"
    [ "$nxt" != "$pkg" ] || bad "$T: N and N+1 are the same file name"
    if [ -f "$ROOT/e2e/targets/$T/old.pattern" ]; then
        # F60: the old package is a third read-only mount, in the fresh container of the second guest run
        [ "$(grep -o -- '-v [^ ]*:/pkg[^ ]*:ro' "$tmp/log" | sort -u | wc -l)" -eq 3 ] || bad "$T: N, N+1 and the old package are not three different read-only mounts"
        grep '^run ' "$tmp/log" | grep -q -- "$tmp/old/custodio_0.0.9-1_amd64.deb:/pkg-old/custodio_0.0.9-1_amd64.deb:ro" || bad "$T: the old package is not mounted read-only at /pkg-old"
        [ "$(grep -c '^run ' "$tmp/log")" -eq 2 ] || bad "$T: the upgrade from the old package does not run in a fresh container"
        [ "$(grep -c '^rm .*custodio-e2e-' "$tmp/log")" -ge 2 ] || bad "$T: the first container is not removed before the second"
        r1=$(grep -n '^run ' "$tmp/log" | head -n 1 | cut -d: -f1)
        rm1=$(grep -n '^rm ' "$tmp/log" | head -n 1 | cut -d: -f1)
        r2=$(grep -n '^run ' "$tmp/log" | tail -n 1 | cut -d: -f1)
        { [ "$r1" -lt "$rm1" ] && [ "$rm1" -lt "$r2" ]; } || bad "$T: the order run, rm, run is wrong: $(cat "$tmp/log")"
        grep -q "exec .* bash /e2e/guest.sh $T old" "$tmp/log" || bad "$T: the guest is not run in the old mode"
        grep -q "installed custodio_0.0.9-1_amd64.deb from the mounted file" "$tmp/out" || bad "$T: the old guest's output is not passed through"
    else
        [ "$(grep -o -- '-v [^ ]*:/pkg[^ ]*:ro' "$tmp/log" | sort -u | wc -l)" -eq 2 ] || bad "$T: N and N+1 are not two different read-only mounts"
        grep -q 'pkg-old' "$tmp/log" && bad "$T: the old package is mounted on a target that has no old.pattern"
        [ "$(grep -c '^run ' "$tmp/log")" -eq 1 ] || bad "$T: more than one container ran"
        grep -q 'guest.sh [a-z0-9]* old' "$tmp/log" && bad "$T: the old-package run happened on a target without old.pattern"
    fi
    grep -q "exec .* bash /e2e/guest.sh $T" "$tmp/log" || bad "the shared guest script is not executed"
    grep -q "installed $pkg from the mounted file" "$tmp/out" || bad "the guest's output is not passed through"
    grep -qi 'cargo\|nfpm\|just package' "$tmp/log" && bad "the engine log shows a package build"
    grep -q 'cargo\|nfpm\|just package' "$ROOT/e2e/run.sh" && bad "the host script builds packages"
done
# the recipe: package is its dependency and the default target is all
grep -Eq '^e2e target="all": package$' "$ROOT/justfile" || bad "the e2e recipe does not take a target (default all) and depend on package"
grep -q 'bash e2e/run.sh {{target}}' "$ROOT/justfile" || bad "the e2e recipe does not pass the target"

# --- the record
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    expect_ok "$T" "$T" || true
    rec=$tmp/o/$T.record
    [ -f "$rec" ] || bad "no record file"
    { grep -qx "target=$T" "$rec" && grep -qx 'bus-daemon=dbus-daemon' "$rec" && grep -qx 'polkit-version=126' "$rec"; } || bad "the record lacks target, daemon or polkit version: $(cat "$rec" 2> /dev/null)"
    { grep -q 'record: bus-daemon=dbus-daemon' "$tmp/out" && grep -q 'record: polkit-version=126' "$tmp/out"; } || bad "the record is not printed"
    STUB_NOPROBE=1 expect_fail probe-empty "$T" || true
    grep -q 'reported no bus-daemon' "$tmp/out" || bad "an empty probe was not named: $(tail -n 3 "$tmp/out")"
done

# --- unknown target: names the targets, never calls the engine
expect_fail unknown-target nope || true
grep -q 'available targets: alma10 arch debian13 fedora44 ubuntu2404 ubuntu2604' "$tmp/out" || bad "an unknown target does not name the available ones"
[ ! -s "$tmp/log" ] || bad "the engine was called for an unknown target"
expect_fail path-target ../targets/debian13 || true
[ ! -s "$tmp/log" ] || bad "the engine was called for a target with a path"

# --- all, with the real targets directory: every real target runs
: > "$tmp/log"; rm -rf "$tmp/o"
STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" all > "$tmp/out" 2>&1 || bad "all (real targets): failed: $(tail -n 5 "$tmp/out")"
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    grep -q "guest.sh $T" "$tmp/log" || bad "all (real targets): $T did not run"
    [ -f "$tmp/o/$T.record" ] || bad "all (real targets): no record for $T"
done

# --- all, with two fake targets copied in with no edit to any script
fake=$tmp/targets
mkdir -p "$fake"
cp -r "$ROOT/e2e/targets/debian13" "$fake/alpha"
cp -r "$ROOT/e2e/targets/debian13" "$fake/beta"
run_all() { : > "$tmp/log"; rm -rf "$tmp/o"; STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_TARGETS="$fake" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" "$@" > "$tmp/out" 2>&1; }
run_all || bad "all: failed: $(tail -n 5 "$tmp/out")"
for t in alpha beta; do
    grep -q "guest.sh $t" "$tmp/log" || bad "all: $t did not run"
    [ -f "$tmp/o/$t.record" ] || bad "all: no record for $t"
done
run_all alpha || bad "a single fake target failed"
grep -q 'guest.sh beta' "$tmp/log" && bad "only alpha was asked for, beta ran"
if STUB_FAIL=alpha run_all; then bad "all: a failing target did not fail the command"; fi
grep -q 'guest.sh beta' "$tmp/log" || bad "all: beta did not run after alpha failed"
grep -q 'failed targets: alpha' "$tmp/out" || bad "all: the failed target is not named"

# --- the case accounting and the skip enforcement, wired in the host
first=$(grep -v '^[[:space:]]*\(#\|$\)' "$ROOT/e2e/cases.list" | head -n 1)
STUB_OMIT=$first expect_fail omitted debian13 || true
grep -q "'$first' was not reported" "$tmp/out" || bad "an omitted case was not named"
STUB_EXTRA=made-up-case expect_fail unknown debian13 || true
grep -q "unknown case 'made-up-case'" "$tmp/out" || bad "an unknown case was not named"
STUB_DUP=$first expect_fail duplicated debian13 || true
grep -q "'$first' reported twice" "$tmp/out" || bad "a duplicated case was not named"
STUB_SKIP=$first expect_fail skip-unlisted debian13 || true
grep -q "'$first' was skipped and is not on the skip list" "$tmp/out" || bad "an unlisted skip did not fail the run"
cp -r "$ROOT/e2e/targets/debian13" "$fake/gamma"
printf '%s: not available on this target\n' "$first" >> "$fake/gamma/skip.list"
STUB_SKIP=$first run_all gamma || bad "a listed skip failed the run: $(tail -n 5 "$tmp/out")"
printf 'bad line without colon\n' >> "$fake/gamma/skip.list"
run_all gamma && bad "a malformed skip list was accepted by the host"
: > "$tmp/log"
# a missing file of a target
rm -rf "$fake/gamma" "$fake/beta"; rm "$fake/alpha/install.sh"
run_all alpha && bad "a target without install.sh was accepted"
! grep -Eq '^(build|run|exec) ' "$tmp/log" || bad "the engine built or ran an incomplete target"

# --- the upgrade case: the ids are registered, a run that omits one fails, and the pair N, N+1 is checked by the host before anything runs
for id in upgrade-version-greater upgrade-service-new-binary upgrade-state-unchanged upgrade-keys-listed upgrade-signs-with-polkit upgrade-no-manual-step; do
    grep -qx "$id" "$ROOT/e2e/cases.list" || bad "cases.list lacks $id"
    STUB_OMIT=$id expect_fail "omitted $id" debian13 || true
    grep -q "'$id' was not reported" "$tmp/out" || bad "an omitted $id was not named"
done
grep -q 'upgrade' "$ROOT/e2e/guest.sh" || bad "the guest does not run the upgrade case"
grep -q 'install.sh' "$ROOT/e2e/upgrade.sh" || bad "the upgrade case does not install N+1 with the target's install.sh"
# N+1 is looked for in its own directory: none there, the run fails before the engine is called
mkdir -p "$tmp/nonext"
: > "$tmp/log"
if STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_NEXT="$tmp/nonext" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1; then bad "a run without package N+1 passed"; fi
grep -q 'no package N+1' "$tmp/out" || bad "a missing N+1 was not named: $(tail -n 3 "$tmp/out")"
! grep -Eq '^(build|run|exec) ' "$tmp/log" || bad "the engine ran without package N+1"
# N+1 must be N with only the version raised: another custodiod, or the same version, is rejected by the host before the engine is called
printf 'another build\n' >> "$FX_DIR/target/release/custodiod"
fx_build other 0.1.1 '' none
mkdir -p "$tmp/otherbin"
cp "$(fx_file other deb)" "$tmp/otherbin/"
: > "$tmp/log"
if STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_NEXT="$tmp/otherbin" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1; then bad "a run with a different custodiod in N+1 passed"; fi
grep -q 'custodiod of N+1 differs' "$tmp/out" || bad "a different custodiod was not named: $(tail -n 3 "$tmp/out")"
! grep -Eq '^(build|run|exec) ' "$tmp/log" || bad "the engine ran with a different custodiod in N+1"
if STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_NEXT="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1; then bad "a run with N as N+1 passed"; fi
grep -q 'same file' "$tmp/out" || bad "N used as N+1 was not named: $(tail -n 3 "$tmp/out")"

# --- F60: the upgrade from the last cargo-deb .deb is for debian13 only, with its own ids
old_ids="upgrade-cargo-deb-version-greater upgrade-cargo-deb-service-new-binary upgrade-cargo-deb-state-unchanged upgrade-cargo-deb-keys-listed upgrade-cargo-deb-signs-with-polkit upgrade-cargo-deb-no-manual-step"
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    if [ "$T" = debian13 ]; then [ -f "$ROOT/e2e/targets/$T/old.pattern" ] || bad "debian13 has no old.pattern"
    else [ ! -e "$ROOT/e2e/targets/$T/old.pattern" ] || bad "$T has an old.pattern"; fi
    # the target's own cases.list belongs to the deb targets only (the purge cycle of F49)
    case $T in debian13 | ubuntu2604 | ubuntu2404) ;; *) [ ! -e "$ROOT/e2e/targets/$T/cases.list" ] || bad "$T has its own cases.list" ;; esac
done
for id in $old_ids; do
    grep -qx "$id" "$ROOT/e2e/targets/debian13/cases.list" || bad "debian13/cases.list lacks $id"
    grep -qx "$id" "$ROOT/e2e/cases.list" && bad "$id is in the common cases.list, so every target would owe it"
    STUB_OMIT=$id expect_fail "omitted $id" debian13 || true
    grep -q "'$id' was not reported" "$tmp/out" || bad "an omitted $id was not named: $(tail -n 3 "$tmp/out")"
done
expect_ok "old ids on debian13" debian13 || true
grep -q 'cases accounted for' "$tmp/out" || bad "debian13 did not account for the cases"
# another target that reports one of them fails (no cases.list of its own, so the id is unknown); a stub run of the old mode on it
cp -r "$ROOT/e2e/targets/ubuntu2604" "$fake/delta"
STUB_EXTRA=upgrade-cargo-deb-version-greater run_all delta && bad "a target without the old package accepted an old-package case"
grep -q "unknown case 'upgrade-cargo-deb-version-greater'" "$tmp/out" || bad "an old-package case on another target was not named: $(tail -n 3 "$tmp/out")"
# the second run failing fails the target
STUB_FAIL_OLD=debian13 expect_fail "old run fails" debian13 || true
grep -q 'upgrade from the old package' "$tmp/out" || bad "a failed old run was not named: $(tail -n 3 "$tmp/out")"
# no old package: fails before the engine is called
mkdir -p "$tmp/noold"
: > "$tmp/log"
if STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_OLD="$tmp/noold" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1; then bad "a run without the old package passed"; fi
grep -q 'no old package' "$tmp/out" || bad "a missing old package was not named: $(tail -n 3 "$tmp/out")"
! grep -Eq '^(build|run|exec) ' "$tmp/log" || bad "the engine ran without the old package"
# the old package is not N
if STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_OLD="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1; then bad "a run with N as the old package passed"; fi
grep -q 'old package is the same file' "$tmp/out" || bad "N used as the old package was not named: $(tail -n 3 "$tmp/out")"
grep -Eqi '^[[:space:]]*(COPY|ADD)\b|pkg-old' "$ROOT/e2e/targets/debian13/Containerfile" && bad "the debian13 image copies or names the old package"

# --- the packages come from the packages directory: none there, the run fails
mkdir -p "$tmp/empty"
STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/empty" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1 && bad "a run without a package passed"


exit "$fail"
