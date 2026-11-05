#!/usr/bin/env bash
# F45: the host script e2e/run.sh with a stub `podman` on PATH that logs its arguments; no container is started. Checked here: the order
# and shape of the engine calls, the target choice and `all`, the read-only package mount, the record, the case accounting and the skip
# enforcement as wired in the host, the Containerfiles (no package copied, real polkit and bus daemon), the lint file list.
# NOT checked here: that a real container boots and the suite passes in it; that is the real run of `just e2e debian13`.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_NAME=test-e2e-host
# shellcheck source=scripts/lib/e2e-host-fixtures.sh
. "$ROOT/scripts/lib/e2e-host-fixtures.sh"

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
        # F50: the package never installs on this target; no N+1 and no old-path package, one read-only mount
        [ "$(grep -o -- '-v [^ ]*:/pkg[^ ]*:ro' "$tmp/log" | sort -u | wc -l)" -eq 1 ] || bad "$T: a refusal-only target mounts more than the package"
        grep -q 'pkg-next\|pkg-oldpath' "$tmp/log" && bad "$T: a refusal-only target mounts N+1 or the old-path package"
        continue
    fi
    nxt=$(find "$tmp/next" -name "$(head -n 1 "$ROOT/e2e/targets/$T/package.pattern")" -exec basename {} \; | sort | tail -n 1)
    [ -n "$nxt" ] || bad "$T: package.pattern matches none of the fake N+1 packages"
    grep '^run ' "$tmp/log" | grep -q -- "$tmp/next/$nxt:/pkg-next/$nxt:ro" || bad "$T: N+1 is not mounted read-only at /pkg-next"
    [ "$nxt" != "$pkg" ] || bad "$T: N and N+1 are the same file name"
    # the mounts and the containers: N and N+1 and the old-path fixture of F61 (every target without a no-oldpath marker)
    mounts=2 runs=1
    [ -f "$ROOT/e2e/targets/$T/no-oldpath" ] || { mounts=$((mounts + 1)); runs=$((runs + 1)); }
    [ "$(grep -o -- '-v [^ ]*:/pkg[^ ]*:ro' "$tmp/log" | sort -u | wc -l)" -eq "$mounts" ] || bad "$T: expected $mounts different read-only mounts: $(grep '^run ' "$tmp/log")"
    [ "$(grep -c '^run ' "$tmp/log")" -eq "$runs" ] || bad "$T: expected $runs containers, each upgrade source in a fresh one: $(grep -c '^run ' "$tmp/log")"
    [ "$(grep -c '^rm .*custodio-e2e-' "$tmp/log")" -ge "$runs" ] || bad "$T: a container is not removed before the next"
    if [ -f "$ROOT/e2e/targets/$T/no-oldpath" ]; then
        grep -q 'pkg-oldpath' "$tmp/log" && bad "$T: the old-path package is mounted on a target with a no-oldpath marker"
        grep -q 'guest.sh [a-z0-9]* oldpath' "$tmp/log" && bad "$T: the old-path run happened on a target with a no-oldpath marker"
    else
        # F61: the old-path fixture is a read-only mount at /pkg-oldpath, upgraded from in a fresh container
        oldp=$(find "$tmp/oldpath" -name "$(head -n 1 "$ROOT/e2e/targets/$T/package.pattern")" -exec basename {} \; | sort | tail -n 1)
        grep '^run ' "$tmp/log" | grep -q -- "$tmp/oldpath/$oldp:/pkg-oldpath/$oldp:ro" || bad "$T: the old-path package is not mounted read-only at /pkg-oldpath"
        grep -q "exec .* bash /e2e/guest.sh $T oldpath" "$tmp/log" || bad "$T: the guest is not run in the oldpath mode"
        [ "$(grep -c "guest.sh $T oldpath" "$tmp/log")" -eq 1 ] || bad "$T: the oldpath run happened more than once"
        rl=$(grep -n "guest.sh $T oldpath" "$tmp/log" | cut -d: -f1)
        rr=$(grep -n '^run ' "$tmp/log" | tail -n 1 | cut -d: -f1)
        rrm=$(grep -n '^rm ' "$tmp/log" | head -n 1 | cut -d: -f1)
        { [ "$rrm" -lt "$rr" ] && [ "$rr" -lt "$rl" ]; } || bad "$T: the oldpath run is not in its own fresh container: $(cat "$tmp/log")"
    fi
    grep -q "exec .* bash /e2e/guest.sh $T" "$tmp/log" || bad "the shared guest script is not executed"
    grep -q "installed $pkg from the mounted file" "$tmp/out" || bad "the guest's output is not passed through"
    grep -qi 'cargo\|nfpm\|just package' "$tmp/log" && bad "the engine log shows a package build"
    grep -q 'cargo\|nfpm\|just package' "$ROOT/e2e/run.sh" && bad "the host script builds packages"
done
# the recipe: package is its dependency and the default target is all
grep -Eq '^e2e target="all": e2e-packages$' "$ROOT/justfile" || bad "the e2e recipe does not take a target (default all) and depend on the shared package build"
grep -q 'bash e2e/run.sh {{target}}' "$ROOT/justfile" || bad "the e2e recipe does not pass the target"

# --- the record
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    expect_ok "$T" "$T" || true
    rec=$tmp/o/$T.swtpm.record
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
    [ -f "$tmp/o/$T.swtpm.record" ] || bad "all (real targets): no record for $T"
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
    [ -f "$tmp/o/$t.swtpm.record" ] || bad "all: no record for $t"
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

# --- the target's own cases (the purge cycle of F49) are for the deb targets only, with their own ids
own_ids="purge-service-stopped purge-no-packaged-files purge-not-activatable purge-state-unchanged purge-account-kept purge-notice-keys reinstall-after-purge-keys-listed reinstall-after-purge-signs-with-polkit reinstall-after-purge-no-import"
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    # the target's own cases.list belongs to the deb targets only
    case $T in debian13 | ubuntu2604 | ubuntu2404) ;; *) [ ! -e "$ROOT/e2e/targets/$T/cases.list" ] || bad "$T has its own cases.list" ;; esac
done
for id in $own_ids; do
    grep -qx "$id" "$ROOT/e2e/targets/debian13/cases.list" || bad "debian13/cases.list lacks $id"
    grep -qx "$id" "$ROOT/e2e/cases.list" && bad "$id is in the common cases.list, so every target would owe it"
    STUB_OMIT=$id expect_fail "omitted $id" debian13 || true
    grep -q "'$id' was not reported" "$tmp/out" || bad "an omitted $id was not named: $(tail -n 3 "$tmp/out")"
done
expect_ok "own ids on debian13" debian13 || true
grep -q 'cases accounted for' "$tmp/out" || bad "debian13 did not account for the cases"
# a case that no list of the target owes is refused, on debian13 and on another target
STUB_EXTRA=upgrade-unlisted-case expect_fail "unlisted case on debian13" debian13 || true
grep -q "unknown case 'upgrade-unlisted-case'" "$tmp/out" || bad "an unlisted case on debian13 was not named: $(tail -n 3 "$tmp/out")"
cp -r "$ROOT/e2e/targets/ubuntu2604" "$fake/delta"
STUB_EXTRA=upgrade-unlisted-case run_all delta && bad "a target accepted a case that no list owes"
grep -q "unknown case 'upgrade-unlisted-case'" "$tmp/out" || bad "an unlisted case on another target was not named: $(tail -n 3 "$tmp/out")"
grep -Eqi '^[[:space:]]*(COPY|ADD)\b' "$ROOT/e2e/targets/debian13/Containerfile" && bad "the debian13 image copies a package"

# --- the packages come from the packages directory: none there, the run fails
mkdir -p "$tmp/empty"
STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/empty" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1 && bad "a run without a package passed"


exit "$fail"
