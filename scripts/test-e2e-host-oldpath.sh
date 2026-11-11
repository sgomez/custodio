#!/usr/bin/env bash
# F61: the host script e2e/run.sh with the stub `podman` of scripts/lib/e2e-host-fixtures.sh: the upgrade from the old-path fixture runs in its own fresh
# container on one target per package format (debian13, alma10), with its own case ids; the others (no-oldpath marker) skip them; the host refuses a missing, equal or copied package.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_NAME=test-e2e-host-oldpath
# shellcheck source=scripts/lib/e2e-host-fixtures.sh
. "$ROOT/scripts/lib/e2e-host-fixtures.sh"
fake=$tmp/targets
mkdir -p "$fake"
# --- F61: the upgrade from the old-path fixture runs on every target that has one, with its own ids
oldpath_ids="upgrade-oldpath-version-greater upgrade-oldpath-service-new-binary upgrade-oldpath-state-unchanged upgrade-oldpath-keys-listed upgrade-oldpath-signs-with-polkit upgrade-oldpath-no-manual-step"
for id in $oldpath_ids; do
    grep -qx "$id" "$ROOT/e2e/cases.list" || bad "cases.list lacks $id"
    ! grep -qx "$id" "$ROOT"/e2e/targets/*/cases.list || bad "$id is in a per-target cases.list"
    STUB_OMIT=$id expect_fail "omitted $id" debian13 || true
    grep -q "'$id' was not reported" "$tmp/out" || bad "an omitted $id was not named: $(tail -n 3 "$tmp/out")"
    # Arch has no old path: the case is skipped there and the skip list says so; an Arch run that omits it still fails
    grep -q "^$id:" "$ROOT/e2e/targets/arch/skip.list" || bad "the arch skip list lacks $id"
    STUB_OMIT=$id expect_fail "omitted $id on arch" arch || true
    grep -q "'$id' was not reported" "$tmp/out" || bad "an omitted $id on arch was not named: $(tail -n 3 "$tmp/out")"
done
# one target per package format with an old path runs the upgrade from it: debian13 (deb) and alma10 (rpm); the others carry the marker and skip its cases
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    case $T in
    arch | fedora44 | ubuntu2604)
        [ -s "$ROOT/e2e/targets/$T/no-oldpath" ] || bad "$T has no no-oldpath marker with a reason"
        for id in $oldpath_ids; do grep -q "^$id:" "$ROOT/e2e/targets/$T/skip.list" || bad "the $T skip list lacks $id"; done ;;
    debian13 | alma10) [ ! -e "$ROOT/e2e/targets/$T/no-oldpath" ] || bad "$T has a no-oldpath marker, so no target of its format runs the upgrade from the old path" ;;
    *) bad "unknown target $T: say whether it runs the upgrade from the old path" ;;
    esac
done
expect_ok "oldpath ids on debian13" debian13 || true
grep -q 'cases accounted for' "$tmp/out" || bad "debian13 did not account for the oldpath cases"
expect_ok "oldpath skips on arch" arch || true
[ "$(grep -c 'skipped (on the skip list): upgrade-oldpath-' "$tmp/out")" -eq 6 ] || bad "arch did not skip the six old-path cases: $(grep skipped "$tmp/out")"
# a target that reports an old-path case as run when it has no old path skips nothing; one that skips it without a skip list entry fails
STUB_SKIP=upgrade-oldpath-keys-listed expect_fail "skipped old-path case on debian13" debian13 || true
grep -q "'upgrade-oldpath-keys-listed' was skipped and is not on the skip list" "$tmp/out" || bad "an unlisted old-path skip was not named: $(tail -n 3 "$tmp/out")"
# the third run failing fails the target
STUB_FAIL_OLDPATH=debian13 expect_fail "oldpath run fails" debian13 || true
grep -q 'upgrade from the old-path package' "$tmp/out" || bad "a failed oldpath run was not named: $(tail -n 3 "$tmp/out")"
# no old-path package: fails before the engine is called
mkdir -p "$tmp/nooldpath"
: > "$tmp/log"
if STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_OLDPATH="$tmp/nooldpath" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1; then bad "a run without the old-path package passed"; fi
grep -q 'no old-path package' "$tmp/out" || bad "a missing old-path package was not named: $(tail -n 3 "$tmp/out")"
! grep -Eq '^(build|run|exec) ' "$tmp/log" || bad "the engine ran without the old-path package"
# the old-path package is not N, nor N+1, nor has N's content
if STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_OLDPATH="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1; then bad "a run with N as the old-path package passed"; fi
grep -q 'old-path package is the same file' "$tmp/out" || bad "N used as the old-path package was not named: $(tail -n 3 "$tmp/out")"
mkdir -p "$tmp/copyofn"
cp "$(fx_file cur deb)" "$tmp/copyofn/"
if STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_OLDPATH="$tmp/copyofn" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1; then bad "a run with a copy of N as the old-path package passed"; fi
grep -q 'old-path package has the same content as N' "$tmp/out" || bad "a copy of N as the old-path package was not named: $(tail -n 3 "$tmp/out")"
# a target with a no-oldpath marker needs no old-path package at all
: > "$tmp/log"
STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_OLDPATH="$tmp/nooldpath" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" arch > "$tmp/out" 2>&1 || bad "arch needed an old-path package: $(tail -n 3 "$tmp/out")"


exit "$fail"
