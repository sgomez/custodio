# shellcheck shell=bash
# shellcheck disable=SC2034 # fail is read by the scripts that source this file
# Sourced by scripts/test-e2e-host.sh and scripts/test-e2e-host-oldpath.sh: the fixture packages, the stub `podman` and the helpers run_host, expect_ok
# and expect_fail. The caller sets TEST_NAME (the prefix of its messages).
tmp=$(mktemp -d)
fail=0
bad() { echo "$TEST_NAME: $*" >&2; fail=1; }

# Real (small) packages: the host checks that N+1 is N with only the version raised (e2e/check-next.sh), which needs the contents.
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
fx_init
trap 'fx_cleanup; rm -rf "$tmp"' EXIT
fx_build cur 0.1.0 '' none
fx_build next 0.1.1 '' none
fx_build oldpath 0.1.0 '' oldpath
mkdir -p "$tmp/bin" "$tmp/pkgs" "$tmp/next" "$tmp/old" "$tmp/oldpath"
# the old package (F60) is a third file, distinct from N and N+1; only its name matters to the host
cp "$(fx_file cur deb)" "$tmp/old/custodio_0.0.9-1_amd64.deb"
export E2E_PACKAGES_OLD=$tmp/old
for f in deb rpm archlinux; do
    cp "$(fx_file cur "$f")" "$tmp/pkgs/"
    cp "$(fx_file next "$f")" "$tmp/next/"
done
export E2E_PACKAGES_NEXT=$tmp/next
# the old-path fixture (F61): the .deb and the .rpm only, with other content than N (the host refuses an equal one)
for f in deb rpm; do cp "$(fx_file oldpath "$f")" "$tmp/oldpath/"; done
export E2E_PACKAGES_OLDPATH=$tmp/oldpath
cat > "$tmp/bin/podman" <<'STUB'
#!/usr/bin/env bash
# Logs the arguments; `exec ... guest.sh` prints what the fake guest would, from STUB_* variables.
echo "$*" >> "$STUB_LOG"
case $1 in
run)
    sed -n 's|.*:/pkg/\([^: ]*\):ro.*|\1|p' <<< "$*" > "$STUB_LOG.pkg"
    sed -n 's|.*:/pkg-next/\([^: ]*\):ro.*|\1|p' <<< "$*" > "$STUB_LOG.next"
    sed -n 's|.*:/pkg-old/\([^: ]*\):ro.*|\1|p' <<< "$*" > "$STUB_LOG.old"
    sed -n 's|.*:/pkg-oldpath/\([^: ]*\):ro.*|\1|p' <<< "$*" > "$STUB_LOG.oldpath"
    ;;
exec)
    case "$*" in
    *"is-system-running"*) echo running ;;
    *"/e2e/guest.sh"*)
        mode=main
        t=${*: -1}
        if [ "$t" = old ] || [ "$t" = oldpath ]; then mode=$t; t=${*: -2:1}; fi
        if [ "$mode" = oldpath ]; then
            echo "e2e: installed $(cat "$STUB_LOG.oldpath") from the mounted file"
            list=$STUB_ROOT/e2e/cases.list
            [ "$t" != "${STUB_FAIL_OLDPATH:-}" ] || { echo "e2e: FAIL: stubbed (oldpath)"; exit 1; }
        elif [ "$mode" = old ]; then
            echo "e2e: installed $(cat "$STUB_LOG.old") from the mounted file"
            list=${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/cases.list
            [ "$t" != "${STUB_FAIL_OLD:-}" ] || { echo "e2e: FAIL: stubbed (old)"; exit 1; }
        else
            echo "e2e: installed $(cat "$STUB_LOG.pkg") from the mounted file"
            # the main run reports the common cases and the target's own, except the ones of the old-package run (F60)
            list=$STUB_LOG.main
            : > "$list"
            [ -f "${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/refusal-only" ] || cat "$STUB_ROOT/e2e/cases.list" > "$list" # F50: a refusal-only target owes none of them
            # F61: the cases of the upgrade from the old path run in their own container, except on a target that has none (skipped in the main run)
            if [ ! -f "${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/no-oldpath" ]; then grep -v '^upgrade-oldpath-' "$list" > "$list.x" || true; mv "$list.x" "$list"; fi
            grep -v '^upgrade-cargo-deb-' "${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/cases.list" >> "$list" 2> /dev/null || true
        fi
        while IFS= read -r c; do
            case $c in '' | '#'*) continue ;; esac
            if [ "$mode" = old ]; then case $c in upgrade-cargo-deb-*) ;; *) continue ;; esac; fi
            if [ "$mode" = oldpath ]; then case $c in upgrade-oldpath-*) ;; *) continue ;; esac; fi
            [ "$c" = "${STUB_OMIT:-}" ] && continue
            if [ "$mode" = main ] && [ -f "${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/no-oldpath" ]; then case $c in upgrade-oldpath-*) echo "E2E-CASE skipped $c"; continue ;; esac; fi
            if [ "$c" = "${STUB_SKIP:-}" ]; then echo "E2E-CASE skipped $c"; else echo "E2E-CASE run $c"; fi
            [ "$c" = "${STUB_DUP:-}" ] && echo "E2E-CASE run $c"
        done < "$list"
        [ "$mode" = old ] && exit 0
        [ "$mode" = oldpath ] && exit 0
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
