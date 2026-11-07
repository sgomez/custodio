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
fx_build m3 0.0.9 '' none
mkdir -p "$tmp/bin" "$tmp/pkgs" "$tmp/next" "$tmp/oldpath" "$tmp/m3"
for f in deb rpm archlinux; do
    cp "$(fx_file cur "$f")" "$tmp/pkgs/"
    cp "$(fx_file next "$f")" "$tmp/next/"
done
export E2E_PACKAGES_NEXT=$tmp/next
# the old-path fixture (F61): the .deb and the .rpm only, with other content than N (the host refuses an equal one)
for f in deb rpm; do cp "$(fx_file oldpath "$f")" "$tmp/oldpath/"; done
export E2E_PACKAGES_OLDPATH=$tmp/oldpath
# the M3 build (F142): all three formats, a lower version
for f in deb rpm archlinux; do cp "$(fx_file m3 "$f")" "$tmp/m3/"; done
export E2E_PACKAGES_M3=$tmp/m3
# no container starts, so the host's inotify limit is not what the stub runs are about
echo 1000000 > "$tmp/inotify-limit"
export E2E_INOTIFY_LIMIT_FILE=$tmp/inotify-limit
cat > "$tmp/bin/podman" <<'STUB'
#!/usr/bin/env bash
# Logs the arguments; `exec ... guest.sh` prints what the fake guest would, from STUB_* variables.
echo "$*" >> "$STUB_LOG"
# the files of a container are its own: e2e/run.sh runs several at once
cname=''
if [ "$1" = run ]; then
    prev=''
    for a in "$@"; do [ "$prev" = --name ] && cname=$a; prev=$a; done
elif [ "$1" = exec ]; then
    shift_e=''
    for a in "${@:2}"; do
        if [ -n "$shift_e" ]; then shift_e=''; continue; fi
        [ "$a" = -e ] && { shift_e=1; continue; }
        cname=$a; break
    done
fi
C=$STUB_LOG.$cname
case $1 in
run)
    sed -n 's|.*:/pkg/\([^: ]*\):ro.*|\1|p' <<< "$*" > "$C.pkg"
    sed -n 's|.*:/pkg-next/\([^: ]*\):ro.*|\1|p' <<< "$*" > "$C.next"
    sed -n 's|.*:/pkg-oldpath/\([^: ]*\):ro.*|\1|p' <<< "$*" > "$C.oldpath"
    sed -n 's|.*:/pkg-m3/\([^: ]*\):ro.*|\1|p' <<< "$*" > "$C.m3"
    ;;
exec)
    case "$*" in
    *"is-system-running"*) echo running ;;
    *"/e2e/guest.sh"*)
        # F63: with -e E2E_SELECT=ids the fake guest reports only those cases (and STUB_EXTRA still adds one)
        sel=''
        for a in "$@"; do case $a in E2E_SELECT=*) sel=${a#E2E_SELECT=} ;; esac; done
        tpm=''
        for a in "$@"; do case $a in E2E_TPM=*) tpm=${a#E2E_TPM=} ;; esac; done # F131: the TPM mode the host asks for
        mode=main
        t=${*: -1}
        if [ "$t" = oldpath ] || [ "$t" = m3 ]; then mode=$t; t=${*: -2:1}; fi
        if [ "$mode" = m3 ]; then
            echo "e2e: installed $(cat "$C.m3") from the mounted file"
            echo "E2E-PHASE m3-upgrade 2"
            list=$STUB_ROOT/e2e/cases.list
            [ "$t" != "${STUB_FAIL_M3:-}" ] || { echo "e2e: FAIL: stubbed (m3)"; exit 1; }
        elif [ "$mode" = oldpath ]; then
            echo "e2e: installed $(cat "$C.oldpath") from the mounted file"
            echo "E2E-PHASE oldpath-upgrade 2"
            list=$STUB_ROOT/e2e/cases.list
            [ "$t" != "${STUB_FAIL_OLDPATH:-}" ] || { echo "e2e: FAIL: stubbed (oldpath)"; exit 1; }
        else
            echo "e2e: installed $(cat "$C.pkg") from the mounted file"
            echo "E2E-PHASE install 3"
            # the main run reports the common cases and the target's own
            list=$C.main
            : > "$list"
            [ -f "${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/refusal-only" ] || cat "$STUB_ROOT/e2e/cases.list" > "$list" # F50: a refusal-only target owes none of them
            # F61: the cases of the upgrade from the old path run in their own container, except on a target that has none (skipped in the main run)
            if [ ! -f "${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/no-oldpath" ]; then grep -v '^upgrade-oldpath-' "$list" > "$list.x" || true; mv "$list.x" "$list"; fi
            # F142: the cases of the upgrade from the M3 build run in their own container
            grep -v '^upgrade-m3-' "$list" > "$list.x" || true; mv "$list.x" "$list"
            cat "${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/cases.list" >> "$list" 2> /dev/null || true
        fi
        while IFS= read -r c; do
            case $c in '' | '#'*) continue ;; esac
            if [ "$mode" = oldpath ]; then case $c in upgrade-oldpath-*) ;; *) continue ;; esac; fi
            if [ "$mode" = m3 ]; then case $c in upgrade-m3-*) ;; *) continue ;; esac; fi
            [ "$c" = "${STUB_OMIT:-}" ] && continue
            if [ -n "$sel" ]; then case " $sel " in *" $c "*) ;; *) continue ;; esac; fi
            if [ "$mode" = main ] && [ -f "${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/no-oldpath" ]; then case $c in upgrade-oldpath-*) echo "E2E-CASE skipped $c"; continue ;; esac; fi
            # the real guest skips what its mode cannot run (the rules of e2e/check-cases.sh); the list of the target names them
            skipped_here=''
            if grep -q "^$c:" "${E2E_TARGETS:-$STUB_ROOT/e2e/targets}/$t/skip.list" 2> /dev/null; then
                skipped_here=1
                case $c in
                fallback-host-*) [ "${tpm:-swtpm}" = none ] && skipped_here='' ;;
                tpmfail-*) [ "${tpm:-swtpm}" = swtpm ] && skipped_here='' ;;
                tpm-kind-*) [ "${tpm:-swtpm}" = swtpm ] && skipped_here='' ;;
                tpm-dup-* | pcr-* | tpm-clear-* | tpm-slots-*) [ "${tpm:-swtpm}" = none ] || skipped_here='' ;;
                esac
            fi
            if [ "$c" = "${STUB_SKIP:-}" ] || [ -n "$skipped_here" ]; then echo "E2E-CASE skipped $c"; else echo "E2E-CASE run $c"; fi
            [ "$c" = "${STUB_DUP:-}" ] && echo "E2E-CASE run $c"
        done < "$list"
        [ "$mode" = oldpath ] || [ "$mode" = m3 ] && exit 0
        if [ -n "${STUB_SLEEP:-}" ]; then # how many main runs are in the guest at once, one line per run in $STUB_LOG.conc
            touch "$STUB_LOG.act.$cname"
            find "$(dirname "$STUB_LOG")" -maxdepth 1 -name "$(basename "$STUB_LOG").act.*" | wc -l >> "$STUB_LOG.conc"
            sleep "$STUB_SLEEP"
            rm -f "$STUB_LOG.act.$cname"
        fi
        [ -z "${STUB_EXTRA:-}" ] || echo "E2E-CASE run $STUB_EXTRA"
        if [ -z "${STUB_NOPROBE:-}" ]; then
            echo "E2E-RECORD bus-daemon=dbus-daemon"
            echo "E2E-RECORD polkit-version=126"
            [ -n "${STUB_NOTPM:-}" ] || echo "E2E-RECORD tpm=${STUB_TPM_REPORT:-$tpm}"
        fi
        [ "$t" != "${STUB_FAIL:-}" ] || { echo "e2e: FAIL: stubbed"; exit 1; }
        [ -z "${STUB_FAIL_TPM:-}" ] || [ "$tpm" != "$STUB_FAIL_TPM" ] || { echo "e2e: FAIL: stubbed ($tpm)"; exit 1; }
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
