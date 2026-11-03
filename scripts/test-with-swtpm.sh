#!/usr/bin/env bash
# Tests of scripts/with-swtpm.sh, the engine of `just with-swtpm` (F104). The missing-tool cases always run. The cases that need a real
# swtpm and tpm2-tools (status, cleanup after success, failure, SIGTERM and SIGINT, fresh state) print a SKIP line when the tools are
# absent, and fail instead when CI is set or WITH_SWTPM_REQUIRE=1: where the packages are installed they must run.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUN=$ROOT/scripts/with-swtpm.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-with-swtpm: $*" >&2; fail=1; }

# --- missing tools: a PATH with nothing, then with a swtpm stub only. The command must not run.
mkdir -p "$tmp/empty" "$tmp/stub"
for t in swtpm swtpm_ioctl; do printf '#!/bin/sh\nexit 0\n' > "$tmp/stub/$t"; done
chmod +x "$tmp/stub/swtpm" "$tmp/stub/swtpm_ioctl"
rc=0
PATH=$tmp/empty "$BASH" "$RUN" touch "$tmp/ran" > /dev/null 2> "$tmp/err" || rc=$?
[ "$rc" != 0 ] || bad "no swtpm: status 0"
grep -q 'swtpm is not installed' "$tmp/err" || bad "no swtpm: stderr does not name swtpm: $(cat "$tmp/err")"
[ ! -e "$tmp/ran" ] || bad "no swtpm: the command ran"
rc=0
PATH=$tmp/stub "$BASH" "$RUN" touch "$tmp/ran" > /dev/null 2> "$tmp/err" || rc=$?
[ "$rc" != 0 ] || bad "no tpm2-tools: status 0"
grep -q 'tpm2-tools is not installed' "$tmp/err" || bad "no tpm2-tools: stderr does not name tpm2-tools: $(cat "$tmp/err")"
[ ! -e "$tmp/ran" ] || bad "no tpm2-tools: the command ran"
rc=0
bash "$RUN" > /dev/null 2>&1 || rc=$?
[ "$rc" != 0 ] || bad "no command: status 0"

# --- cases with a real TPM
if ! { command -v swtpm && command -v swtpm_ioctl && command -v tpm2_startup && command -v tpm2_getcap && command -v tpm2_evictcontrol; } > /dev/null 2>&1; then
    if [ -n "${CI:-}" ] || [ "${WITH_SWTPM_REQUIRE:-}" = 1 ]; then
        bad "swtpm or tpm2-tools is missing, and CI or WITH_SWTPM_REQUIRE is set: the real cases must run"
    else
        echo "test-with-swtpm: SKIP the cases that need swtpm and tpm2-tools (not installed); the missing-tool cases ran" >&2
    fi
    exit "$fail"
fi

# The command records "STATE_DIR PID" from its environment in $PROBE.
# shellcheck disable=SC2016 # expanded by the sh -c that runs it
probe='dir=$(dirname "${TPM2TOOLS_TCTI#swtpm:path=}"); echo "$dir $(cat "$dir/swtpm.pid")" > "$PROBE"'
export PROBE=$tmp/probe
gone() { # LABEL: the state directory removed and the swtpm process not running
    local dir pid
    read -r dir pid < "$PROBE" || { bad "$1: the command did not record its state"; return; }
    [ ! -e "$dir" ] || bad "$1: the state directory $dir is still there"
    ! kill -0 "$pid" 2> /dev/null || bad "$1: swtpm $pid is still running"
}

rc=0
bash "$RUN" sh -c "$probe; exit 7" || rc=$?
[ "$rc" = 7 ] || bad "failing command: status $rc, expected 7"
gone "failing command"
bash "$RUN" sh -c "$probe; tpm2_getcap algorithms > /dev/null" || bad "succeeding command failed"
gone "succeeding command"

# Job control (set -m) so the background job does not start with SIGINT ignored, as it would in a plain script.
set -m
for sig in TERM INT; do
    rm -f "$PROBE"
    bash "$RUN" sh -c "$probe; sleep 9" &
    pid=$!
    for _ in $(seq 1 100); do [ -s "$PROBE" ] && break; sleep 0.1; done
    [ -s "$PROBE" ] || { bad "SIG$sig: the command did not start"; kill "$pid" 2> /dev/null || true; continue; }
    kill -"$sig" "$pid"
    rc=0
    wait "$pid" || rc=$?
    [ "$rc" != 0 ] || bad "SIG$sig: status 0"
    gone "SIG$sig"
done
set +m

# --- a new TPM each run: a persistent object from one run is not in the next
bash "$RUN" sh -c 'tpm2_createprimary -C o -c "$0/p.ctx" > /dev/null && tpm2_evictcontrol -C o -c "$0/p.ctx" 0x81010001 > /dev/null && tpm2_getcap handles-persistent | grep -q 0x81010001' "$tmp" \
    || bad "could not persist an object"
out=$(bash "$RUN" tpm2_getcap handles-persistent)
[ -z "$out" ] || bad "the persistent object survived into the next run: $out"
exit "$fail"
