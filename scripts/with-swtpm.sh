#!/usr/bin/env bash
# Runs a command against a fresh software TPM (F104): swtpm in socket mode with its state in a new temporary directory,
# TPM2_Startup run, TPM2TOOLS_TCTI exported (tpm2-tools and tss-esapi read it). swtpm is stopped and the state removed
# whatever the outcome; the exit status is the command's (128+N when it was killed by signal N, or this script got it).
# Usage: scripts/with-swtpm.sh COMMAND [ARG...]   (the recipe: just with-swtpm COMMAND [ARG...])
set -euo pipefail

[ "$#" -gt 0 ] || { echo "with-swtpm: no command given" >&2; exit 2; }
if ! command -v swtpm > /dev/null 2>&1; then
    echo "with-swtpm: swtpm is not installed (Debian/Ubuntu: apt install swtpm swtpm-tools tpm2-tools libtss2-dev)" >&2
    exit 127
fi
for tool in tpm2_startup tpm2_getcap; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "with-swtpm: tpm2-tools is not installed: $tool not found (Debian/Ubuntu: apt install tpm2-tools)" >&2
        exit 127
    fi
done

state=$(mktemp -d "${TMPDIR:-/tmp}/with-swtpm.XXXXXX")
chmod 0700 "$state"
swtpm_pid="" cmd_pid=""
# shellcheck disable=SC2329 # run by the EXIT trap below
cleanup() {
    if [ -n "$cmd_pid" ] && kill -0 "$cmd_pid" 2> /dev/null; then
        kill -TERM "$cmd_pid" 2> /dev/null || true
        wait "$cmd_pid" 2> /dev/null || true
    fi
    if [ -n "$swtpm_pid" ]; then
        kill -TERM "$swtpm_pid" 2> /dev/null || true
        wait "$swtpm_pid" 2> /dev/null || true
    fi
    rm -rf "$state"
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# The TCTI module derives the control socket path from the data socket path (<path>.ctrl).
sock=$state/swtpm.sock
swtpm socket --tpm2 --tpmstate "dir=$state" --server "type=unixio,path=$sock" --ctrl "type=unixio,path=$sock.ctrl" \
    --flags not-need-init --pid "file=$state/swtpm.pid" > "$state/swtpm.log" 2>&1 &
swtpm_pid=$!
for _ in $(seq 1 100); do
    [ -S "$sock" ] && [ -S "$sock.ctrl" ] && break
    kill -0 "$swtpm_pid" 2> /dev/null || { echo "with-swtpm: swtpm exited at start:" >&2; cat "$state/swtpm.log" >&2; exit 1; }
    sleep 0.1
done
[ -S "$sock" ] || { echo "with-swtpm: swtpm did not create its socket" >&2; cat "$state/swtpm.log" >&2; exit 1; }

export TPM2TOOLS_TCTI="swtpm:path=$sock"
tpm2_startup -c || { echo "with-swtpm: TPM2_Startup failed" >&2; exit 1; }

# In the background and waited for, so a signal runs the traps at once instead of after the command.
"$@" &
cmd_pid=$!
rc=0
wait "$cmd_pid" || rc=$?
cmd_pid=""
exit "$rc"
