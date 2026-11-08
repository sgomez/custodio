#!/usr/bin/env bash
# Self-test of the VM launcher e2e/vm/vm.sh (F159), without a VM: stub qemu-system-x86_64 and swtpm (scripts/lib/vm-fakes) record their command
# lines, and the stub QEMU serves a fake guest (a local bash behind a login prompt) on the -serial socket, so the launcher's real channel code
# runs. Real qemu-img, cloud-localds and bsdtar make and read the overlay and the seed. Each check has a negative control: a copy of the launcher
# with the one behaviour removed (shown to differ with cmp), on which the same check must fail. The modes are in test-vm-modes.sh; the real boot
# is at the checkpoint. The scenarios run at once; their results are checked after `wait`.
# shellcheck disable=SC2034,SC2329,SC2086,SC2015,SC2016 # SC2034: IMG_SUM is read by the sourced checks; SC2016: the control texts are launcher source; SC2329: the scenarios run through run() and "$@"; SC2086: $w is a fixed scenario word; SC2015: A && B || C is used as a check
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VMDIR=$ROOT/e2e/vm
FAKES=$ROOT/scripts/lib/vm-fakes
for tool in python3 qemu-img cloud-localds bsdtar sha256sum; do
    command -v "$tool" > /dev/null 2>&1 || { echo "test-vm-launch: $tool is not installed" >&2; exit 127; }
done
tmp=$(mktemp -d)
cleanup() {
    local f
    for f in "$tmp"/*/log*/pids; do
        [ -f "$f" ] || continue
        while read -r _ pid; do kill -9 "$pid" 2> /dev/null || true; done < "$f"
    done
    rm -rf "$tmp"
}
trap cleanup EXIT
mkdir "$tmp/res"
bad() { echo "test-vm-launch: $*" >&2; echo x >> "${FAILFILE:-$tmp/res/failed}"; }

# --- the shared stub world ---
IMG=$tmp/image.qcow2
qemu-img create -q -f qcow2 "$IMG" 1M
printf '#!/bin/sh\necho path=%s\n' "$IMG" > "$tmp/image.sh"
printf '#!/bin/sh\necho "image.sh: down" >&2\nexit 1\n' > "$tmp/image-fail.sh"
chmod +x "$tmp/image.sh" "$tmp/image-fail.sh"
: > "$tmp/kvm"
printf 'OVMF-CODE' > "$tmp/code.fd"
printf 'OVMF-VARS-TEMPLATE' > "$tmp/vars.fd"
cp "$tmp/vars.fd" "$tmp/vars.pristine"
IMG_SUM=$(sha256sum < "$IMG")

world() { mkdir -p "$tmp/$1/log" "$tmp/$1/tmp"; }
# vx WORLD [VAR=value ...] -- ARGS: runs $LAUNCHER (default the real one) in the world; later VAR=value wins over the defaults.
vx() {
    local w=$1 envs=()
    shift
    while [ "$1" != -- ]; do envs+=("$1"); shift; done
    shift
    env STUB_LOG="$tmp/$w/log" TMPDIR="$tmp/$w/tmp" VM_QEMU="$FAKES/qemu-system-x86_64" VM_SWTPM="$FAKES/swtpm" VM_KVM_DEV="$tmp/kvm" \
        VM_IMAGE_SH="$tmp/image.sh" VM_OVMF_CODE="$tmp/code.fd" VM_OVMF_VARS="$tmp/vars.fd" VM_BOOT_TIMEOUT=20 \
        "${envs[@]}" "${LAUNCHER:-$VMDIR/vm.sh}" "$@"
}
# mut NAME FILE OLD NEW: a copy of e2e/vm in $tmp/ctl-NAME with OLD (exact text) replaced by NEW in FILE; fails if OLD is absent or the copy is equal.
mut() {
    mkdir -p "$tmp/ctl-$1"
    cp -r "$VMDIR/." "$tmp/ctl-$1/"
    python3 -I - "$tmp/ctl-$1/$2" "$3" "$4" << 'PY'
import sys
p, old, new = sys.argv[1:]
s = open(p).read()
if old not in s:
    sys.exit("mut: text not found in %s: %r" % (p, old))
open(p, "w").write(s.replace(old, new, 1))
PY
    cmp -s "$VMDIR/$2" "$tmp/ctl-$1/$2" && { bad "control $1: the copy equals the original"; return 1; }
    return 0
}
ctl() { echo "$tmp/ctl-$1/vm.sh"; }
dir_of() { sed -n 's/^VM_DIR=//p' "$1"; }
args_of() { sed '1d' "$tmp/$1/log/$2.$3.args"; } # WORLD qemu|swtpm N: the arguments, one per line
procs_gone() { # WORLD [LOGDIR]: every recorded stub pid is gone
    local f=$tmp/$1/${2:-log}/pids pid
    [ -f "$f" ] || return 0
    while read -r _ pid; do kill -0 "$pid" 2> /dev/null && return 1; done < "$f"
    return 0
}
tmp_empty() { [ -z "$(ls -A "$tmp/$1/tmp")" ]; }
nothing_started() { [ -z "$(ls -A "$tmp/$1/log")" ] && tmp_empty "$1"; }
wait_for() { local i; for ((i = 0; i < 400; i++)); do "$@" && return 0; sleep 0.05; done; return 1; }

# ---------------------------------------------------------------------------------------------------------------------------------
# good: boots, the argument checks, the channel, a power cycle, a stop
# ---------------------------------------------------------------------------------------------------------------------------------
head -c 3000000 /dev/urandom > "$tmp/big.bin"
python3 -I -c 'import sys; sys.stdout.buffer.write(bytes(range(256)))' > "$tmp/all256.bin"
printf 'l1\nl2\n__RC=5__\n\nlast' > "$tmp/exact.expected"

scenario_good() {
    local w=good dir r q1 q2 s1 s2 e
    world $w
    vx $w -- start full > "$tmp/$w/out" 2> "$tmp/$w/err" || { bad "good: start failed: $(cat "$tmp/$w/err")"; return; }
    dir=$(dir_of "$tmp/$w/out")
    for c in ck_kvm ck_pflash ck_tpm ck_overlay; do r=$($c $w) || bad "good: $c: $r"; done
    r=$(ck_seed $w "$dir") || bad "good: ck_seed: $r"
    # the channel
    r=$(vx $w -- run "$dir" 'echo out; exit 3') && e=0 || e=$?
    [ "$r" = out ] && [ "$e" = 3 ] || bad "good: run: output '$r' code $e"
    vx $w -- run "$dir" 'true' > /dev/null || bad "good: run true failed"
    r=$(vx $w -- run "$dir" 'no-such-command-xyz' 2> /dev/null) && e=0 || e=$?
    [ "$e" = 127 ] || bad "good: a missing command gave $e, not 127"
    vx $w -- run "$dir" "printf 'l1\nl2\n__RC=5__\n\nlast'" > "$tmp/$w/exact.out" || bad "good: exact run failed"
    cmp -s "$tmp/$w/exact.out" "$tmp/exact.expected" || bad "good: multi-line output with __RC= changed"
    local t0=$SECONDS
    vx $w -- run "$dir" -t 2 'sleep 30' > /dev/null 2>&1 && e=0 || e=$?
    [ "$e" != 0 ] && [ $((SECONDS - t0)) -le 4 ] || bad "good: a hanging command gave $e after $((SECONDS - t0))s"
    r=$(vx $w -- run "$dir" 'echo alive') || bad "good: the guest does not answer after a timeout"
    [ "$r" = alive ] || bad "good: after the timeout: '$r'"
    for f in all256 big; do
        vx $w -- put "$dir" "$tmp/$f.bin" "$tmp/$w/$f.remote" || bad "good: put $f failed"
        cmp -s "$tmp/$f.bin" "$tmp/$w/$f.remote" || bad "good: put $f is not byte-exact"
        vx $w -- get "$dir" "$tmp/$w/$f.remote" "$tmp/$w/$f.back" || bad "good: get $f failed"
        cmp -s "$tmp/$f.bin" "$tmp/$w/$f.back" || bad "good: get $f is not byte-exact"
    done
    # the power cycle: the same swtpm state, a new QEMU
    q1=$(sed -n 's/^qemu //p' "$tmp/$w/log/pids" | tail -n1)
    vx $w -- cycle "$dir" || bad "good: cycle failed"
    q2=$(sed -n 's/^qemu //p' "$tmp/$w/log/pids" | tail -n1)
    [ -n "$q2" ] && [ "$q1" != "$q2" ] || bad "good: no new QEMU after the cycle ($q1 $q2)"
    r=$(vx $w -- run "$dir" 'echo after-cycle') && [ "$r" = after-cycle ] || bad "good: the guest does not answer after the cycle"
    s1=$(args_of $w swtpm 1 | sed -n 's/^dir=//p'); s2=$(args_of $w swtpm 2 | sed -n 's/^dir=//p')
    [ -n "$s1" ] && [ "$s1" = "$s2" ] || bad "good: the swtpm state directory changed over the cycle ($s1 / $s2)"
    [ -z "$(cat "$tmp/$w/log/swtpm.1.state-before")" ] || bad "good: the first swtpm found a non-empty state"
    grep -qx marker "$tmp/$w/log/swtpm.2.state-before" || bad "good: the second swtpm did not find the marker of the first"
    [ "$(args_of $w qemu 1 | sed -n 's/^if=pflash,format=raw,file=//p')" = "$(args_of $w qemu 2 | sed -n 's/^if=pflash,format=raw,file=//p')" ] \
        || bad "good: the vars copy changed over the cycle"
    vx $w -- stop "$dir" || bad "good: stop failed"
    procs_gone $w || bad "good: stub processes left after stop"
    tmp_empty $w || bad "good: files left after stop: $(ls -A "$tmp/$w/tmp")"
    [ ! -e "$dir" ] || bad "good: $dir left"
    ck_backing_untouched > /dev/null || bad "good: the image changed"
}

# two launches at once, the second world a second run: different directories and sockets, an empty state each
scenario_two() {
    local w=two out1 out2 d1 d2 r
    world $w; mkdir -p "$tmp/$w/log2"
    vx $w -- start full > "$tmp/$w/out1" 2> "$tmp/$w/err1" &
    local p1=$!
    vx $w STUB_LOG="$tmp/$w/log2" -- start full > "$tmp/$w/out2" 2> "$tmp/$w/err2" &
    local p2=$!
    wait $p1 || bad "two: the first launch failed: $(cat "$tmp/$w/err1")"
    wait $p2 || bad "two: the second launch failed: $(cat "$tmp/$w/err2")"
    d1=$(dir_of "$tmp/$w/out1"); d2=$(dir_of "$tmp/$w/out2")
    [ -n "$d1" ] && [ -n "$d2" ] && [ "$d1" != "$d2" ] || bad "two: the directories are not different ($d1 $d2)"
    out1=$(sed -n 's/^socket,id=chrtpm,path=//p' "$tmp/$w/log/qemu.1.args"); out2=$(sed -n 's/^socket,id=chrtpm,path=//p' "$tmp/$w/log2/qemu.1.args")
    [ "$out1" != "$out2" ] || bad "two: the same swtpm socket"
    [ "$(grep '^unix:' "$tmp/$w/log/qemu.1.args")" != "$(grep '^unix:' "$tmp/$w/log2/qemu.1.args")" ] || bad "two: the same serial socket"
    [ "$(sed -n 's/^dir=//p' "$tmp/$w/log/swtpm.1.args")" != "$(sed -n 's/^dir=//p' "$tmp/$w/log2/swtpm.1.args")" ] || bad "two: the same state directory"
    [ -z "$(cat "$tmp/$w/log/swtpm.1.state-before" "$tmp/$w/log2/swtpm.1.state-before")" ] || bad "two: a state was not empty"
    [ "$(sed -n 's/^if=pflash,format=raw,file=//p' "$tmp/$w/log/qemu.1.args")" != "$(sed -n 's/^if=pflash,format=raw,file=//p' "$tmp/$w/log2/qemu.1.args")" ] \
        || bad "two: the same vars copy"
    r=$(vx $w -- run "$d1" 'echo one') && [ "$r" = one ] || bad "two: first guest does not answer"
    vx $w -- stop "$d1" || bad "two: stop 1"
    vx $w STUB_LOG="$tmp/$w/log2" -- stop "$d2" || bad "two: stop 2"
    tmp_empty $w || bad "two: files left"
}

# a second run in the same world after the first: a different, empty state (the first run's marker is not there)
scenario_reuse() {
    local w=reuse d
    world $w
    for _ in 1 2; do
        vx $w -- start full > "$tmp/$w/out" 2> "$tmp/$w/err" || { bad "reuse: start failed: $(cat "$tmp/$w/err")"; return; }
        d=$(dir_of "$tmp/$w/out")
        vx $w -- stop "$d" || bad "reuse: stop failed"
    done
    [ -f "$tmp/$w/log/swtpm.2.args" ] || { bad "reuse: no second swtpm"; return; }
    [ -z "$(cat "$tmp/$w/log/swtpm.2.state-before")" ] || bad "reuse: the second run found the first run's state: $(cat "$tmp/$w/log/swtpm.2.state-before")"
    [ "$(sed -n 's/^dir=//p' "$tmp/$w/log/swtpm.1.args")" != "$(sed -n 's/^dir=//p' "$tmp/$w/log/swtpm.2.args")" ] || bad "reuse: the same state directory twice"
}

# ---------------------------------------------------------------------------------------------------------------------------------
# refusals and failures
# ---------------------------------------------------------------------------------------------------------------------------------
scenario_refuse() { # NAME [VAR=value ...] -- args: must exit non-zero, name KVM, start nothing, leave nothing
    local w=ref-$1 rc=0
    shift
    world "$w"
    vx "$w" "$@" > "$tmp/$w/out" 2> "$tmp/$w/err" || rc=$?
    [ "$rc" != 0 ] || bad "$w: it started"
    grep -qi 'kvm' "$tmp/$w/err" || bad "$w: the message does not name KVM: $(cat "$tmp/$w/err")"
    nothing_started "$w" || bad "$w: something started or was left: $(ls -A "$tmp/$w/log" "$tmp/$w/tmp")"
}
refuse_ok() { # as scenario_refuse, for use inside a control: returns non-zero instead of calling bad
    local w=$1 rc=0
    shift
    world "$w"
    vx "$w" "$@" > "$tmp/$w/out" 2> "$tmp/$w/err" || rc=$?
    [ "$rc" != 0 ] && grep -qi kvm "$tmp/$w/err" && nothing_started "$w"
}

scenario_failures() {
    local w rc t0 dir
    # boot timeout: the guest never shows a login; fails, and nothing is left
    w=fail-timeout; world $w
    t0=$SECONDS
    vx $w STUB_QEMU_NOLOGIN=1 VM_BOOT_TIMEOUT=2 -- start full > "$tmp/$w/out" 2> "$tmp/$w/err" && bad "$w: it succeeded" || true
    [ $((SECONDS - t0)) -le 6 ] || bad "$w: took $((SECONDS - t0))s for a 2s timeout"
    procs_gone $w || bad "$w: processes left"; tmp_empty $w || bad "$w: files left"
    # qemu fails to start: the swtpm that was started is gone
    w=fail-qemu; world $w
    vx $w STUB_QEMU_FAIL=1 -- start full > "$tmp/$w/out" 2> "$tmp/$w/err" && bad "$w: it succeeded" || true
    [ -f "$tmp/$w/log/swtpm.1.args" ] || bad "$w: swtpm was not even started"
    procs_gone $w || bad "$w: swtpm left"; tmp_empty $w || bad "$w: files left"
    # qemu starts and dies at once
    w=fail-qemudie; world $w
    vx $w STUB_QEMU_DIE=1 -- start full > "$tmp/$w/out" 2> "$tmp/$w/err" && bad "$w: it succeeded" || true
    procs_gone $w || bad "$w: processes left"; tmp_empty $w || bad "$w: files left"
    # swtpm refuses: no QEMU was started
    w=fail-swtpm; world $w
    vx $w STUB_SWTPM_FAIL=1 -- start full > "$tmp/$w/out" 2> "$tmp/$w/err" && bad "$w: it succeeded" || true
    ls "$tmp/$w/log"/qemu.* > /dev/null 2>&1 && bad "$w: QEMU was started after swtpm failed"
    tmp_empty $w || bad "$w: files left"
    # a failing command, then a normal stop
    w=fail-cmd; world $w
    if vx $w -- start full > "$tmp/$w/out" 2> "$tmp/$w/err"; then
        dir=$(dir_of "$tmp/$w/out")
        vx $w -- run "$dir" 'exit 7' > /dev/null && bad "$w: exit 7 gave 0" || true
        vx $w -- stop "$dir" || bad "$w: stop failed"
        procs_gone $w || bad "$w: processes left"; tmp_empty $w || bad "$w: files left"
    else bad "$w: start failed"; fi
    # the image cannot be had: nothing starts
    w=fail-image; world $w
    vx $w VM_IMAGE_SH="$tmp/image-fail.sh" -- start full > "$tmp/$w/out" 2> "$tmp/$w/err" && bad "$w: it succeeded" || true
    nothing_started $w || bad "$w: something started with a failing image.sh"
    # a state directory supplied by the caller
    w=fail-state; world $w; mkdir "$tmp/$w/mine"; echo old > "$tmp/$w/mine/tpm2-00.permall"
    vx $w VM_TPM_STATE="$tmp/$w/mine" -- start full > "$tmp/$w/out" 2> "$tmp/$w/err" && bad "$w: it accepted a caller's state directory" || true
    grep -q VM_TPM_STATE "$tmp/$w/err" || bad "$w: the message does not name VM_TPM_STATE"
    nothing_started $w || bad "$w: something started"
    [ "$(ls "$tmp/$w/mine")" = tpm2-00.permall ] || bad "$w: the caller's directory was touched"
}

scenario_signal() { # SIG: the launcher is killed while it waits for a login that never comes
    local sig=$1 w=${2:-sig-$1} pid rc=0
    world "$w"
    env --default-signal=INT,TERM STUB_LOG="$tmp/$w/log" TMPDIR="$tmp/$w/tmp" VM_QEMU="$FAKES/qemu-system-x86_64" VM_SWTPM="$FAKES/swtpm" \
        VM_KVM_DEV="$tmp/kvm" VM_IMAGE_SH="$tmp/image.sh" VM_OVMF_CODE="$tmp/code.fd" VM_OVMF_VARS="$tmp/vars.fd" STUB_QEMU_NOLOGIN=1 VM_BOOT_TIMEOUT=60 \
        "${LAUNCHER:-$VMDIR/vm.sh}" start full > "$tmp/$w/out" 2> "$tmp/$w/err" &
    pid=$!
    has_qemu() { grep -q '^qemu ' "$tmp/$w/log/pids" 2> /dev/null; }
    wait_for has_qemu || { bad "$w: the stub QEMU never started"; kill -9 $pid 2> /dev/null; return; }
    kill -"$sig" $pid
    wait $pid || rc=$?
    [ "$rc" != 0 ] || bad "$w: exit code 0"
    procs_gone "$w" || bad "$w: processes left"
    tmp_empty "$w" || bad "$w: files left: $(ls -A "$tmp/$w/tmp")"
}
sig_ok() { # as scenario_signal, inside a control, with its own failure file: returns non-zero when something is left
    (
        FAILFILE=$tmp/res/sigctl
        rm -f "$FAILFILE"
        scenario_signal "$1" c-sig-notrap 2> /dev/null
        [ ! -e "$FAILFILE" ]
    )
}

scenario_path() { # TMPDIR over 100 characters: works, or refuses before starting anything naming the path length
    local w=path base rc=0 dir
    world $w
    base=$tmp/$w/$(printf 'p%.0s' $(seq 1 100))
    mkdir -p "$base"
    vx $w TMPDIR="$base" -- start full > "$tmp/$w/out" 2> "$tmp/$w/err" || rc=$?
    if [ "$rc" = 0 ]; then
        dir=$(dir_of "$tmp/$w/out"); vx $w TMPDIR="$base" -- stop "$dir" || true
    else
        grep -qi 'path length' "$tmp/$w/err" || bad "$w: the refusal does not name the path length: $(cat "$tmp/$w/err")"
        [ -z "$(ls -A "$tmp/$w/log")" ] && [ -z "$(ls -A "$base")" ] || bad "$w: something started or was left"
    fi
}

scenario_chan_timeout() { # chan.py wait against a console that never shows a login: fails at its timeout, within one second more
    local w=chan sock t0 t1 rc=0
    world $w
    sock=$tmp/$w/s.sock
    python3 -I -c '
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1)
c, _ = s.accept(); time.sleep(8)' "$sock" &
    local srv=$!
    wait_for test -S "$sock" || { bad "chan: no socket"; return; }
    t0=$(date +%s.%N)
    python3 -I "$VMDIR/chan.py" "$sock" wait --timeout 2 2> /dev/null || rc=$?
    t1=$(date +%s.%N)
    kill $srv 2> /dev/null || true
    [ "$rc" != 0 ] || bad "chan: wait succeeded without a login"
    python3 -I -c 'import sys; d=float(sys.argv[2])-float(sys.argv[1]); sys.exit(0 if 1.9 <= d <= 3.0 else 1)' "$t0" "$t1" || bad "chan: wait ended at $(python3 -I -c 'import sys; print(float(sys.argv[2])-float(sys.argv[1]))' "$t0" "$t1")s for a 2s timeout"
}

# shellcheck source=scripts/lib/vm-launch-controls.sh
. "$ROOT/scripts/lib/vm-launch-controls.sh"

# ---------------------------------------------------------------------------------------------------------------------------------
# run everything at once
# ---------------------------------------------------------------------------------------------------------------------------------
pids=()
# ONLY=text runs only the scenarios whose name contains the text (for work on one of them).
run() { [ -z "${ONLY:-}" ] || [[ "$*" == *"$ONLY"* ]] || return 0; "$@" & pids+=($!); }
run scenario_good
run scenario_two
run scenario_reuse
run scenario_failures
run scenario_signal INT
run scenario_signal TERM
run scenario_path
run scenario_chan_timeout
run scenario_refuse nokvm-missing VM_KVM_DEV="$tmp/missing-kvm" -- start full
run scenario_refuse nokvm-dir VM_KVM_DEV="$tmp" -- start full
run scenario_refuse nokvm-accel STUB_QEMU_NO_KVM=1 -- start full
run scenario_refuse accel-env VM_KVM_DEV="$tmp/missing-kvm" QEMU_ACCEL=tcg ACCEL=tcg -- start full
run scenario_refuse accel-arg VM_KVM_DEV="$tmp/missing-kvm" -- start full --accel tcg
for c in overlay kvm vars tpm seed statecycle statereuse exitcode strip nokvmcheck notrap notrap_sig; do run "control_$c"; done
for p in "${pids[@]}"; do wait "$p" || true; done

if [ -f "$tmp/res/failed" ]; then exit 1; fi
exit 0
