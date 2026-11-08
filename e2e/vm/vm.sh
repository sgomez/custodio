#!/usr/bin/env bash
# The VM launcher (SPEC Design 1, "Machine" and "TPM modes"). It boots the verified Ubuntu 26.04 image (e2e/vm/image.sh) as a qcow2 overlay
# under QEMU with KVM, OVMF code plus a per-run copy of the vars file, and a tpm-crb device backed by an swtpm on the host, configures the
# guest with a cloud-init NoCloud seed and drives it over its serial console (docs/findings/F151.md). It changes nothing in the product and
# installs nothing in the guest. It never uses software emulation: without a /dev/kvm it can open read-write, and a QEMU that offers kvm, it
# refuses before starting anything.
#
#   vm.sh start MODE        boot a new VM and wait for its login; MODE is `full` (the virtual TPM unchanged) or `lacking` (swtpm with the
#                           profile e2e/vm/lacking-rsa.json: no TPM2_RSA_Decrypt, so RSA 2048 is not usable; docs/findings/F152.md).
#                           Prints `VM_DIR=<dir>` on success; every later command takes that directory. On failure nothing is left behind.
#   vm.sh wait DIR          wait until the guest answers at a shell
#   vm.sh run DIR [-t S] CMD  run the shell string CMD in the guest as `ubuntu`: output (stdout and stderr together) on stdout, the exit
#                           code is ours (124 after S seconds, default 120)
#   vm.sh put DIR LOCAL REMOTE / vm.sh get DIR REMOTE LOCAL   copy a file into / out of the guest, byte for byte
#   vm.sh cycle DIR         power cycle: shut the guest down, start QEMU again on the same disk, vars copy and swtpm state
#   vm.sh stop DIR          shut down and remove everything the run made (QEMU, swtpm, the directory)
#
# The swtpm state directory is made fresh for each run inside DIR, is never one the caller supplies (VM_TPM_STATE is refused) and is the one
# every power cycle of that run reuses. After `start` succeeds the caller must call `stop` (also from its own trap).
# Settings (all optional; the self-tests use them): VM_BOOT_TIMEOUT (240), VM_KVM_DEV (/dev/kvm), VM_QEMU, VM_IMAGE_SH, VM_OVMF_CODE, VM_OVMF_VARS,
# VM_SWTPM and VM_SWTPM_PREFIX (e2e/vm/swtpm-path.sh), TMPDIR.
# Guest account: ubuntu / custodio-throwaway-test, a throwaway credential of a VM that is never reachable from a network (user networking,
# no port forward).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=/dev/null
. "$HERE/swtpm-path.sh"

QEMU=${VM_QEMU:-qemu-system-x86_64}
KVM_DEV=${VM_KVM_DEV:-/dev/kvm}
IMAGE_SH=${VM_IMAGE_SH:-$HERE/image.sh}
OVMF_CODE=${VM_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
OVMF_VARS=${VM_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
BOOT_TIMEOUT=${VM_BOOT_TIMEOUT:-240}
PROFILE=$HERE/lacking-rsa.json
GUEST_USER=ubuntu
GUEST_PASSWORD=custodio-throwaway-test
export VM_USER=$GUEST_USER VM_PASSWORD=$GUEST_PASSWORD

die() { echo "vm.sh: $*" >&2; exit 1; }

RUN_DIR=
CHAN_PID=
# pid_of FILE: the pid in FILE if that process exists.
pid_of() {
    local p
    [ -s "$1" ] || return 1
    p=$(<"$1")
    [[ $p =~ ^[0-9]+$ ]] && kill -0 "$p" 2> /dev/null && echo "$p"
}
# wait_until SECONDS CMD...: polls CMD (no fixed sleep: it returns as soon as CMD holds).
wait_until() {
    local end=$((SECONDS + $1)) i=0
    shift
    while ! "$@"; do
        i=$((i + 1))
        if [ "$SECONDS" -ge "$end" ] && [ "$i" -gt 2 ]; then return 1; fi
        sleep 0.05
    done
}
gone() { ! pid_of "$1" > /dev/null; }
# stop_pid FILE: ends the process, TERM first, then KILL.
stop_pid() {
    local p
    p=$(pid_of "$1") || return 0
    kill "$p" 2> /dev/null || true
    wait_until 5 gone "$1" || { kill -9 "$p" 2> /dev/null || true; wait_until 5 gone "$1" || true; }
}
cleanup() {
    if [ -n "$CHAN_PID" ]; then kill "$CHAN_PID" 2> /dev/null || true; fi
    if [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ]; then
        stop_pid "$RUN_DIR/qemu.pid"
        stop_pid "$RUN_DIR/swtpm.pid"
        rm -rf -- "$RUN_DIR"
    fi
}
# chan ARGS...: the channel driver, in the background and waited for, so that a signal to this script is handled at once.
chan() {
    local rc=0
    python3 -I "$HERE/chan.py" "$@" &
    CHAN_PID=$!
    wait "$CHAN_PID" || rc=$?
    CHAN_PID=
    return "$rc"
}
logs() {
    local f
    for f in swtpm.log swtpm.out qemu.out; do
        [ -s "$RUN_DIR/$f" ] && { echo "--- $f (tail) ---" >&2; tail -n 15 "$RUN_DIR/$f" >&2; }
    done
    return 0
}

# --- preflight: everything that can refuse, before anything is started ---
preflight_kvm() {
    [ -e "$KVM_DEV" ] || die "KVM is required and $KVM_DEV does not exist; there is no software emulation fallback"
    (exec 3<> "$KVM_DEV") 2> /dev/null || die "KVM is required and $KVM_DEV cannot be opened read-write by this user; there is no software emulation fallback"
    command -v "$QEMU" > /dev/null || die "$QEMU is not installed"
    "$QEMU" -accel help 2> /dev/null | grep -qw kvm || die "KVM is required and $QEMU does not offer the kvm accelerator; there is no software emulation fallback"
}
preflight_mode() {
    case $1 in
    full | lacking) ;;
    *) die "mode '$1' is not allowed: the modes are 'full' and 'lacking'" ;;
    esac
}
preflight_tools() {
    local t
    for t in qemu-img cloud-localds python3; do command -v "$t" > /dev/null || die "$t is not installed"; done
    [ -f "$OVMF_CODE" ] || die "OVMF code $OVMF_CODE not found (package ovmf)"
    [ -f "$OVMF_VARS" ] || die "OVMF vars $OVMF_VARS not found (package ovmf)"
    vm_swtpm_resolve
    [ -n "$VM_SWTPM" ] || die "swtpm is not installed"
    if [ "$1" = lacking ]; then
        [ -s "$PROFILE" ] || die "the lacking mode needs its swtpm profile $PROFILE, which is missing or empty"
        vm_swtpm_profile_support || die "the lacking mode needs an swtpm that takes a profile: $VM_SWTPM_WHY (harness/Containerfile adds 0.10.2 under /opt/swtpm)"
    fi
}

start_swtpm() { # $1 = 1 to pass the profile (first start of a lacking run only: a restart finds it in the state)
    local a=(socket --tpm2 --tpmstate "dir=$RUN_DIR/tpm" --ctrl "type=unixio,path=$RUN_DIR/tpm.sock"
        --pid "file=$RUN_DIR/swtpm.pid" --log "file=$RUN_DIR/swtpm.log" --terminate --daemon)
    [ "$1" = 1 ] && a+=(--profile "file=$PROFILE")
    rm -f -- "$RUN_DIR/swtpm.pid" "$RUN_DIR/tpm.sock"
    vm_swtpm_run "${a[@]}" >> "$RUN_DIR/swtpm.out" 2>&1 || { logs; die "swtpm did not start"; }
    wait_until 10 test -S "$RUN_DIR/tpm.sock" || { logs; die "swtpm has no control socket"; }
    wait_until 10 test -s "$RUN_DIR/swtpm.pid" || { logs; die "swtpm wrote no pid file"; }
}
start_qemu() {
    local a=(-machine "q35,accel=kvm" -cpu host -smp 2 -m 2048 -display none
        -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE"
        -drive "if=pflash,format=raw,file=$RUN_DIR/vars.fd"
        -drive "file=$RUN_DIR/disk.qcow2,if=virtio,format=qcow2"
        -drive "file=$RUN_DIR/seed.img,if=virtio,format=raw,readonly=on"
        -netdev "user,id=n0" -device "virtio-net-pci,netdev=n0"
        -chardev "socket,id=chrtpm,path=$RUN_DIR/tpm.sock" -tpmdev "emulator,id=tpm0,chardev=chrtpm" -device "tpm-crb,tpmdev=tpm0"
        -serial "unix:$RUN_DIR/serial.sock,server,nowait" -monitor none -daemonize -pidfile "$RUN_DIR/qemu.pid")
    rm -f -- "$RUN_DIR/qemu.pid" "$RUN_DIR/serial.sock"
    "$QEMU" "${a[@]}" >> "$RUN_DIR/qemu.out" 2>&1 || { logs; die "$QEMU did not start"; }
    wait_until 10 test -s "$RUN_DIR/qemu.pid" || { logs; die "$QEMU wrote no pid file"; }
}
wait_boot() {
    chan "$RUN_DIR/serial.sock" wait --timeout "$BOOT_TIMEOUT" --pid-file "$RUN_DIR/qemu.pid" || { logs; die "the guest did not come up within ${BOOT_TIMEOUT}s"; }
}

cmd_start() {
    local mode=${1-} base need image out
    preflight_kvm
    [ $# -le 1 ] || die "start takes one argument, the mode"
    [ -n "$mode" ] || die "no mode given: the modes are 'full' and 'lacking'"
    preflight_mode "$mode"
    [ -z "${VM_TPM_STATE+x}" ] || die "VM_TPM_STATE is set: the swtpm state is always a fresh directory of the run, never one the caller supplies"
    preflight_tools "$mode"
    base=${TMPDIR:-/tmp}
    base=${base%/}
    [ -d "$base" ] || die "TMPDIR $base is not a directory"
    need=$((${#base} + 1 + 18 + 1 + 11)) # <base>/custodio-vm.XXXXXX/serial.sock
    [ "$need" -le 107 ] || die "the path length of TMPDIR ($base) is too long for a unix socket (${need} > 107 bytes): use a shorter TMPDIR"
    out=$("$IMAGE_SH") || die "the image is not available: $IMAGE_SH failed"
    image=$(printf '%s\n' "$out" | sed -n 's/^path=//p')
    [ -f "$image" ] || die "$IMAGE_SH printed no image path"

    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    RUN_DIR=$(mktemp -d "$base/custodio-vm.XXXXXX")
    mkdir "$RUN_DIR/tpm"
    cp -- "$OVMF_VARS" "$RUN_DIR/vars.fd"
    qemu-img create -q -f qcow2 -b "$image" -F qcow2 "$RUN_DIR/disk.qcow2" 10G
    printf '#cloud-config\nchpasswd: {expire: false, users: [{name: %s, password: %s, type: text}]}\nssh_pwauth: false\n' \
        "$GUEST_USER" "$GUEST_PASSWORD" > "$RUN_DIR/user-data"
    printf 'instance-id: custodio-vm-%s\nlocal-hostname: custodio-vm\n' "${RUN_DIR##*.}" > "$RUN_DIR/meta-data"
    cloud-localds "$RUN_DIR/seed.img" "$RUN_DIR/user-data" "$RUN_DIR/meta-data"
    printf '%s\n' "$mode" > "$RUN_DIR/mode"
    # swtpm only now, right before QEMU: an swtpm without a QEMU stays idle (docs/findings/F151.md).
    start_swtpm "$([ "$mode" = lacking ] && echo 1 || echo 0)"
    start_qemu
    wait_boot
    : > "$RUN_DIR/vm.run"
    trap - EXIT INT TERM
    printf 'VM_DIR=%s\n' "$RUN_DIR"
}

# A directory this script made and has not stopped: the marker file and the name guard the rm -rf.
need_dir() {
    [ $# -ge 1 ] || die "the VM directory is missing"
    RUN_DIR=$1
    case $RUN_DIR in */custodio-vm.??????) ;; *) RUN_DIR= && die "'$1' is not a VM directory of this script" ;; esac
    [ -f "$RUN_DIR/vm.run" ] || { RUN_DIR=; die "'$1' is not a running VM directory (no vm.run)"; }
}

cmd_run() {
    local t=120
    need_dir "$@"; shift
    if [ "${1-}" = -t ]; then t=${2:?-t needs seconds}; shift 2; fi
    [ $# -eq 1 ] || die "run takes one command string"
    chan "$RUN_DIR/serial.sock" run --timeout "$t" --pid-file "$RUN_DIR/qemu.pid" "$1"
}
cmd_put() { need_dir "$@"; [ $# -eq 3 ] || die "put DIR LOCAL REMOTE"; chan "$RUN_DIR/serial.sock" put --pid-file "$RUN_DIR/qemu.pid" "$2" "$3"; }
cmd_get() { need_dir "$@"; [ $# -eq 3 ] || die "get DIR REMOTE LOCAL"; chan "$RUN_DIR/serial.sock" get --pid-file "$RUN_DIR/qemu.pid" "$2" "$3"; }
cmd_wait() { need_dir "$@"; wait_boot; }

power_off() { # asks the guest, then makes sure QEMU and swtpm are gone
    chan "$RUN_DIR/serial.sock" poweroff --timeout 30 --pid-file "$RUN_DIR/qemu.pid" 2> /dev/null || true
    wait_until 60 gone "$RUN_DIR/qemu.pid" || true
    stop_pid "$RUN_DIR/qemu.pid"
    wait_until 10 gone "$RUN_DIR/swtpm.pid" || true
    stop_pid "$RUN_DIR/swtpm.pid"
}
cmd_cycle() {
    need_dir "$@"
    trap 'exit 130' INT
    trap 'exit 143' TERM
    vm_swtpm_resolve
    power_off
    start_swtpm 0
    start_qemu
    wait_boot
}
cmd_stop() {
    need_dir "$@"
    power_off
    cleanup
}

[ $# -ge 1 ] || die "usage: vm.sh start MODE | wait DIR | run DIR [-t S] CMD | put DIR LOCAL REMOTE | get DIR REMOTE LOCAL | cycle DIR | stop DIR"
op=$1
shift
case $op in
start) cmd_start "$@" ;;
wait) cmd_wait "$@" ;;
run) cmd_run "$@" ;;
put) cmd_put "$@" ;;
get) cmd_get "$@" ;;
cycle) cmd_cycle "$@" ;;
stop) cmd_stop "$@" ;;
*) die "unknown command '$op'" ;;
esac
