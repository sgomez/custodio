#!/usr/bin/env bash
# Self-test of the TPM modes of e2e/vm/vm.sh (F159), without a VM: stub qemu-system-x86_64 and swtpm (scripts/lib/vm-fakes) record their command
# lines. Checks that `full` and `lacking` are the only modes and anything else is refused before a VM starts; that `full` adds nothing; that
# `lacking` differs from `full` by the swtpm profile and nothing else (same swtpm executable, same QEMU arguments, same seed), with the profile of
# docs/findings/F152.md (default commands minus TPM2_RSA_Decrypt, nothing else removed); and that `lacking` cannot start without its route in place.
# Each check has a negative control: a copy of the launcher with the one behaviour removed (shown to differ), on which the check must fail.
# shellcheck disable=SC2329,SC2086,SC2015,SC2016 # SC2329: the scenarios run through run(); SC2086: $w is a fixed scenario word; SC2015: used as a check; SC2016: control texts are launcher source
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VMDIR=$ROOT/e2e/vm
FAKES=$ROOT/scripts/lib/vm-fakes
for tool in python3 qemu-img cloud-localds bsdtar; do
    command -v "$tool" > /dev/null 2>&1 || { echo "test-vm-modes: $tool is not installed" >&2; exit 127; }
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
bad() { echo "test-vm-modes: $*" >&2; echo x >> "$tmp/res/failed"; }

IMG=$tmp/image.qcow2
qemu-img create -q -f qcow2 "$IMG" 1M
printf '#!/bin/sh\necho path=%s\n' "$IMG" > "$tmp/image.sh"
chmod +x "$tmp/image.sh"
: > "$tmp/kvm"
printf 'OVMF-CODE' > "$tmp/code.fd"
printf 'OVMF-VARS-TEMPLATE' > "$tmp/vars.fd"
# The swtpm the launcher is told to use is a path of its own: the stub records the path it was started from.
mkdir "$tmp/swtpm-a" "$tmp/swtpm-b"
ln -s "$FAKES/swtpm" "$tmp/swtpm-a/swtpm"
ln -s "$FAKES/swtpm" "$tmp/swtpm-b/swtpm"
SW=$tmp/swtpm-a/swtpm

world() { mkdir -p "$tmp/$1/log" "$tmp/$1/tmp"; }
# vx WORLD [VAR=value ...] -- ARGS: runs $LAUNCHER (default the real one); later VAR=value wins over the defaults.
vx() {
    local w=$1 envs=()
    shift
    while [ "$1" != -- ]; do envs+=("$1"); shift; done
    shift
    env STUB_LOG="$tmp/$w/log" TMPDIR="$tmp/$w/tmp" VM_QEMU="$FAKES/qemu-system-x86_64" VM_SWTPM="$SW" VM_KVM_DEV="$tmp/kvm" \
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
nothing_started() { [ -z "$(ls -A "$tmp/$1/log")" ] && [ -z "$(ls -A "$tmp/$1/tmp")" ]; }
# norm WORLD FILE: the recorded arguments (without argv[0]) with the run's paths replaced by fixed words.
norm() { sed '1d' "$tmp/$1/log/$2" | sed -E "s#$tmp/$1/tmp/custodio-vm\.[A-Za-z0-9]{6}#RUN#g; s#$tmp/code.fd#OVMF_CODE#g; s#$VMDIR/lacking-rsa.json#PROFILE#g; s#$tmp/ctl-[a-z0-9]+/lacking-rsa.json#PROFILE#g"; }

EXPECT_SWTPM='socket
--tpm2
--tpmstate
dir=RUN/tpm
--ctrl
type=unixio,path=RUN/tpm.sock
--pid
file=RUN/swtpm.pid
--log
file=RUN/swtpm.log
--terminate
--daemon'
EXPECT_QEMU='-machine
q35,accel=kvm
-cpu
host
-smp
2
-m
2048
-display
none
-drive
if=pflash,format=raw,readonly=on,file=OVMF_CODE
-drive
if=pflash,format=raw,file=RUN/vars.fd
-drive
file=RUN/disk.qcow2,if=virtio,format=qcow2
-drive
file=RUN/seed.img,if=virtio,format=raw,readonly=on
-netdev
user,id=n0
-device
virtio-net-pci,netdev=n0
-chardev
socket,id=chrtpm,path=RUN/tpm.sock
-tpmdev
emulator,id=tpm0,chardev=chrtpm
-device
tpm-crb,tpmdev=tpm0
-serial
unix:RUN/serial.sock,server,nowait
-monitor
none
-daemonize
-pidfile
RUN/qemu.pid'
EXPECT_SWTPM_LACKING="$EXPECT_SWTPM
--profile
file=PROFILE"

# --- checks, each prints why it fails and returns non-zero ---
ck_full_exact() { # WORLD: the swtpm and QEMU arguments are the exact lists, and no profile exists
    [ "$(norm "$1" swtpm.1.args)" = "$EXPECT_SWTPM" ] || { echo "swtpm arguments differ: $(norm "$1" swtpm.1.args | tr '\n' ' ')"; return 1; }
    [ "$(norm "$1" qemu.1.args)" = "$EXPECT_QEMU" ] || { echo "qemu arguments differ"; return 1; }
    ! ls "$tmp/$1/log"/swtpm.*.profile > /dev/null 2>&1 || { echo "a profile file was read"; return 1; }
    ! grep -qx -- '--profile' "$tmp/$1/log/swtpm.1.args" || { echo "--profile given"; return 1; }
}
ck_profile() { # WORLD: file= profile, F152's commands minus 0x159 (RSA_Decrypt) and 0x15d (Sign) exactly, rsa and P-256 kept
    local w=$1 a p
    a=$(sed '1d' "$tmp/$w/log/swtpm.1.args")
    printf '%s\n' "$a" | grep -A1 -x -- '--profile' | tail -n1 | grep -q '^file=' || { echo "the profile is not passed as file="; return 1; }
    p=$tmp/$w/log/swtpm.1.profile
    [ -s "$p" ] || { echo "no profile was read"; return 1; }
    python3 -I - "$p" 2>&1 << 'PY'
import json, re, sys

def cmds(s):
    out = set()
    for part in s.split(","):
        a, _, b = part.partition("-")
        out |= set(range(int(a, 16), int(b or a, 16) + 1))
    return out

DEFAULT = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197,0x199-0x19c"
text = open(sys.argv[1]).read()
p = json.loads(text)
got, want = cmds(p["Commands"]), cmds(DEFAULT) - {0x159, 0x15D}
if got != want:
    sys.exit("Commands differ from the default minus 0x159 and 0x15d: missing %s extra %s" % (sorted(map(hex, want - got)), sorted(map(hex, got - want))))
if 0x159 in got or 0x15D in got:
    sys.exit("0x159 (RSA_Decrypt) and 0x15d (Sign) must both be absent")
algs = set(p["Algorithms"].split(","))
if "rsa" not in algs or "ecc-nist-p256" not in algs:
    sys.exit("Algorithms lost rsa or ecc-nist-p256")
for bad in ("ecc-min-size=384", "rsa-min-size=3072"):
    if bad in text:
        sys.exit("profile holds " + bad)
if p.get("Name") != "custom":
    sys.exit("Name is not custom")
PY
}
ck_same_swtpm() { # WORLD_FULL WORLD_LACKING: the same executable path in both
    [ "$(head -n1 "$tmp/$1/log/swtpm.1.args")" = "$SW" ] && [ "$(head -n1 "$tmp/$2/log/swtpm.1.args")" = "$SW" ] \
        || { echo "swtpm started from $(head -n1 "$tmp/$1/log/swtpm.1.args") and $(head -n1 "$tmp/$2/log/swtpm.1.args"), not both $SW"; return 1; }
}
ck_lacking_diff() { # WORLD_FULL WORLD_LACKING: arguments differ only by the profile; QEMU and seed identical
    [ "$(norm "$2" swtpm.1.args)" = "$EXPECT_SWTPM_LACKING" ] || { echo "lacking swtpm arguments: $(norm "$2" swtpm.1.args | tr '\n' ' ')"; return 1; }
    [ "$(norm "$1" qemu.1.args)" = "$(norm "$2" qemu.1.args)" ] || { echo "QEMU arguments differ between the modes"; return 1; }
    [ "$(cat "$tmp/$1/user-data")" = "$(cat "$tmp/$2/user-data")" ] || { echo "the seed user-data differs between the modes"; return 1; }
}

# boot WORLD MODE [VAR=value ...]: starts, keeps the user-data of the seed, stops (the profile and arguments stay in the stub log). Uses $LAUNCHER.
boot() {
    local w=$1 m=$2 d
    shift 2
    world $w
    vx $w "$@" -- start "$m" > "$tmp/$w/out" 2> "$tmp/$w/err" || return 1
    d=$(dir_of "$tmp/$w/out")
    bsdtar -xOf "$d/seed.img" user-data > "$tmp/$w/user-data"
    vx $w "$@" -- stop "$d" > /dev/null 2>&1 || true
}

scenario_modes() { # full and lacking start; the pair is compared
    boot m-full full || { bad "modes: full did not start: $(cat "$tmp/m-full/err")"; return; }
    boot m-lack lacking || { bad "modes: lacking did not start: $(cat "$tmp/m-lack/err")"; return; }
    local r
    r=$(ck_full_exact m-full) || bad "full adds something: $r"
    r=$(ck_profile m-lack) || bad "lacking: $r"
    r=$(ck_same_swtpm m-full m-lack) || bad "modes: $r"
    r=$(ck_lacking_diff m-full m-lack) || bad "modes: $r"
}

scenario_cycle() { # a power cycle of lacking restarts swtpm without the profile (it is in the state)
    local w=m-cycle d
    world $w
    vx $w -- start lacking > "$tmp/$w/out" 2> "$tmp/$w/err" || { bad "cycle: start failed: $(cat "$tmp/$w/err")"; return; }
    d=$(dir_of "$tmp/$w/out")
    vx $w -- cycle "$d" || bad "cycle: failed"
    if grep -qx -- '--profile' "$tmp/$w/log/swtpm.2.args"; then bad "cycle: the restart passes --profile again"; fi
    [ "$(head -n1 "$tmp/$w/log/swtpm.2.args")" = "$SW" ] || bad "cycle: another swtpm after the cycle"
    vx $w -- stop "$d" || bad "cycle: stop failed"
}

scenario_refused() { # label, mode words...: refused before either stub starts, nothing left, the allowed values named
    local label=$1 w rc=0
    shift
    w=ref-$label
    world $w
    vx $w -- start "$@" > "$tmp/$w/out" 2> "$tmp/$w/err" || rc=$?
    [ "$rc" != 0 ] || bad "refuse $label: it started"
    grep -q 'full' "$tmp/$w/err" && grep -q 'lacking' "$tmp/$w/err" || bad "refuse $label: the message does not name the allowed values: $(cat "$tmp/$w/err")"
    nothing_started $w || bad "refuse $label: something started or was left"
}

scenario_route() { # lacking without its route: refused before any stub starts
    local label=$1 pat=$2 w rc=0
    shift 2
    w=route-$label
    world $w
    vx $w "$@" -- start lacking > "$tmp/$w/out" 2> "$tmp/$w/err" || rc=$?
    [ "$rc" != 0 ] || bad "route $label: it started"
    grep -qiE -e "$pat" "$tmp/$w/err" || bad "route $label: the message does not match '$pat': $(cat "$tmp/$w/err")"
    nothing_started $w || bad "route $label: something started or was left"
}
scenario_route_file() { # a copy of the launcher with the profile removed or emptied
    local label=$1 w rc=0 c=$tmp/ctl-route-$1
    w=route-$label
    mkdir -p "$c"; cp -r "$VMDIR/." "$c/"
    if [ "$label" = nofile ]; then rm "$c/lacking-rsa.json"; else : > "$c/lacking-rsa.json"; fi
    world $w
    LAUNCHER=$c/vm.sh vx $w -- start lacking > "$tmp/$w/out" 2> "$tmp/$w/err" || rc=$?
    [ "$rc" != 0 ] || bad "route $label: it started"
    grep -qi 'profile' "$tmp/$w/err" || bad "route $label: the message does not name the profile: $(cat "$tmp/$w/err")"
    nothing_started $w || bad "route $label: something started or was left"
}
scenario_full_old() { # full still starts on an swtpm 0.7.1
    boot m-old full STUB_SWTPM_VERSION=0.7.1 STUB_SWTPM_NO_PROFILE=1 || bad "full on swtpm 0.7.1 did not start: $(cat "$tmp/m-old/err")"
}

# --- controls ---
expect_fail() { local d=$1; shift; if "$@" > /dev/null 2>&1; then bad "control '$d': the check passed on the copy without the behaviour"; fi; }

control_missing_mode() { # a missing mode treated as full
    mut missingmode vm.sh "[ -n \"\$mode\" ] || die \"no mode given: the modes are 'full' and 'lacking'\"" '[ -n "$mode" ] || mode=full' || return 0
    local w=c-missing rc=0
    world $w
    LAUNCHER=$(ctl missingmode) vx $w -- start > "$tmp/$w/out" 2> "$tmp/$w/err" || rc=$?
    # the "refused" check (non-zero, nothing started) must fail on the copy: it starts a VM
    if [ "$rc" != 0 ] || nothing_started $w; then bad "control missing mode: the copy still refuses a missing mode"; return 0; fi
    LAUNCHER=$(ctl missingmode) vx $w -- stop "$(dir_of "$tmp/$w/out")" > /dev/null 2>&1 || true
}
control_always_profile() {
    mut alwaysprofile vm.sh '    [ "$1" = 1 ] && a+=(--profile "file=$PROFILE")' '    a+=(--profile "file=$PROFILE")' || return 0
    LAUNCHER=$(ctl alwaysprofile) boot c-always full || { bad "control always-profile: the copy did not start"; return; }
    expect_fail "always the profile" ck_full_exact c-always
}
control_keep_sign() {
    mut keepsign lacking-rsa.json '0x15b-0x15c,0x15e' '0x15b-0x15e' || return 0
    LAUNCHER=$(ctl keepsign) boot c-sign lacking || { bad "control keep-sign: the copy did not start"; return; }
    expect_fail "profile keeps 0x15d" ck_profile c-sign
}
control_drop_other() {
    mut dropother lacking-rsa.json '0x160-0x165' '0x161-0x165' || return 0
    LAUNCHER=$(ctl dropother) boot c-other-cmd lacking || { bad "control drop-other: the copy did not start"; return; }
    expect_fail "profile drops another command" ck_profile c-other-cmd
}
control_ecc384() {
    mut ecc384 lacking-rsa.json 'ecc-min-size=192' 'ecc-min-size=384' || return 0
    LAUNCHER=$(ctl ecc384) boot c-ecc384 lacking || { bad "control ecc384: the copy did not start"; return; }
    expect_fail "profile has ecc-min-size=384" ck_profile c-ecc384
}
control_rsa3072() {
    mut rsa3072 lacking-rsa.json 'rsa-min-size=1024' 'rsa-min-size=3072' || return 0
    LAUNCHER=$(ctl rsa3072) boot c-rsa3072 lacking || { bad "control rsa3072: the copy did not start"; return; }
    expect_fail "profile has rsa-min-size=3072" ck_profile c-rsa3072
}
control_drop_alg() {
    mut dropalg lacking-rsa.json 'ecc-nist-p256,' '' || return 0
    LAUNCHER=$(ctl dropalg) boot c-dropalg lacking || { bad "control drop-alg: the copy did not start"; return; }
    expect_fail "profile drops ecc-nist-p256" ck_profile c-dropalg
}
control_keep_decrypt() {
    mut keepdecrypt lacking-rsa.json '0x142-0x158' '0x142-0x159' || return 0
    LAUNCHER=$(ctl keepdecrypt) boot c-keep lacking || { bad "control keep-decrypt: the copy did not start"; return; }
    expect_fail "profile keeps 0x159" ck_profile c-keep
}
control_other_swtpm() {
    mut otherswtpm vm.sh '    vm_swtpm_run "${a[@]}"' '    [ "$1" = 1 ] && VM_SWTPM=${OTHER_SWTPM:?}; vm_swtpm_run "${a[@]}"' || return 0
    LAUNCHER=$(ctl otherswtpm) boot c-other-f full OTHER_SWTPM="$tmp/swtpm-b/swtpm" || { bad "control other-swtpm: full did not start"; return; }
    LAUNCHER=$(ctl otherswtpm) boot c-other-l lacking OTHER_SWTPM="$tmp/swtpm-b/swtpm" || { bad "control other-swtpm: lacking did not start"; return; }
    expect_fail "another swtpm in lacking only" ck_same_swtpm c-other-f c-other-l
}
control_no_version_check() {
    mut noversion swtpm-path.sh 'if [ "${BASH_REMATCH[1]}" -lt 1 ] && [ "${BASH_REMATCH[2]}" -lt 10 ]; then' 'if false; then' || return 0
    local w=c-noversion rc=0
    world $w
    LAUNCHER=$(ctl noversion) vx $w STUB_SWTPM_VERSION=0.7.1 -- start lacking > "$tmp/$w/out" 2> "$tmp/$w/err" || rc=$?
    [ "$rc" = 0 ] || bad "control no-version-check: the copy still refuses lacking on 0.7.1"
    [ "$rc" != 0 ] || LAUNCHER=$(ctl noversion) vx $w -- stop "$(dir_of "$tmp/$w/out")" > /dev/null 2>&1 || true
}

pids=()
run() { [ -z "${ONLY:-}" ] || [[ "$*" == *"$ONLY"* ]] || return 0; "$@" & pids+=($!); }
run scenario_modes
run scenario_cycle
run scenario_full_old
run scenario_refused partial partial
run scenario_refused upper FULL
run scenario_refused empty ''
run scenario_refused two 'full lacking'
run scenario_refused flag --mode
run scenario_refused none
run scenario_route old-version 'swtpm.*0\.7\.1|0\.7\.1' STUB_SWTPM_VERSION=0.7.1
run scenario_route no-profile-flag '--profile|profile' STUB_SWTPM_NO_PROFILE=1
run scenario_route_file nofile
run scenario_route_file empty
for c in missing_mode always_profile keep_sign drop_other ecc384 rsa3072 drop_alg keep_decrypt other_swtpm no_version_check; do run "control_$c"; done
for p in "${pids[@]}"; do wait "$p" || true; done

if [ -f "$tmp/res/failed" ]; then exit 1; fi
exit 0
