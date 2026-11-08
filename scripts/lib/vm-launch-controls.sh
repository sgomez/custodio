#!/usr/bin/env bash
# The checks on one run and the negative controls of scripts/test-vm-launch.sh (sourced by it, which defines the helpers used here). Each control runs the same check on a copy of
# the launcher with the one behaviour removed, and the check must fail there.
# shellcheck disable=SC2329,SC2086,SC2015,SC2016 # functions run through run(); $w is a fixed word; control texts are launcher source
# shellcheck disable=SC2154 # tmp, VMDIR, FAKES and the helpers come from the sourcing script

# ---------------------------------------------------------------------------------------------------------------------------------
# negative controls: the same check on a copy of the launcher with the one behaviour removed must fail
# ---------------------------------------------------------------------------------------------------------------------------------
CENV=()
control_boot() { # NAME: a started run of the control; sets CW (world) and CD (dir); returns non-zero if it did not start
    CW=c-$1; CD=
    world "$CW"
    LAUNCHER=$(ctl "$1") vx "$CW" "${CENV[@]}" -- start full > "$tmp/$CW/out" 2> "$tmp/$CW/err" || return 1
    CD=$(dir_of "$tmp/$CW/out")
}
control_end() { [ -n "$CD" ] && LAUNCHER=$(ctl "$1") vx "$CW" -- stop "$CD" > /dev/null 2>&1 || true; }
expect_fail() { # DESCRIPTION CMD...: CMD must fail
    local d=$1
    shift
    if "$@" > /dev/null 2>&1; then bad "control '$d': the check passed on the copy without the behaviour"; fi
}

control_start_checks() { # NAME CHECK DESC
    control_boot "$1" || { bad "control $1: the copy did not start: $(cat "$tmp/$CW/err")"; return; }
    expect_fail "$3" "$2" "$CW"
    control_end "$1"
}

control_overlay() { mut overlay vm.sh 'file=$RUN_DIR/disk.qcow2,if=virtio' 'file=$image,if=virtio' && control_start_checks overlay ck_overlay "disk is the image"; }
control_kvm() { mut kvm vm.sh 'accel=kvm' 'accel=tcg' && control_start_checks kvm ck_kvm "no kvm"; }
control_vars() { # the stub writes to the vars file it is given: with the template given directly, the template changes (a private one here)
    mut vars vm.sh 'file=$RUN_DIR/vars.fd' 'file=$OVMF_VARS' || return 0
    mkdir -p "$tmp/c-vars-tpl"; cp "$tmp/vars.fd" "$tmp/c-vars-tpl/vars.fd"; cp "$tmp/vars.fd" "$tmp/c-vars-tpl/pristine"
    CENV=(VM_OVMF_VARS="$tmp/c-vars-tpl/vars.fd")
    control_boot vars || { bad "control vars: the copy did not start"; return; }
    expect_fail "vars template used directly" ck_pflash "$CW" "$tmp/c-vars-tpl/vars.fd" "$tmp/c-vars-tpl/pristine"
    control_end vars
}
control_tpm() { mut tpm vm.sh 'tpm-crb,tpmdev' 'tpm-tis,tpmdev' && control_start_checks tpm ck_tpm "tpm-tis"; }
control_seed() {
    mut seed vm.sh 'chpasswd: {expire: false, users: [{name: %s, password: %s, type: text}]}\n' '' || return 0
    control_boot seed || { bad "control seed: the copy did not start"; return; }
    expect_fail "seed without the password" ck_seed "$CW" "$CD"
    control_end seed
}
control_statecycle() { # a new state directory at every swtpm start: the power cycle must not find the marker
    mut statecycle vm.sh '    vm_swtpm_run "${a[@]}"' '    a[3]="dir=$RUN_DIR/tpm$RANDOM"; mkdir -p "${a[3]#dir=}"; vm_swtpm_run "${a[@]}"' || return 0
    control_boot statecycle || { bad "control statecycle: the copy did not start"; return; }
    LAUNCHER=$(ctl statecycle) vx "$CW" -- cycle "$CD" > /dev/null 2>&1 || true
    if grep -qx marker "$tmp/$CW/log/swtpm.2.state-before" 2> /dev/null; then bad "control statecycle: the second swtpm still found the marker"; fi
    control_end statecycle
}
control_statereuse() { # one fixed state directory: the second run finds the first run's marker
    mut statereuse vm.sh '    vm_swtpm_run "${a[@]}"' '    a[3]="dir=${TMPDIR}/fixed-tpm"; mkdir -p "${TMPDIR}/fixed-tpm"; vm_swtpm_run "${a[@]}"' || return 0
    local w=c-statereuse d
    world $w
    for _ in 1 2; do
        LAUNCHER=$(ctl statereuse) vx $w -- start full > "$tmp/$w/out" 2> "$tmp/$w/err" || { bad "control statereuse: no start"; return; }
        d=$(dir_of "$tmp/$w/out")
        LAUNCHER=$(ctl statereuse) vx $w -- stop "$d" > /dev/null 2>&1 || true
    done
    [ -n "$(cat "$tmp/$w/log/swtpm.2.state-before")" ] || bad "control statereuse: the second run did not find the first run's state"
}
control_exitcode() {
    mut exitcode chan.py '            sys.stdout.buffer.flush()
            return rc' '            sys.stdout.buffer.flush()
            return 0' || return 0
    control_boot exitcode || { bad "control exitcode: the copy did not start"; return; }
    local e=0
    LAUNCHER=$(ctl exitcode) vx "$CW" -- run "$CD" 'exit 3' > /dev/null || e=$?
    [ "$e" = 0 ] || bad "control exitcode: the copy still returns the code ($e)"
    control_end exitcode
}
control_strip() {
    mut strip chan.py '        f.write(data)' '        f.write(data[:-1])' || return 0
    control_boot strip || { bad "control strip: the copy did not start"; return; }
    LAUNCHER=$(ctl strip) vx "$CW" -- put "$CD" "$tmp/all256.bin" "$tmp/$CW/r.bin" > /dev/null 2>&1 || true
    LAUNCHER=$(ctl strip) vx "$CW" -- get "$CD" "$tmp/$CW/r.bin" "$tmp/$CW/back.bin" > /dev/null 2>&1 || true
    if cmp -s "$tmp/all256.bin" "$tmp/$CW/back.bin"; then bad "control strip: the copy still copies byte for byte"; fi
    control_end strip
}
control_nokvmcheck() {
    mut nokvm vm.sh '    preflight_kvm
' '' || return 0
    if LAUNCHER=$(ctl nokvm) refuse_ok c-nokvm VM_KVM_DEV="$tmp/missing-kvm" -- start full; then bad "control nokvm: the copy still refuses without KVM"; fi
    LAUNCHER=$(ctl nokvm) vx c-nokvm VM_KVM_DEV="$tmp/missing-kvm" -- stop "$(dir_of "$tmp/c-nokvm/out")" > /dev/null 2>&1 || true
}
control_notrap() {
    mut notrap vm.sh '    trap cleanup EXIT
    trap '"'exit 130'"' INT
    trap '"'exit 143'"' TERM
' '' || return 0
    local w=c-notrap
    world $w
    LAUNCHER=$(ctl notrap) vx $w STUB_QEMU_NOLOGIN=1 VM_BOOT_TIMEOUT=2 -- start full > /dev/null 2>&1 || true
    if procs_gone $w && tmp_empty $w; then bad "control notrap: the copy without the trap still cleans up"; fi
}
control_notrap_sig() {
    mut notrap2 vm.sh '    trap cleanup EXIT
    trap '"'exit 130'"' INT
    trap '"'exit 143'"' TERM
' '' || return 0
    if LAUNCHER=$(ctl notrap2) sig_ok TERM; then bad "control notrap: the TERM case still passes on the copy"; fi
}


# --- checks on one run, each prints why it fails and returns non-zero ---
ck_kvm() { # WORLD: kvm acceleration with -cpu host, tcg nowhere
    local a; a=$(args_of "$1" qemu 1)
    printf '%s\n' "$a" | grep -qx 'q35,accel=kvm' || { echo "no accel=kvm"; return 1; }
    printf '%s\n' "$a" | grep -A1 -x -- '-cpu' | grep -qx host || { echo "no -cpu host"; return 1; }
    ! printf '%s\n' "$a" | grep -qi 'tcg' || { echo "tcg in the arguments"; return 1; }
}
ck_pflash() { # WORLD [TEMPLATE PRISTINE]: code readonly, vars a second pflash that is a copy of the template, template untouched
    local a vars tpl=${2:-$tmp/vars.fd} pristine=${3:-$tmp/vars.pristine}; a=$(args_of "$1" qemu 1)
    printf '%s\n' "$a" | grep -qx "if=pflash,format=raw,readonly=on,file=$tmp/code.fd" || { echo "OVMF code is not readonly pflash"; return 1; }
    vars=$(printf '%s\n' "$a" | sed -n 's/^if=pflash,format=raw,file=//p')
    [ -n "$vars" ] && [ "$vars" != "$tpl" ] || { echo "vars is not a separate copy: $vars"; return 1; }
    cmp -s "$tpl" "$tmp/$1/log/qemu.1.vars-before" || { echo "the vars copy differed from the template at start"; return 1; }
    cmp -s "$tpl" "$pristine" || { echo "the template was modified"; return 1; }
    echo "$vars" > "$tmp/$1/vars-path"
}
ck_tpm() { # WORLD
    local a s sock; a=$(args_of "$1" qemu 1); s=$(args_of "$1" swtpm 1)
    printf '%s\n' "$a" | grep -qx 'tpm-crb,tpmdev=tpm0' || { echo "no tpm-crb device"; return 1; }
    printf '%s\n' "$a" | grep -qx 'emulator,id=tpm0,chardev=chrtpm' || { echo "no emulator tpmdev"; return 1; }
    sock=$(printf '%s\n' "$a" | sed -n 's/^socket,id=chrtpm,path=//p')
    printf '%s\n' "$s" | grep -qx "type=unixio,path=$sock" || { echo "swtpm does not listen on the socket QEMU uses ($sock)"; return 1; }
    printf '%s\n' "$s" | grep -qx -- '--tpm2' || { echo "swtpm is not --tpm2"; return 1; }
}
ck_overlay() { # WORLD
    local a disk back; a=$(args_of "$1" qemu 1)
    disk=$(printf '%s\n' "$a" | sed -n 's/^file=\(.*\),if=virtio,format=qcow2$/\1/p')
    [ -n "$disk" ] || { echo "no virtio qcow2 disk"; return 1; }
    back=$(qemu-img info --output=json "$disk" | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("backing-filename",""))')
    [ "$back" = "$IMG" ] || { echo "the disk's backing file is '$back', not the image"; return 1; }
}
ck_seed() { # WORLD DIR
    local seed=$2/seed.img a vol ud md
    a=$(args_of "$1" qemu 1)
    vol=$(python3 -I -c 'import sys; f=open(sys.argv[1],"rb"); f.seek(32808); print(f.read(32).decode().strip())' "$seed")
    [ "$vol" = cidata ] || { echo "volume id '$vol'"; return 1; }
    ud=$(bsdtar -xOf "$seed" user-data); md=$(bsdtar -xOf "$seed" meta-data)
    [ "$(printf '%s\n' "$ud" | head -n1)" = '#cloud-config' ] || { echo "user-data does not start with #cloud-config"; return 1; }
    printf '%s\n' "$ud" | grep -q 'name: ubuntu' || { echo "no account"; return 1; }
    printf '%s\n' "$ud" | grep -q 'password: custodio-throwaway-test' || { echo "no password"; return 1; }
    printf '%s\n' "$ud" | grep -qx 'ssh_pwauth: false' || { echo "ssh password login not off"; return 1; }
    printf '%s\n' "$md" | grep -q '^instance-id: .' || { echo "no instance-id"; return 1; }
    printf '%s\n' "$md" | grep -q '^local-hostname: .' || { echo "no hostname"; return 1; }
    ! { printf '%s\n%s\n' "$ud" "$md" | grep -qE 'CUSTODIOD_|\[Service\]|\.service'; } || { echo "the seed holds product configuration"; return 1; }
    ! printf '%s\n' "$a" | grep -q 'hostfwd' || { echo "port forward"; return 1; }
    [ "$(printf '%s\n' "$a" | grep -c '^-netdev$')" = 1 ] && printf '%s\n' "$a" | grep -qx 'user,id=n0' || { echo "network is not only user networking"; return 1; }
}
ck_backing_untouched() { [ "$(sha256sum < "$IMG")" = "$IMG_SUM" ] || { echo "the image changed"; return 1; }; }

