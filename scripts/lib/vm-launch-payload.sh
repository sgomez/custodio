#!/usr/bin/env bash
# The payload drive of the launcher (F159 amendment, F160): scenarios and negative controls of scripts/test-vm-launch.sh (sourced by it, which
# defines the helpers used here). VM_PAYLOAD=FILE on `start` adds a read-only raw virtio drive with serial custodio-payload, the same after a cycle.
# shellcheck disable=SC2329,SC2086,SC2015,SC2016 # functions run through run(); $w is a fixed word; control texts are launcher source
# shellcheck disable=SC2034 # CENV is read by control_boot in the sourcing script
# shellcheck disable=SC2154 # tmp, VMDIR and the helpers come from the sourcing script

pay_arg() { printf 'file=%s,if=virtio,format=raw,readonly=on,serial=custodio-payload' "$1"; }
pay_count() { args_of "$1" qemu "$2" | grep -c 'serial=custodio-payload' || true; } # WORLD N: payload drives in the Nth QEMU's arguments
# ck_payload WORLD N FILE: exactly one payload drive, the exact argument, after a "-drive"
ck_payload() {
    local want
    want=$(pay_arg "$3")
    [ "$(pay_count "$1" "$2")" = 1 ] || { echo "payload drives in qemu $2: $(pay_count "$1" "$2")"; return 1; }
    args_of "$1" qemu "$2" | grep -x -B1 -- "$want" | head -n 1 | grep -qx -- -drive || { echo "no '-drive $want'"; return 1; }
}

head -c 8192 /dev/urandom > "$tmp/payload.tar"

scenario_payload() {
    local w=payload dir r p=$tmp/payload.tar
    world $w
    (cd "$tmp" && VM_PAYLOAD=payload.tar vx $w -- start full) > "$tmp/$w/out" 2> "$tmp/$w/err" || { bad "payload: start failed: $(cat "$tmp/$w/err")"; return; }
    dir=$(dir_of "$tmp/$w/out")
    r=$(ck_payload $w 1 "$p") || bad "payload: ck: $r (a relative VM_PAYLOAD becomes an absolute path)"
    vx $w -- cycle "$dir" || bad "payload: cycle failed"
    r=$(ck_payload $w 2 "$p") || bad "payload: after the cycle: $r"
    vx $w -- stop "$dir" || bad "payload: stop failed"
    cmp -s "$p" "$tmp/payload.pristine" || bad "payload: the file changed"
    tmp_empty $w || bad "payload: files left after stop"
    # without VM_PAYLOAD no such drive; with an empty one neither
    local w2=payload-none
    world $w2
    VM_PAYLOAD='' vx $w2 -- start full > "$tmp/$w2/out" 2> "$tmp/$w2/err" || { bad "payload: start without payload failed"; return; }
    [ "$(pay_count $w2 1)" = 0 ] || bad "payload: a drive without VM_PAYLOAD"
    vx $w2 -- stop "$(dir_of "$tmp/$w2/out")" || bad "payload: stop 2 failed"
}
cp "$tmp/payload.tar" "$tmp/payload.pristine"

scenario_payload_missing() { # a missing file, a directory, a path QEMU cannot take: refused, nothing started
    local w=payload-missing n
    for n in missing dir comma; do
        world $w-$n
        case $n in
        missing) p=$tmp/nope.tar ;;
        dir) p=$tmp ;;
        comma) p=$tmp/a,b.tar; cp "$tmp/payload.tar" "$p" ;;
        esac
        VM_PAYLOAD=$p vx $w-$n -- start full > "$tmp/$w-$n/out" 2> "$tmp/$w-$n/err" && { bad "payload $n: start succeeded"; continue; }
        grep -q VM_PAYLOAD "$tmp/$w-$n/err" || bad "payload $n: the message does not name VM_PAYLOAD: $(cat "$tmp/$w-$n/err")"
        nothing_started $w-$n || bad "payload $n: something was started or left"
    done
}

# --- controls ---
control_payload_rw() { # the drive is writable
    mut payload_rw vm.sh 'format=raw,readonly=on,serial=custodio-payload' 'format=raw,serial=custodio-payload' || return 0
    CENV=(VM_PAYLOAD="$tmp/payload.tar")
    control_boot payload_rw || { bad "control payload_rw: the copy did not start"; return; }
    expect_fail "writable payload" ck_payload "$CW" 1 "$tmp/payload.tar"
    control_end payload_rw
}
control_payload_cycle() { # a cycle forgets the drive
    mut payload_cycle vm.sh 'if [ -f "$RUN_DIR/payload.path" ]; then' 'if false; then' || return 0
    CENV=(VM_PAYLOAD="$tmp/payload.tar")
    control_boot payload_cycle || { bad "control payload_cycle: the copy did not start"; return; }
    LAUNCHER=$(ctl payload_cycle) vx "$CW" -- cycle "$CD" > /dev/null 2>&1 || true
    expect_fail "no drive after a cycle" ck_payload "$CW" 2 "$tmp/payload.tar"
    control_end payload_cycle
}
control_payload_check() { # no check of the file: the missing payload starts the stubs
    mut payload_check vm.sh '[ -f "$VM_PAYLOAD" ] && [ -r "$VM_PAYLOAD" ] || die' ': || die' || return 0
    local w=c-payload_check
    world $w
    VM_PAYLOAD=$tmp/nope.tar LAUNCHER=$(ctl payload_check) vx $w -- start full > "$tmp/$w/out" 2> "$tmp/$w/err" || true
    CW=$w CD=$(dir_of "$tmp/$w/out")
    expect_fail "missing payload accepted" nothing_started $w
    control_end payload_check
}
