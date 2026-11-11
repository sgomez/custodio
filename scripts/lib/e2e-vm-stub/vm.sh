#!/usr/bin/env bash
# A stub of e2e/vm/vm.sh for scripts/test-e2e-vm-host.sh: logs every call to $STUB_LOG and answers from canned outputs. No QEMU, no apt, no network.
# Knobs (environment): STUB_FAIL_START, STUB_FAIL_INSTALL, STUB_HAS2 (the has-tpm2 output, default yes), STUB_HAS2_RC, STUB_CASES (a file with the E2E-CASE lines the guest prints),
# STUB_GUEST_RC, STUB_HOLD (a directory: the guest run waits there until the file `release` appears, after touching `in-guest`), STUB_VMDIR (where the running marker lives).
set -u
op=$1; shift
echo "vm $op $*" >> "$STUB_LOG"
case $op in
start)
    [ -z "${STUB_FAIL_START:-}" ] || { echo "stub: start failed" >&2; exit 1; }
    # the real launcher refuses a payload that is not a readable file; the stub keeps a copy, as the driver deletes its own
    if [ -n "${VM_PAYLOAD:-}" ]; then cp -- "$VM_PAYLOAD" "$STUB_LOG.payload" || { echo "stub: no payload" >&2; exit 1; }; fi
    mkdir -p "$STUB_VMDIR/custodio-vm.AAAAAA"; echo running > "$STUB_VMDIR/custodio-vm.AAAAAA/vm.run"
    echo "VM_DIR=$STUB_VMDIR/custodio-vm.AAAAAA" ;;
cycle) [ -z "${STUB_FAIL_CYCLE:-}" ] || { echo "stub: cycle failed" >&2; exit 1; } ;;
stop) echo "stop" >> "$STUB_LOG.stops"; rm -rf "$1" ;;
put) [ -f "$2" ] || { echo "stub: no such file $2" >&2; exit 1; } ;;
run)
    shift # the directory
    [ "${1:-}" != -t ] || shift 2
    cmd=$1
    case $cmd in
    *"systemd-analyze has-tpm2"*) echo "${STUB_HAS2:-yes}"; exit "${STUB_HAS2_RC:-0}" ;;
    "uname -r") echo 6.14.0-stub; exit 0 ;;
    *"systemctl --version") echo "systemd 257 (257.9-stub)"; exit 0 ;;
    *"apt-get install"*) [ -z "${STUB_FAIL_INSTALL:-}" ] || { echo "E: stub apt failure"; exit 100; }; exit 0 ;;
    *guest.sh*)
        if [ -n "${STUB_HOLD:-}" ]; then
            touch "$STUB_HOLD/in-guest"
            for _ in $(seq 400); do [ -e "$STUB_HOLD/release" ] && break; sleep 0.05; done
        fi
        # F163: with E2E_PCR_HALF the pcr cases are reported by half (first: pcr-extended-signs; second: the other two), and a half that STUB_FAIL_HALF names fails
        half=$(sed -n 's/.*E2E_PCR_HALF=\([a-z]*\) .*/\1/p' <<< "$cmd")
        [ -z "$half" ] || echo "$half" >> "$STUB_LOG.halves"
        if [ -n "${STUB_FAIL_HALF:-}" ] && [ "$half" = "$STUB_FAIL_HALF" ]; then echo "stub: half $half failed"; exit 1; fi
        if [ -n "${STUB_CASES:-}" ]; then cat "$STUB_CASES"; else
            sel=$(sed -n "s/.*E2E_SELECT='\([^']*\)'.*/\1/p" <<< "$cmd")
            for id in $sel; do
                case $half:$id in
                first:pcr-restarted-signs | first:pcr-signs-every-key | second:pcr-extended-signs) continue ;;
                esac
                echo "E2E-CASE run $id"
            done
        fi
        printf 'E2E-PHASE install 3\nE2E-PHASE service 2\nE2E-PHASE import 4\nE2E-PHASE sign 5\nE2E-PHASE pcr 6\nE2E-PHASE upgrade 7\n'
        exit "${STUB_GUEST_RC:-0}" ;;
    esac
    exit 0 ;;
esac
