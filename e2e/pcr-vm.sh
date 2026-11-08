#!/usr/bin/env bash
# Root side of the pcr-* cases in a VM run (F163, acceptance 8). Started by pcr-run.sh when E2E_VM=1; E2E_TPM is swtpm (the guest's full mode: kind tpm) or lacking (kind
# encrypted-tpm). The TPM is the VM's own, reached through the kernel's resource manager ($PCR_TCTI, default device:/dev/tpmrm0); nothing stops or starts swtpm. The restart of swtpm of
# the container is, here, a guest power cycle with the swtpm state kept, which a guest command cannot survive: the host driver (e2e/vm/run.sh) runs this twice, PCR_HALF=first
# and PCR_HALF=second, and cycles the guest between them. The files of the run live in $PCR_DIR (default /var/tmp/custodio-e2e-pcr, which a power cycle keeps).
#   first    fixtures; the first reading of PCRs 0 and 7; the PolicyPCR control; alice imports both keys (in lacking root runs the reader on each credential, F157) and signs (round base);
#            PCRs 7 and 0 are extended and read, the control fails, round ext; `systemctl restart custodio` (a new MainPID, active, bus Ping), round restart.
#            Reports pcr-extended-signs. The keys stay.
#   second   after the cycle: the PCRs equal the first reading (OVMF measures the same boot twice), the boot id changed, the service is active, the same keys are listed with the same
#            kind (and in lacking pass the reader again), round cycle; alice deletes the keys. Reports pcr-restarted-signs and pcr-signs-every-key.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}" "${PCR_HALF:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/pcr-cases.sh
source "$here/pcr-cases.sh"
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
case ${E2E_TPM:-} in
swtpm) mode=vm-full kind=tpm ;;
lacking) mode=vm-lacking kind=encrypted-tpm ;;
*) fail "a VM run has the TPM mode swtpm or lacking, not '${E2E_TPM:-}'" ;;
esac
for tool in tpm2_pcrread tpm2_pcrextend tpm2_createprimary tpm2_create tpm2_load tpm2_unseal tpm2_startauthsession tpm2_policypcr tpm2_flushcontext openssl python3 busctl; do
    command -v "$tool" > /dev/null || fail "$tool is not installed"
done
PC=${PCR_DIR:-/var/tmp/custodio-e2e-pcr}
BOOT_ID_FILE=${BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}
export PCR_INDEXES=0,7
pc() { python3 -I "$here/pcr.py" "$@"; }
TCTI=${PCR_TCTI:-device:/dev/tpmrm0}
BANK=sha256
tt() { # DIR TOOL ARGS...: a tpm2-tools command on the guest's TPM, in DIR. Output DIR/last.out, status DIR/last.rc.
    local dir=$1 rc=0
    shift
    ( cd "$dir" && TPM2TOOLS_TCTI=$TCTI timeout 60 "$@" > last.out 2>&1 < /dev/null ) || rc=$?
    echo "$rc" > "$dir/last.rc"
    TPM2TOOLS_TCTI=$TCTI timeout 60 tpm2_flushcontext -t > /dev/null 2>&1 < /dev/null || true
    return 0
}
must() { [ "$(cat "$PC/ctl/last.rc")" = 0 ] || { cat "$PC/ctl/last.out" >&2; fail "$* failed"; }; }
pcrread() { # FILE
    tt "$PC/ctl" tpm2_pcrread "$BANK:$PCR_INDEXES"
    must tpm2_pcrread
    cp "$PC/ctl/last.out" "$1"
}
alice() { # ARGS: one call of pcr-user.sh as alice
    local tag="${1}${2:+-$2}"
    timeout 300 su -l alice -c "WORK=$WORK MODULE=$MODULE PCR_DIR=$PC PCR_KIND=$kind ${3:-} bash /e2e/pcr-user.sh $1 ${2:-}" > "$PC/alice-$tag.out" 2>&1 \
        || { cat "$PC/alice-$tag.out" >&2; fail "alice's session ($1 ${2:-}) failed"; }
}
read_creds() { # the reader (F157) on the credential of each key, in lacking only; prints the problems
    [ "$mode" = vm-lacking ] || return 0
    # shellcheck source=e2e/vm/cred-lib.sh
    source "$here/vm/cred-lib.sh"
    local id
    for id in pr-rsa pr-ec; do vm_read_credential "$id" >&2 || echo "reader: $id: the credential of an encrypted-tpm key did not pass the reader"; done
}
problems=''
judge() { # CASE PROBLEMS
    local case=$1 p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
add_problems() { # NAME PROBLEMS: problems that belong to no case
    [ -z "$(printf '%s' "$2" | tr -d '[:space:]')" ] || problems="$problems
$1:
$2"
}
finish() {
    [ -z "$(printf '%s' "$problems" | tr -d '[:space:]')" ] || fail "pcr cases:$problems"
    echo "pcr-vm: $PCR_HALF half passed"
}
wait_service() { # OLD_PID: a new MainPID, active and a bus Ping
    local p
    for _ in $(seq 100); do
        p=$(systemctl show -p MainPID --value custodio)
        if [ "$p" -gt 0 ] && [ "$p" != "${1:-}" ] && systemctl is-active --quiet custodio \
            && busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 org.freedesktop.DBus.Peer Ping > /dev/null 2>&1; then return 0; fi
        sleep 0.1
    done
    return 1
}

case $PCR_HALF in
first)
    rm -rf "${PC:?}"
    mkdir -p "$PC/in" "$PC/out" "$PC/ctl"
    tk_make "$PC" pcr
    rm -f "${PC:?}"/*.crt
    fx="$(fixture_problems "$PC/rsa.p12" rsa)
$(fixture_problems "$PC/ec.p12" ec)"
    [ "$(printf '%s' "$fx" | tr -d '[:space:]')" = '' ] || fail "the fixtures are not what the cases need: $fx"
    head -c 1000 /dev/urandom > "$PC/in/msg.bin"
    chmod -R a+rX "$PC"
    chmod 1777 "$PC" "$PC/in" "$PC/out"
    secret=custodio-pcr-secret
    printf '%s' "$secret" > "$PC/ctl/secret.bin"
    pcrread "$PC/pcr-first.txt"
    tt "$PC/ctl" tpm2_createprimary -C o -c cp.ctx
    must tpm2_createprimary
    tt "$PC/ctl" tpm2_startauthsession -S trial.ctx
    must "trial session"
    tt "$PC/ctl" tpm2_policypcr -S trial.ctx -l "$BANK:7" -L pol.dat
    must "trial tpm2_policypcr"
    tt "$PC/ctl" tpm2_flushcontext trial.ctx
    tt "$PC/ctl" tpm2_create -C cp.ctx -g sha256 -i secret.bin -L pol.dat -a 'fixedtpm|fixedparent|userwithauth' -u c.pub -r c.priv
    must "tpm2_create of the PCR-bound object"
    tt "$PC/ctl" tpm2_load -C cp.ctx -u c.pub -r c.priv -c c.ctx
    must "tpm2_load of the PCR-bound object"
    unseal() { # TAG
        tt "$PC/ctl" tpm2_startauthsession --policy-session -S s.ctx
        must "policy session"
        tt "$PC/ctl" tpm2_policypcr -S s.ctx -l "$BANK:7"
        must "tpm2_policypcr"
        tt "$PC/ctl" tpm2_unseal -c c.ctx -p session:s.ctx
        cp "$PC/ctl/last.rc" "$PC/ctl/unseal-$1.rc"
        cp "$PC/ctl/last.out" "$PC/ctl/unseal-$1.out"
        tt "$PC/ctl" tpm2_flushcontext s.ctx
    }
    unseal before
    alice import '' PCR_NOSIGN=1
    add_problems reader "$(read_creds)"
    alice sign base
    pid_first=$(systemctl show -p MainPID --value custodio)
    echo "$pid_first" > "$PC/pid-first"
    for i in 7 0; do
        tt "$PC/ctl" tpm2_pcrextend "$i:$BANK=$(printf 'custodio-pcr-%s' "$i" | sha256sum | cut -d' ' -f1)"
        must "tpm2_pcrextend $i"
    done
    pcrread "$PC/pcr-extended.txt"
    unseal after
    alice sign ext
    systemctl restart custodio || fail "systemctl restart custodio failed"
    wait_service "$pid_first" || fail "the service did not come back after the restart"
    systemctl show -p MainPID --value custodio > "$PC/pid-restart"
    alice sign restart
    cp "$BOOT_ID_FILE" "$PC/boot-first"
    echo "pcr: main pid $pid_first -> $(cat "$PC/pid-restart"); boot $(cat "$PC/boot-first")"
    judge pcr-extended-signs "$(pc extended "$PC/pcr-first.txt" "$PC/pcr-extended.txt")
$(pc control "$(cat "$PC/ctl/unseal-before.rc")" "$PC/ctl/unseal-before.out" "$(cat "$PC/ctl/unseal-after.rc")" "$PC/ctl/unseal-after.out" "$secret")
$(pc sigs "$PC" base "$PC/list-base.out" "$kind")
$(pc sigs "$PC" ext "$PC/list-ext.out" "$kind")
$(pc pid "$PC/pid-first" "$PC/pid-restart")
$(pc sigs "$PC" restart "$PC/list-restart.out" "$kind")
$(pc keys "$PC/list-base.out" "$PC/list-restart.out" "$mode" pr-rsa:rsa2048 pr-ec:ecdsa-p256)"
    : > "$PC/first-done"
    finish
    ;;
second)
    [ -e "$PC/first-done" ] || fail "the first half did not finish: there is nothing to check after the power cycle"
    wait_service '' || fail "the service is not active after the power cycle"
    pcrread "$PC/pcr-cycle.txt"
    cp "$BOOT_ID_FILE" "$PC/boot-second"
    alice sign cycle
    add_problems reader "$(read_creds)"
    alice delete
    judge pcr-restarted-signs "$(pc boot "$PC/boot-first" "$PC/boot-second")
$(pc restarted "$PC/pcr-first.txt" "$PC/pcr-extended.txt" "$PC/pcr-cycle.txt")
$(pc keys "$PC/list-restart.out" "$PC/list-cycle.out" "$mode" pr-rsa:rsa2048 pr-ec:ecdsa-p256)"
    judge pcr-signs-every-key "$(pc sigs "$PC" cycle "$PC/list-cycle.out" "$kind")"
    if grep -qE '^pr-(rsa|ec)	' "$PC/list-after.out"; then problems="$problems
end:
a key of the cases is still listed after the deletes"; fi
    systemctl is-active --quiet custodio || problems="$problems
end:
custodio.service is not active after the step"
    finish
    ;;
*) fail "PCR_HALF is first or second, not '$PCR_HALF'" ;;
esac
