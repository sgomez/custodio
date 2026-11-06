#!/usr/bin/env bash
# Root side of the pcr-* cases (F137, acceptance 5 first part of SPEC.md: "no PCR dependency"). Needs WORK and E2E_TPM. Mode none has no TPM: the cases are reported skipped.
# In swtpm and lacking alice imports an RSA 2048 and a P-256 key (pcr-user.sh; both of kind tpm) and signs with every key of kind tpm she lists, verified by `openssl` against the
# served certificate (round base). Root, with tpm2-tools on the service's own TPM socket ($TPM_SOCK, in lacking the filter's):
#   control   an object whose policy is PolicyPCR on PCR 7 (the value read before) unseals before the extension; after it, the same policy session fails (policy failure)
#   extend    PCRs 0, 7 and 11 (sha256) are extended with tpm2_pcrextend and read again (they differ); every key signs again (round ext)
#   restart   the TPM goes down and up on the same state directory (tpm_swtpm_restart: swtpm_ioctl -s, wait for the state directory to be free) and then `systemctl restart custodio`;
#             readiness is: a new MainPID, ActiveState active and a bus Ping answered; the PCRs read back at the first reading's values; the keys are listed as before;
#             every key signs again (round restart)
#   pcr-extended-signs   the extension changed the PCRs, the control, rounds base and ext verify
#   pcr-restarted-signs  the restarts happened (new pid, PCRs back at the first reading and not the extended ones) and the same keys are listed with the same kind
#   pcr-signs-every-key  round restart: every key of kind tpm the service lists (at least the two imported) signs and verifies
# Placement: guest.sh runs this after the tpmdup step. It is the first step that restarts the TPM and the service in the middle of the run: it leaves the service active (a new
# MainPID; the steps after it read MainPID fresh), swtpm and its socket in place, and both keys deleted. Journal counts that the later steps read since boot are in the finding.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/pcr-cases.sh
source "$here/pcr-cases.sh"
mode=${E2E_TPM:-swtpm}
if [ "$mode" = none ]; then
    pcr_skip_all "$mode"
    exit 0
fi
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
# shellcheck source=e2e/tpm-lib.sh
source "$here/tpm-lib.sh"
for tool in tpm2_pcrread tpm2_pcrextend tpm2_createprimary tpm2_create tpm2_load tpm2_unseal tpm2_startauthsession tpm2_policypcr tpm2_flushcontext swtpm_ioctl openssl python3 busctl; do
    command -v "$tool" > /dev/null || fail "$tool is not installed"
done
PC=$WORK/pcr
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
pc() { python3 -I "$here/pcr.py" "$@"; }
TCTI=swtpm:path=$TPM_SOCK
BANK=sha256
# tt DIR TOOL ARGS...: a tpm2-tools command on the service's TPM, in DIR; transient objects are flushed after it (no resource manager). Output DIR/last.out, status DIR/last.rc.
tt() {
    local dir=$1 rc=0
    shift
    ( cd "$dir" && TPM2TOOLS_TCTI=$TCTI timeout 60 "$@" > last.out 2>&1 < /dev/null ) || rc=$?
    echo "$rc" > "$dir/last.rc"
    TPM2TOOLS_TCTI=$TCTI timeout 60 tpm2_flushcontext -t > /dev/null 2>&1 < /dev/null || true
    return 0
}
must() { [ "$(cat "$PC/ctl/last.rc")" = 0 ] || { cat "$PC/ctl/last.out" >&2; fail "$* failed"; }; }
pcrread() { # FILE: PCRs 0, 7 and 11 of the bank
    tt "$PC/ctl" tpm2_pcrread "$BANK:0,7,11"
    must tpm2_pcrread
    cp "$PC/ctl/last.out" "$1"
}
alice() { timeout 300 su -l alice -c "WORK=$WORK MODULE=$MODULE bash /e2e/pcr-user.sh $*" > "$PC/alice-${1}${2:+-$2}.out" 2>&1 || { cat "$PC/alice-${1}${2:+-$2}.out" >&2; fail "alice's session ($*) failed"; }; }

# the control: a sealed object whose policy is PolicyPCR on PCR 7 as it is now; the policy session is satisfied now (unseal works)
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
unseal() { # TAG: a policy session on PCR 7 (its current value), then tpm2_unseal under it; result in ctl/unseal-TAG.{rc,out}
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
echo "pcr: control before the extension: exit $(cat "$PC/ctl/unseal-before.rc")"

alice import
pid_first=$(systemctl show -p MainPID --value custodio)
echo "$pid_first" > "$PC/pid-first"

# extend PCRs 7, 0 and 11, read them, and sign again
for i in 7 0 11; do
    tt "$PC/ctl" tpm2_pcrextend "$i:$BANK=$(printf 'custodio-pcr-%s' "$i" | sha256sum | cut -d' ' -f1)"
    must "tpm2_pcrextend $i"
done
pcrread "$PC/pcr-extended.txt"
unseal after
echo "pcr: control after the extension: exit $(cat "$PC/ctl/unseal-after.rc"): $(grep -m1 -i 'policy' "$PC/ctl/unseal-after.out" || true)"
alice sign ext

# restart the TPM and then the service
tpm_swtpm_restart "$mode" || fail "the TPM could not be restarted"
systemctl restart custodio || fail "systemctl restart custodio failed"
for _ in $(seq 100); do
    p=$(systemctl show -p MainPID --value custodio)
    if [ "$p" -gt 0 ] && [ "$p" != "$pid_first" ] && systemctl is-active --quiet custodio \
        && busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 org.freedesktop.DBus.Peer Ping > /dev/null 2>&1; then break; fi
    sleep 0.1
done
systemctl show -p MainPID --value custodio > "$PC/pid-restart"
pcrread "$PC/pcr-restart.txt"
echo "pcr: main pid $pid_first -> $(cat "$PC/pid-restart"); PCR 7 first $(sed -n 's/^ *7 *: *//p' "$PC/pcr-first.txt"), extended $(sed -n 's/^ *7 *: *//p' "$PC/pcr-extended.txt"), after restart $(sed -n 's/^ *7 *: *//p' "$PC/pcr-restart.txt")"
alice sign restart
alice delete

problems=''
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
for r in base ext restart; do echo "pcr: round $r signed with: $(pc enumerate "$PC/list-$r.out" | cut -f1 | tr '\n' ' ')"; done
judge pcr-extended-signs "$(pc extended "$PC/pcr-first.txt" "$PC/pcr-extended.txt")
$(pc control "$(cat "$PC/ctl/unseal-before.rc")" "$PC/ctl/unseal-before.out" "$(cat "$PC/ctl/unseal-after.rc")" "$PC/ctl/unseal-after.out" "$secret")
$(pc sigs "$PC" base "$PC/list-base.out")
$(pc sigs "$PC" ext "$PC/list-ext.out")"
judge pcr-restarted-signs "$(pc pid "$PC/pid-first" "$PC/pid-restart")
$(pc restarted "$PC/pcr-first.txt" "$PC/pcr-extended.txt" "$PC/pcr-restart.txt")
$(pc keys "$PC/list-base.out" "$PC/list-restart.out" "$mode" pr-rsa:rsa2048 pr-ec:ecdsa-p256)"
judge pcr-signs-every-key "$(pc sigs "$PC" restart "$PC/list-restart.out")"
if grep -qE '^pr-(rsa|ec)	' "$PC/list-after.out"; then problems="$problems
end:
a key of the cases is still listed after the deletes"; fi
systemctl is-active --quiet custodio || problems="$problems
end:
custodio.service is not active after the step"
[ -S "$TPM_SOCK" ] || problems="$problems
end:
the TPM socket is gone after the step"
[ -z "$(printf '%s' "$problems" | tr -d '[:space:]')" ] || fail "pcr cases:$problems"
echo "pcr-run: passed"
