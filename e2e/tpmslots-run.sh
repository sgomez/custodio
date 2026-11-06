#!/usr/bin/env bash
# Root side of the tpm-slots-* cases (F143, acceptance 10 of SPEC.md: "more calls than TPM object slots"). Needs WORK, MODULE and E2E_TPM. Mode none has no TPM: the cases are reported skipped.
# In swtpm and lacking the service talks to swtpm through its socket with no kernel resource manager, so an object it left loaded would stay loaded. Root reads the slot count from the
# TPM (TPM2_PT_HR_TRANSIENT_MIN, tpm2_getcap properties-fixed on $TPM_SOCK, the filter's in lacking), N = slots + 3, and takes a snapshot of handles-transient and handles-loaded-session
# after the service is up and before any call of this step. Then alice (tpmslots-user.sh, polkit approved each time):
#   imports an RSA 2048 and a P-256 key (kind tpm); N signatures with each in a row (RSA-PKCS and RSA-PKCS-PSS alternating; the two runs as parallel jobs, TS_SERIES=1 for one after
#   the other); N imports in a row of the same .p12; one signature with the last imported key. Every call is logged by the guest after it ran, and the judgements count the logs.
# Then root takes the second snapshot, loads one object and leaves it (the control: the same judgement must report it), flushes it, and alice signs once more with each key and deletes
# every key of the step in one session; the last snapshot is taken after the deletes.
#   tpm-slots-sign-rsa / -sign-ec   at least N calls, all succeed and verify with openssl against the served certificate; the key is of kind tpm
#   tpm-slots-import                at least N imports, all listed with kind tpm, the last signs and verifies, all gone after the deletes
#   tpm-slots-no-leak               no transient handle and no loaded session in the second and last snapshots that the first lacks; the control is reported; a signature works after
# Placement: guest.sh runs this after the tpmclear step. The service stays active, the TPM as it was, and all the keys of the step are deleted.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/tpmslots-cases.sh
source "$here/tpmslots-cases.sh"
mode=${E2E_TPM:-swtpm}
if [ "$mode" = none ]; then
    tpmslots_skip_all "$mode"
    exit 0
fi
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
# shellcheck source=e2e/tpm-lib.sh
source "$here/tpm-lib.sh"
for tool in tpm2_getcap tpm2_createprimary tpm2_flushcontext openssl pkcs11-tool python3 busctl; do
    command -v "$tool" > /dev/null || fail "$tool is not installed"
done
TS=$WORK/tpmslots
rm -rf "${TS:?}"
mkdir -p "$TS/in" "$TS/out" "$TS/ctl"
tk_make "$TS" tpmslots
rm -f "${TS:?}"/*.crt
fx="$(fixture_problems "$TS/rsa.p12" rsa)
$(fixture_problems "$TS/ec.p12" ec)"
[ "$(printf '%s' "$fx" | tr -d '[:space:]')" = '' ] || fail "the fixtures are not what the cases need: $fx"
head -c 1000 /dev/urandom > "$TS/in/msg.bin"
openssl dgst -sha256 -binary "$TS/in/msg.bin" > "$TS/in/dgst.bin"
chmod -R a+rX "$TS"
chmod 1777 "$TS" "$TS/in" "$TS/out"
tsj() { python3 -I "$here/tpmslots.py" "$@"; }
TCTI=swtpm:path=$TPM_SOCK
# tt FILE TOOL ARGS...: a tpm2-tools command on the service's TPM; output in FILE, which must be the output of a command that succeeded. Nothing is flushed here: a handle that is
# loaded stays loaded, which is what is being looked at.
tt() {
    local f=$1
    shift
    TPM2TOOLS_TCTI=$TCTI timeout 60 "$@" > "$f" 2>&1 < /dev/null || { cat "$f" >&2; fail "$* failed"; }
}
snapshot() { # TAG: handles-transient and handles-loaded-session
    tt "$TS/ctl/transient-$1.txt" tpm2_getcap handles-transient
    tt "$TS/ctl/session-$1.txt" tpm2_getcap handles-loaded-session
}
alice() { timeout 900 su -l alice -c "WORK=$WORK MODULE=$MODULE TS_SERIES=${TS_SERIES:-} bash /e2e/tpmslots-user.sh $*" > "$TS/alice-$1.out" 2>&1 || { cat "$TS/alice-$1.out" >&2; fail "alice's session ($*) failed"; }; }
t0=$SECONDS
lap() { echo "tpmslots: $1 done at +$((SECONDS - t0)) s"; }

# the service is up (a Ping activates it); then the slot count and the first snapshot, before any call of this step
busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 org.freedesktop.DBus.Peer Ping > /dev/null 2>&1 || fail "the service does not answer a Ping"
systemctl is-active --quiet custodio || fail "custodio.service is not active"
tt "$TS/ctl/slots.txt" tpm2_getcap properties-fixed
slots=$(tsj slotcount "$TS/ctl/slots.txt") || fail "the slot count cannot be read"
n=$((slots + 3))
snapshot before
echo "tpmslots: the TPM reports $slots transient object slots (TPM2_PT_HR_TRANSIENT_MIN); $n signatures per key and $n imports; transient handles before: $(grep -c . "$TS/ctl/transient-before.txt" || true), loaded sessions before: $(grep -c . "$TS/ctl/session-before.txt" || true)"

alice import
lap import
alice sign "$n"
lap sign
alice imports "$n"
lap imports
snapshot after
echo "tpmslots: after the runs: transient handles $(grep -c . "$TS/ctl/transient-after.txt" || true), loaded sessions $(grep -c . "$TS/ctl/session-after.txt" || true)"

# the control: root loads one object and leaves it loaded; the same judgement reports it; it is flushed again
tt "$TS/ctl/cp.out" tpm2_createprimary -C o -c "$TS/ctl/cp.ctx"
snapshot leaked
leak_found=$(tsj leaked "$TS/ctl/transient-before.txt" "$TS/ctl/transient-leaked.txt")
tt "$TS/ctl/flush.out" tpm2_flushcontext -t
snapshot flushed
echo "tpmslots: control: transient handles with the object left loaded: $(grep -c . "$TS/ctl/transient-leaked.txt" || true); after the flush: $(grep -c . "$TS/ctl/transient-flushed.txt" || true)"

alice post
ids="ts-rsa ts-ec"
for i in $(seq "$n"); do ids="$ids ts-imp-$i"; done
# shellcheck disable=SC2086 # the ids are words
alice delete $ids
lap delete
snapshot final

# the calls the guest logged, counted from the logs (and every call asked polkit: the agent's approvals are at least the calls)
count() { wc -l < "$1"; }
calls=$(($(count "$TS/calls-rsa.tsv") + $(count "$TS/calls-ec.tsv") + $(count "$TS/imports.tsv") + $(count "$TS/calls-last.tsv") + $(count "$TS/calls-post-rsa.tsv") + $(count "$TS/calls-post-ec.tsv") + 2))
approved=0
for c in import sign imports post delete; do approved=$((approved + $(cat "$TS/requests-$c"))); done
echo "tpmslots: calls logged: rsa $(count "$TS/calls-rsa.tsv"), ec $(count "$TS/calls-ec.tsv"), imports $(count "$TS/imports.tsv"); polkit approvals $approved for $calls calls and 1 delete session"

problems=''
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
imported="ts-rsa:rsa2048 ts-ec:ecdsa-p256"
all_imp=''
for i in $(seq "$n"); do all_imp="$all_imp ts-imp-$i:rsa2048"; done
# shellcheck disable=SC2086 # the specs are words
judge tpm-slots-sign-rsa "$(tsj slotcount "$TS/ctl/slots.txt" 2>&1 > /dev/null || true)
$(tsj calls "$TS" calls-rsa.tsv "$TS/in/ts-rsa.pub.pem" rsa2048 "$n")
$(tsj listed "$TS/list-start.out" ts-rsa:rsa2048)"
judge tpm-slots-sign-ec "$(tsj slotcount "$TS/ctl/slots.txt" 2>&1 > /dev/null || true)
$(tsj calls "$TS" calls-ec.tsv "$TS/in/ts-ec.pub.pem" ecdsa-p256 "$n")
$(tsj listed "$TS/list-start.out" ts-ec:ecdsa-p256)"
# shellcheck disable=SC2086
judge tpm-slots-import "$(tsj imports "$TS/imports.tsv" "$n")
$(tsj listed "$TS/list-imports.out" $imported $all_imp)
$(tsj calls "$TS" calls-last.tsv "$TS/in/ts-imp-$n.pub.pem" rsa2048 1)
$(tsj gone "$TS/list-after.out" $ids)"
judge tpm-slots-no-leak "$(tsj handles "$TS/ctl/transient-before.txt" "$TS/ctl/transient-after.txt")
$(tsj handles "$TS/ctl/session-before.txt" "$TS/ctl/session-after.txt")
$(tsj handles "$TS/ctl/transient-before.txt" "$TS/ctl/transient-final.txt")
$(tsj handles "$TS/ctl/session-before.txt" "$TS/ctl/session-final.txt")
$leak_found
$(tsj handles "$TS/ctl/transient-before.txt" "$TS/ctl/transient-flushed.txt")
$(tsj calls "$TS" calls-post-rsa.tsv "$TS/in/ts-rsa.pub.pem" rsa2048 1)
$(tsj calls "$TS" calls-post-ec.tsv "$TS/in/ts-ec.pub.pem" ecdsa-p256 1)
$([ "$approved" -ge "$calls" ] || echo "the agent approved $approved requests for $calls calls: some call did not ask polkit")"
systemctl is-active --quiet custodio || problems="$problems
end:
custodio.service is not active after the step"
[ -S "$TPM_SOCK" ] || problems="$problems
end:
the TPM socket is gone after the step"
[ -z "$(printf '%s' "$problems" | tr -d '[:space:]')" ] || fail "tpmslots cases:$problems"
echo "tpmslots-run: passed"
