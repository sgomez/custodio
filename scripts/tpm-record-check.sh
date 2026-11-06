#!/usr/bin/env bash
# Checks, with tpm2-tools, that a TPM key stored by Custodio cannot be copied off its TPM (manual acceptance 13, F145).
# Usage: scripts/tpm-record-check.sh STATE_DIR KEY_ID      (as root, TPM2TOOLS_TCTI as the machine under test has it)
#   STATE_DIR  the service's real state directory, /var/lib/private/custodio (/var/lib/custodio is a link to it)
#   KEY_ID     the id of the key as `custodio list` shows it
# It reads the record with `python3 -I e2e/tpmdup.py scan`, makes the parent with the template of the service (docs/findings/F113.md),
# loads the key, prints `tpm2_readpublic` of it, and runs `tpm2_duplicate` under a policy session on TPM2_CC_Duplicate.
# Expected output: `authPolicy: empty` and `tpm2_duplicate: failed with TPM_RC_POLICY_FAIL`.
# Exit 0: both hold. 1: the check failed (authPolicy not empty, the duplicate succeeded) or a command did not work (load, readpublic, a
# duplicate failing with any other error): the message says which, and it is never read as "the duplicate fails as expected".
# 2: bad usage, a missing tool, or no record of kind tpm with that id.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
usage() { echo "usage: tpm-record-check.sh STATE_DIR KEY_ID" >&2; exit 2; }
[ $# -eq 2 ] || usage
state=$1
id=$2
case $id in '' | -* | */* | *$'\t'*) usage ;; esac
[ -d "$state" ] || { echo "tpm-record-check: $state: not a directory" >&2; exit 2; }
for tool in python3 tpm2_createprimary tpm2_load tpm2_readpublic tpm2_duplicate tpm2_startauthsession tpm2_policycommandcode tpm2_flushcontext; do
    command -v "$tool" > /dev/null || { echo "tpm-record-check: $tool is not installed (tpm2-tools)" >&2; exit 2; }
done
work=$(mktemp -d)
chmod 0700 "$work"
trap 'rm -rf "$work"' EXIT
scan=$(python3 -I "$ROOT/e2e/tpmdup.py" scan "$state" "$work/rec") || { echo "tpm-record-check: the records of $state could not be read" >&2; exit 2; }
dirs=$(awk -F'\t' -v k="$id" '$2 == k && $3 == "tpm" { print $1 "-" $2 }' <<< "$scan")
[ -n "$dirs" ] || { echo "tpm-record-check: no record of kind tpm with the id $id in $state" >&2; exit 2; }

SRK_ATTRS='fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt'
# tt FILE-PREFIX CMD...: runs a command in the work directory, its output in PREFIX.out and its status in PREFIX.rc; the transient objects are flushed after
tt() {
    local p=$1 rc=0
    shift
    ( cd "$work" && timeout 60 "$@" > "$p.out" 2>&1 < /dev/null ) || rc=$?
    echo "$rc" > "$work/$p.rc"
    timeout 60 tpm2_flushcontext -t > /dev/null 2>&1 < /dev/null || true
}
step_ok() { [ "$(cat "$work/$1.rc")" = 0 ]; }
status=0
tt parent tpm2_createprimary -C o -G ecc256:aes128cfb -a "$SRK_ATTRS" -c p.ctx
step_ok parent || { echo "tpm-record-check: FAIL: the parent could not be made: $(tail -n 3 "$work/parent.out")" >&2; exit 1; }
for d in $dirs; do
    echo "tpm-record-check: key $d"
    cp "$work/rec/$d/k.pub" "$work/k.pub"
    cp "$work/rec/$d/k.priv" "$work/k.priv"
    rm -f "$work/k.ctx" "$work/dup.priv" "$work/dup.seed"
    tt load tpm2_load -C p.ctx -u k.pub -r k.priv -c k.ctx
    step_ok load || { echo "tpm-record-check: FAIL: $d: tpm2_load failed: $(tail -n 3 "$work/load.out")" >&2; status=1; continue; }
    tt show tpm2_readpublic -c k.ctx
    step_ok show || { echo "tpm-record-check: FAIL: $d: tpm2_readpublic failed: $(tail -n 3 "$work/show.out")" >&2; status=1; continue; }
    cat "$work/show.out"
    if grep -qiE '^authorization policy: *[0-9a-f]' "$work/show.out"; then
        echo "authPolicy: NOT empty ($(grep -iE '^authorization policy' "$work/show.out"))"
        status=1
    elif grep -qiE '^name-alg' "$work/show.out"; then
        echo "authPolicy: empty"
    else
        echo "tpm-record-check: FAIL: $d: the output of tpm2_readpublic is not a public area" >&2
        status=1
        continue
    fi
    tt np tpm2_createprimary -C e -c np.ctx
    tt sess tpm2_startauthsession --policy-session -S s.ctx
    tt pcc tpm2_policycommandcode -S s.ctx TPM2_CC_Duplicate
    if ! step_ok np || ! step_ok sess || ! step_ok pcc; then
        echo "tpm-record-check: FAIL: $d: the policy session could not be set up: $(tail -n 3 "$work/np.out" "$work/sess.out" "$work/pcc.out" 2>&1 | tail -n 3)" >&2
        status=1
        continue
    fi
    tt dup tpm2_duplicate -C np.ctx -c k.ctx -G null -p session:s.ctx -r dup.priv -s dup.seed
    tt fl tpm2_flushcontext s.ctx
    if step_ok dup; then
        echo "tpm2_duplicate: succeeded"
        status=1
    elif grep -qiE '0x99d' "$work/dup.out"; then
        echo "tpm2_duplicate: failed with TPM_RC_POLICY_FAIL ($(grep -m1 -iE '0x99d' "$work/dup.out"))"
    else
        echo "tpm2_duplicate: failed with another error: $(tail -n 2 "$work/dup.out")"
        status=1
    fi
done
if [ "$status" = 0 ]; then echo "tpm-record-check: pass"; else echo "tpm-record-check: FAIL" >&2; fi
exit "$status"
