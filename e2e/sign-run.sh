#!/usr/bin/env bash
# Root side of the sign-* cases (F134, acceptances 2 and 6 of SPEC.md). Needs WORK, MODULE and E2E_TPM. In every mode (swtpm, none, lacking) alice imports an RSA 2048 and a
# P-256 key (sign-user.sh), signs with every mechanism the module offers for them, and sign.py verifies each signature with `openssl` against the certificate the module served.
# No case is skipped in any mode: the keys get another kind in each mode and must sign the same way; sign-kind-matches-mode shows which kind they got.
# Placement: guest.sh runs this after the tpm-kind step and before the upgrade. Both keys are deleted by alice, her agent state is apart from $WORK/agent, and the step
# comes after the journal step has counted its entries, so the state and the counts the other steps read are as before.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
bash "$here/sign-selftest.sh" || fail "the sign self-test failed"

mode=${E2E_TPM:-swtpm}
# F162: in a VM run (E2E_VM=1) the TPM is the VM's own: swtpm is the full mode (kind tpm), lacking is the lacking mode (kind encrypted-tpm for both keys; root reads both stored
# credentials with the reader of F157 while alice waits between the imports and the signatures). A container run keeps its table.
read_creds=''
if [ -n "${E2E_VM:-}" ]; then
    case $mode in
    swtpm) mode=vm-full ;;
    lacking) mode=vm-lacking read_creds=1 ;;
    *) fail "a VM run has the TPM mode swtpm or lacking, not '$mode'" ;;
    esac
fi
SG=$WORK/sign
rm -rf "$SG"
mkdir "$SG"
chmod 1777 "$SG"
python3 -I "$here/sign.py" prepare "$SG"
tk_make "$SG" sign
rm -f "$SG"/*.crt
chmod -R a+rX "$SG"
chmod 1777 "$SG" "$SG/in"
fx="$(fixture_problems "$SG/rsa.p12" rsa)
$(fixture_problems "$SG/ec.p12" ec)"
[ "$(printf '%s' "$fx" | tr -d '[:space:]')" = '' ] || fail "the fixtures are not what the cases need: $fx"
mkdir -p "$SG/out"
chmod 1777 "$SG/out"

problems=''
if [ -n "$read_creds" ]; then
    # shellcheck source=e2e/vm/cred-lib.sh
    source "$here/vm/cred-lib.sh"
    timeout 900 su -l alice -c "WORK=$WORK MODULE=$MODULE SG_READ=1 bash /e2e/sign-user.sh" > "$SG/alice.out" 2>&1 &
    alice=$!
    for _ in $(seq 600); do
        [ -e "$SG/imported" ] && break
        kill -0 "$alice" 2> /dev/null || break
        sleep 0.2
    done
    if [ -e "$SG/imported" ]; then
        for id in sg-rsa sg-ec; do vm_read_credential "$id" || problems="$problems
reader:
$id: the credential of an encrypted-tpm key did not pass the reader"; done
    else
        problems="$problems
reader: the keys were never imported, the credentials were not read"
    fi
    : > "$SG/read-done"
    wait "$alice" || { cat "$SG/alice.out" >&2; fail "alice's session failed"; }
else
    timeout 900 su -l alice -c "WORK=$WORK MODULE=$MODULE bash /e2e/sign-user.sh" > "$SG/alice.out" 2>&1 || { cat "$SG/alice.out" >&2; fail "alice's session failed"; }
fi

sg() { python3 -I "$here/sign.py" "$@"; }
# what every signature gave (a log for the reader of the run)
while read -r name _; do
    echo "sign: $name rc=$(cat "$SG/out/$name.rc") bytes=$(stat -c %s "$SG/out/$name.sig" 2> /dev/null || echo none) $(grep -o 'CKR_[A-Z_0-9]*' "$SG/out/$name.log" | tail -n 1)"
    [ "$(cat "$SG/out/$name.rc")" = 0 ] || sed 's/^/sign:     /' "$SG/out/$name.log" | tail -n 4
done < "$SG/jobs"
while read -r g; do echo "sign: $g agent requests $(cat "$SG/count-$g")"; done < "$SG/groups"
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
judge sign-kind-matches-mode "$(sg kind "$SG/api.out" "$mode" sg-rsa:rsa2048 sg-ec:ecdsa-p256)"
while read -r g; do judge "$g" "$(sg case "$g" "$SG")"; done < "$SG/groups"
if grep -qE '^sg-(rsa|ec)	' "$SG/api-after.out"; then problems="$problems
end:
a key of the cases is still listed after the deletes"; fi
[ -z "$problems" ] || fail "sign cases:$problems"
echo "sign-run: passed"
