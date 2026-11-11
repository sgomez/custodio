#!/usr/bin/env bash
# Root side of the fallback-* cases (F138, acceptance 6 of SPEC.md). Needs WORK. Mode none (no TPM): alice imports an RSA 2048 and a P-256 .p12 with the CLI
# (fallback-user.sh); the kind must be encrypted-host in the API's list, the import output must give it, say the key is weaker and why (no TPM), and `custodio list`
# must show it. The fallback-tpmbound-* cases are skipped in every mode (SPEC_DEVIATIONS.md, F134: the container cannot make encrypted-tpm); in the other modes the host cases are
# skipped too (the keys are tpm there).
# Placement: guest.sh runs this after the pcr step and before the upgrade. Both keys are deleted by alice, her agent state is apart from $WORK/agent, and the step comes after the
# journal step has counted its entries, so the state and the counts the other steps read are as before.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
# shellcheck source=e2e/fallback-cases.sh
source "$here/fallback-cases.sh"

mode=${E2E_TPM:-swtpm}
# F161: in a VM run (E2E_VM=1) the tpmbound cases run in both modes and the host cases are not in the VM list. full: both keys are tpm and nothing is called weaker; lacking: both are
# encrypted-tpm, the import output says the key is weaker and why, and root reads each stored credential with the reader of F157.
vm_mode=''
if [ -n "${E2E_VM:-}" ]; then
    case $mode in
    swtpm) vm_mode=full ;;
    lacking) vm_mode=lacking ;;
    *) fail "a VM run has the TPM mode swtpm or lacking, not '$mode'" ;;
    esac
else
    fallback_skip "$mode"
    [ "$mode" = none ] || exit 0
fi
FB=$WORK/fallback
rm -rf "${FB:?}"
mkdir "$FB"
chmod 1777 "$FB"
tk_make "$FB" fallback
rm -f "${FB:?}"/*.crt
chmod 644 "$FB"/*
fx="$(fixture_problems "$FB/rsa.p12" rsa)
$(fixture_problems "$FB/ec.p12" ec)"
[ "$(printf '%s' "$fx" | tr -d '[:space:]')" = '' ] || fail "the fixtures are not what the cases need: $fx"

read_creds=''
[ "$vm_mode" != lacking ] || read_creds=1
if [ -n "$read_creds" ]; then
    # shellcheck source=e2e/vm/cred-lib.sh
    source "$here/vm/cred-lib.sh"
    timeout 600 su -l alice -c "WORK=$WORK FB_READ=1 bash /e2e/fallback-user.sh" > "$FB/alice.out" 2>&1 &
    alice=$!
    problems=''
    for _ in $(seq 600); do [ -e "$FB/imported" ] || ! kill -0 "$alice" 2> /dev/null || sleep 0.2; done
    if [ -e "$FB/imported" ]; then
        for id in fb-rsa fb-ec; do vm_read_credential "$id" || problems="$problems
reader:
$id: the credential of an encrypted-tpm key did not pass the reader"; done
    else
        problems="$problems
reader: the keys were never imported, the credentials were not read"
    fi
    : > "$FB/read-done"
    wait "$alice" || { cat "$FB/alice.out" >&2; fail "alice's session failed"; }
else
    timeout 600 su -l alice -c "WORK=$WORK bash /e2e/fallback-user.sh" > "$FB/alice.out" 2>&1 || { cat "$FB/alice.out" >&2; fail "alice's session failed"; }
fi

problems=${problems:-}
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
if [ -n "$vm_mode" ]; then
    fb() { python3 -I "$here/fallback.py" --mode "$vm_mode" "$@"; }
    judge fallback-tpmbound-import "$(fb import "$FB/import-rsa.out" fb-rsa rsa2048)
$(fb import "$FB/import-ec.out" fb-ec ecdsa-p256)
$(fb api "$FB/api.out" fb-rsa:rsa2048 fb-ec:ecdsa-p256)
$(fb why "$FB/import-rsa.out" "$FB/import-ec.out")"
    judge fallback-tpmbound-cli-list "$(fb cli "$FB/cli.out" fb-rsa:rsa2048 fb-ec:ecdsa-p256)"
    if grep -qE '^fb-(rsa|ec)	' "$FB/api-after.out"; then problems="$problems
end:
a key of the cases is still listed after the deletes"; fi
    [ -z "$problems" ] || fail "fallback cases:$problems"
    echo "fallback-run: passed"
    exit 0
fi
fb() { python3 -I "$here/fallback.py" "$@"; }
# the kind the service gives (ListKeys) is judged with each import, so the CLI text is never judged against a mode that gave another kind
judge fallback-host-import-rsa "$(fb import "$FB/import-rsa.out" fb-rsa rsa2048)
$(fb api "$FB/api.out" fb-rsa:rsa2048)"
judge fallback-host-import-ec "$(fb import "$FB/import-ec.out" fb-ec ecdsa-p256)
$(fb api "$FB/api.out" fb-ec:ecdsa-p256)"
judge fallback-host-says-weaker-why "$(fb why "$FB/import-rsa.out" "$FB/import-ec.out")"
judge fallback-host-cli-list "$(fb cli "$FB/cli.out" fb-rsa:rsa2048 fb-ec:ecdsa-p256)"
if grep -qE '^fb-(rsa|ec)	' "$FB/api-after.out"; then problems="$problems
end:
a key of the cases is still listed after the deletes"; fi
[ -z "$problems" ] || fail "fallback cases:$problems"
echo "fallback-run: passed"
