#!/usr/bin/env bash
# Root side of the tpm-kind-* cases (F133, acceptance 1 of SPEC.md). Needs WORK. With the TPM of the run (swtpm) alice imports an RSA 2048 and a P-256 .p12 with the
# CLI (tpmkind-user.sh); the kind must be tpm in the import result, in the API's list, in `custodio list` and in the import entries of the journal. In any other
# mode (none, lacking) the key gets another kind, which later features prove, and every case is reported skipped.
# Placement: guest.sh runs this after the cli step and before the upgrade. Both keys are deleted by alice, her agent state is apart from $WORK/agent, and the
# step comes after the journal step has counted its entries, so the state and the counts the other steps read are as before.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
# shellcheck source=e2e/tpmkind-cases.sh
source "$here/tpmkind-cases.sh"
bash "$here/tpmkind-selftest.sh" || fail "the tpm-kind self-test failed"

mode=${E2E_TPM:-swtpm}
# F161: in a VM run (E2E_VM=1) the TPM is the VM's own: swtpm is the full mode (kind tpm), lacking is the lacking mode (kind encrypted-tpm, read back with the reader of F157). A container
# run keeps its rule: only swtpm runs the cases.
judge_mode=swtpm
read_creds=''
if [ -n "${E2E_VM:-}" ]; then
    case $mode in
    swtpm) judge_mode=full ;;
    lacking) judge_mode=lacking read_creds=1 ;;
    *) fail "a VM run has the TPM mode swtpm or lacking, not '$mode'" ;;
    esac
elif [ "$mode" != swtpm ]; then
    tpmkind_skip_all "$mode"
    exit 0
fi
TK=$WORK/tpmkind
rm -rf "$TK"
mkdir "$TK"
chmod 1777 "$TK"
tk_make "$TK"
rm -f "$TK"/*.crt
chmod 644 "$TK"/*
problems=''
fx="$(fixture_problems "$TK/rsa.p12" rsa)
$(fixture_problems "$TK/ec.p12" ec)"
[ "$(printf '%s' "$fx" | tr -d '[:space:]')" = '' ] || fail "the fixtures are not what the cases need: $fx"

since=$(date +%s)
# With the reader (lacking, VM) alice waits after her list until root has read the stored credentials, then deletes the keys (tpmkind-user.sh, TK_READ).
if [ -n "$read_creds" ]; then
    # shellcheck source=e2e/vm/cred-lib.sh
    source "$here/vm/cred-lib.sh"
    timeout 600 su -l alice -c "WORK=$WORK TK_READ=1 bash /e2e/tpmkind-user.sh" > "$TK/alice.out" 2>&1 &
    alice=$!
    for _ in $(seq 600); do [ -e "$TK/imported" ] || ! kill -0 "$alice" 2> /dev/null || sleep 0.2; done
    if [ -e "$TK/imported" ]; then
        for id in tk-rsa tk-ec; do vm_read_credential "$id" || problems="$problems
reader:
$id: the credential of an encrypted-tpm key did not pass the reader"; done
    fi
    : > "$TK/read-done"
    wait "$alice" || { cat "$TK/alice.out" >&2; fail "alice's session failed"; }
else
    timeout 600 su -l alice -c "WORK=$WORK bash /e2e/tpmkind-user.sh" > "$TK/alice.out" 2>&1 || { cat "$TK/alice.out" >&2; fail "alice's session failed"; }
fi

jp=''
for _ in $(seq 60); do
    journalctl --sync
    journalctl --since "@$since" -o json --no-pager > "$TK/journal.json"
    jp=$(python3 -I "$here/tpmkind.py" --mode "$judge_mode" journal "$TK/journal.json" tk-rsa tk-ec) || true
    [ -z "$jp" ] && break
    sleep 0.5
done
tpmkind_judge "$judge_mode" "$TK" "$jp"
problems="$problems$TK_PROBLEMS"
[ -z "$problems" ] || fail "tpm-kind cases:$problems"
echo "tpmkind-run: passed"
