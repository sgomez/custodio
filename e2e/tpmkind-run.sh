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
if [ "$mode" != swtpm ]; then
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
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
fx="$(fixture_problems "$TK/rsa.p12" rsa)
$(fixture_problems "$TK/ec.p12" ec)"
[ "$(printf '%s' "$fx" | tr -d '[:space:]')" = '' ] || fail "the fixtures are not what the cases need: $fx"

since=$(date +%s)
timeout 600 su -l alice -c "WORK=$WORK bash /e2e/tpmkind-user.sh" > "$TK/alice.out" 2>&1 || { cat "$TK/alice.out" >&2; fail "alice's session failed"; }

jp=''
for _ in $(seq 60); do
    journalctl --sync
    journalctl --since "@$since" -o json --no-pager > "$TK/journal.json"
    jp=$(python3 -I "$here/tpmkind.py" journal "$TK/journal.json" tk-rsa tk-ec) || true
    [ -z "$jp" ] && break
    sleep 0.5
done
tk() { python3 -I "$here/tpmkind.py" "$@"; }
judge tpm-kind-import-rsa "$(tk import "$TK/import-rsa.out" tk-rsa rsa2048)"
judge tpm-kind-import-ec "$(tk import "$TK/import-ec.out" tk-ec ecdsa-p256)"
judge tpm-kind-api-list "$(tk api "$TK/api.out" tk-rsa:rsa2048 tk-ec:ecdsa-p256)"
judge tpm-kind-cli-list "$(tk cli "$TK/cli.out" tk-rsa:rsa2048 tk-ec:ecdsa-p256)"
judge tpm-kind-journal "$jp"
# state left as found: the keys are gone
if grep -qE '^tk-(rsa|ec)	' "$TK/api-after.out"; then problems="$problems
end:
a key of the cases is still listed after the deletes"; fi
[ -z "$problems" ] || fail "tpm-kind cases:$problems"
echo "tpmkind-run: passed"
