#!/usr/bin/env bash
# Root side of the vm-silent-* cases (F161, acceptance 11 of SPEC.md). Needs WORK, E2E_VM=1 and E2E_TPM. Only the lacking VM mode runs them (an RSA import needs to go to encrypted-tpm);
# in the full mode every case is reported skipped.
# The libtss2-rc library is hidden from systemd (silent-lib.sh: dpkg-divert, the package stays installed) and what loads it restarted. Then alice imports an RSA 2048 key, which the
# lacking TPM sends to encrypted-tpm, and sealing needs the library: the import must fail with CredentialsUnavailable, leave one journal entry with the cause binding_mismatch, leave the
# state directory as it was, and leave no key of any kind for the id. The library is put back (always: a trap, plus an explicit restore) and the same import gives encrypted-tpm, which the
# reader (cred-lib.sh) finds bound to the TPM.
#   vm-silent-import-fails       has-tpm2 no longer yes while hidden; non-zero exit, CredentialsUnavailable in the CLI's text
#   vm-silent-journal-cause      exactly one import entry, outcome storage_failure, cause binding_mismatch, no secret
#   vm-silent-nothing-stored     the state directory listing (names, modes, sizes, checksums) is identical
#   vm-silent-no-key             the id is in neither list (API, custodio list), and no weaker kind is named anywhere
#   vm-silent-restored-imports   library back (no diversion, has-tpm2 yes), the same id gives encrypted-tpm, the reader passes
# Placement: guest.sh runs this after tpm-kind (before sign); the key it creates is deleted at the end.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/../report.sh"
VS_CASES="vm-silent-import-fails vm-silent-journal-cause vm-silent-nothing-stored vm-silent-no-key vm-silent-restored-imports"
mode=${E2E_TPM:-swtpm}
if [ -z "${E2E_VM:-}" ] || [ "$mode" != lacking ]; then
    for c in $VS_CASES; do case_skip "$c" "E2E_TPM=$mode: the import must go to encrypted-tpm (RSA on the lacking TPM) for the missing library to matter; the cases run in the lacking VM mode"; done
    exit 0
fi
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/../tpmkind-lib.sh"
# shellcheck source=e2e/vm/silent-lib.sh
source "$here/silent-lib.sh"
# shellcheck source=e2e/vm/cred-lib.sh
source "$here/cred-lib.sh"
for tool in openssl python3 busctl journalctl find sha256sum systemctl dpkg-divert systemd-analyze; do command -v "$tool" > /dev/null || fail "$tool is not installed"; done
ID=vs-key
VS=$WORK/vmsilent
rm -rf "${VS:?}"
mkdir "$VS" "$VS/hidden" "$VS/restored"
chmod 1777 "$VS" "$VS/hidden" "$VS/restored"
tk_make "$VS" vm-silent
rm -f "${VS:?}"/*.crt "$VS/ec.p12"
chmod 644 "$VS/rsa.p12"
fx=$(fixture_problems "$VS/rsa.p12" rsa)
[ -z "$fx" ] || fail "the fixture is not what the cases need: $fx"
pre=$(vs_has2 || true)
[ "$pre" = yes ] || fail "systemd-analyze has-tpm2 is not yes before the library is hidden: '$pre'"
vs_install_trap

alice() { # DIR import|delete: alice's session; the files go to DIR
    local d=$1 a=$2
    timeout 300 su -l alice -c "WORK=$WORK bash /e2e/vm/silent-user.sh $d $a $ID $VS/rsa.p12" > "$d/alice.out" 2>&1 || { cat "$d/alice.out" >&2; fail "alice's session ($a) failed"; }
}
state_listing() { # FILE
    { find /var/lib/custodio/ -printf '%y %p %m %s\n' | sort; find /var/lib/custodio/ -type f -exec sha256sum {} + | sort -k2; } > "$1"
}

# hidden
h=$VS/hidden
state_listing "$h/state-before"
vs_hide || fail "the library could not be hidden or the service did not start without it (docs: a service that does not start is BLOCKED.md material)"
rc=0
vs_has2 > "$h/has2.out" || rc=$?
echo "$rc" > "$h/has2.rc"
echo "vm-silent: has-tpm2 while hidden: '$(cat "$h/has2.out")' exit $rc"
cur=$(journalctl --sync; journalctl -n1 --show-cursor | sed -n 's/^-- cursor: //p')
alice "$h" import
journalctl --sync
journalctl --after-cursor="$cur" _SYSTEMD_UNIT=custodio.service CUSTODIO_OPERATION=import -o json --no-pager > "$h/journal.json"
state_listing "$h/state-after"

# restored
r=$VS/restored
vs_restore || fail "the library could not be put back"
rp=$(vs_restore_ok)
printf '%s\n' "$rp" | sed '/^$/d' > "$r/restore.problems"
rc=0
vs_has2 > "$r/has2.out" || rc=$?
echo "$rc" > "$r/has2.rc"
alice "$r" import
rc=0
vm_read_credential "$ID" > "$r/reader.out" 2>&1 || rc=$?
echo "$rc" > "$r/reader.rc"
mkdir "$VS/end"
chmod 1777 "$VS/end"
alice "$VS/end" delete

problems=''
for c in $VS_CASES; do
    p=$(vs_problems "$c" "$VS" "$ID")
    if [ -z "$p" ]; then case_run "$c"; else problems="$problems
$c:
$p"; fi
done
if grep -qE "^$ID	" "$VS/end/list.out"; then problems="$problems
end:
the key $ID is still listed after the delete"; fi
[ -z "$problems" ] || fail "vm-silent cases:$problems"
echo "vm-silent: passed"
