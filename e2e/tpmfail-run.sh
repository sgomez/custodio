#!/usr/bin/env bash
# Root side of the tpmfail-* cases (F139, acceptance 7 of SPEC.md). Needs WORK and E2E_TPM. Only mode swtpm runs them; the others report them skipped.
# The service gets, one at a time, a TPM that is present and fails (tpmfail-lib.sh: the drop-in names another socket) or a credential service that is down, and alice imports one RSA key
# with the CLI (tpmfail-user.sh). Each case is judged on five facts (tpmfail.py): (a) non-zero exit and the documented error in the CLI's text, (b) the state directory identical and
# the id not listed, (c) exactly one import entry in the journal, outcome storage_failure and the cause, no secret, (d) no weaker kind anywhere and, with the TPM restored, an
# import of the same id gives kind tpm, (e) the service is back (new MainPID, active, Ping) on the TPM of the mode.
#   tpmfail-device-unopenable             a socket file nobody listens on: TpmFailed, cause tpm_device (open.rs: a refused connection is OpenFailed, classified tpm_device)
#   tpmfail-tpm-error                     a TPM whose capability query fails: TpmFailed, cause tpm_error
#   tpmfail-credentials-down-tpm-lacking  a TPM that lacks RSA (so the choice is encrypted-tpm) and the credential socket stopped: CredentialsUnavailable, credentials_unavailable.
#                                         It alone cannot show the stopped service is the cause (docs/findings/F134.md: the container never seals to a TPM)
#   tpmfail-credentials-down-host         no TPM (a missing path, so the choice is encrypted-host): an import succeeds with the credential service up (kind encrypted-host), fails
#                                         with it stopped and succeeds again once started: the stopped service is the cause
# Placement: guest.sh runs this after the fallback step and before the upgrade. The drop-in, the credential socket and the service are put back at the end, even when a case fails.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/tpmfail-cases.sh
source "$here/tpmfail-cases.sh"
mode=${E2E_TPM:-swtpm}
if [ "$mode" != swtpm ]; then
    tpmfail_skip_all "$mode"
    exit 0
fi
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
# shellcheck source=e2e/tpm-lib.sh
source "$here/tpm-lib.sh"
# shellcheck source=e2e/tpmfail-lib.sh
source "$here/tpmfail-lib.sh"
for tool in openssl python3 busctl journalctl find sha256sum systemctl; do command -v "$tool" > /dev/null || fail "$tool is not installed"; done
TF=$WORK/tpmfail
rm -rf "${TF:?}"
mkdir "$TF"
chmod 1777 "$TF"
tk_make "$TF" tpmfail
rm -f "${TF:?}"/*.crt "$TF/ec.p12"
chmod 644 "$TF/rsa.p12"
fx=$(fixture_problems "$TF/rsa.p12" rsa)
[ -z "$fx" ] || fail "the fixture is not what the cases need: $fx"
tf() { python3 -I "$here/tpmfail.py" "$@"; }
# what must not be in a journal entry: the password and bytes of the file that holds the key (raw, hex and base64)
secret_hex=$(dd if="$TF/rsa.p12" bs=1 skip=200 count=24 2> /dev/null | od -An -tx1 | tr -d ' \n')
secret_b64=$(dd if="$TF/rsa.p12" bs=1 skip=201 count=24 2> /dev/null | base64 -w0)
SECRETS=(e2e-password "$secret_hex" "$secret_b64")

dirty=''
on_exit() {
    local rc=$?
    if [ -n "$dirty" ]; then tf_restore > /dev/null 2>&1 || true; fi
    tf_cleanup
    exit "$rc"
}
trap on_exit EXIT
tf_prepare

alice() { # DIR import ID | delete ID...: alice's session; DIR/import.{out,rc}, DIR/list.out
    local d=$1 file=''
    shift
    mkdir -p "$d"
    chmod 1777 "$d"
    [ "$1" != import ] || file=$TF/rsa.p12
    timeout 300 su -l alice -c "WORK=$WORK bash /e2e/tpmfail-user.sh $d $* $file" > "$d/alice.out" 2>&1 || { cat "$d/alice.out" >&2; fail "alice's session ($*) failed"; }
}
state_listing() { # FILE: names, types, modes, sizes and checksums of everything the service keeps
    { find /var/lib/custodio/ -printf '%y %p %m %s\n' | sort; find /var/lib/custodio/ -type f -exec sha256sum {} + | sort -k2; } > "$1"
}
cursor() { journalctl --sync; journalctl -n1 --show-cursor | sed -n 's/^-- cursor: //p'; }
problems=''
judge() { # CASE PROBLEMS
    local p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$1"; else problems="$problems
$1:
$p"; fi
}
ready_problems() { # (e): the service answers on the TPM of the mode
    tpm_observe swtpm > /dev/null 2> "$TF/observe.err" || echo "the unit's TPM is not the mode's: $(head -n 2 "$TF/observe.err")"
    systemctl is-active --quiet custodio || echo "the service is not active after the restore"
    busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 org.freedesktop.DBus.Peer Ping > /dev/null 2>&1 || echo "the service does not answer Ping after the restore"
}

# the rig works: with the TPM of the run an import gives kind tpm
alice "$TF/control" import tf-control
control=$(tf kind "$TF/control/import.out" "$TF/control/list.out" tf-control tpm)
[ -z "$control" ] || { echo "$control" >&2; fail "the control import with the TPM of the run did not give kind tpm"; }

# scenario ID DIR SOCKET ERROR CAUSE BACK-SOCKET BACK-KIND [down]: the attempt under the injection and the facts (a) to (d) and (e); the problems go to DIR/problems (not a subshell: a failure stops the run)
scenario() {
    local id=$1 d=$TF/$2 sock=$3 error=$4 cause=$5 back=$6 kind=$7 down=${8:-} cur out=""
    dirty=1
    tf_point "$sock"
    [ -z "$down" ] || tf_credentials_down
    mkdir -p "$d"
    state_listing "$d/state-before"
    cur=$(cursor)
    alice "$d" import "$id"
    journalctl --sync
    journalctl --after-cursor="$cur" _SYSTEMD_UNIT=custodio.service CUSTODIO_OPERATION=import -o json --no-pager > "$d/journal.json"
    state_listing "$d/state-after"
    [ -z "$down" ] || tf_credentials_up
    out="$(tf failed "$d/import.out" "$d/import.rc" "$error")
$(tf nothing "$d/state-before" "$d/state-after" "$d/list.out" "$id")
$(tf journal "$d/journal.json" "$id" "$cause" "${SECRETS[@]}")
$(tf noweaker "$d/import.out" "$d/list.out" "$d/journal.json" "$id")"
    # the TPM back: the same id was not consumed and the service is as before (d, e)
    tf_point "$back"
    [ "$back" != "$TPM_SOCK" ] || dirty=''
    alice "$d/restore" import "$id"
    out="$out
$(tf kind "$d/restore/import.out" "$d/restore/list.out" "$id" "$kind")"
    printf '%s\n' "$out" > "$d/problems"
}

scenario tf-dev stale "$TF_STALE" TpmFailed tpm_device "$TPM_SOCK" tpm
judge tpmfail-device-unopenable "$(cat "$TF/stale/problems")"
scenario tf-err broken "$TF_BROKEN" TpmFailed tpm_error "$TPM_SOCK" tpm
judge tpmfail-tpm-error "$(cat "$TF/broken/problems")"
scenario tf-cred norsa "$TF_NORSA" CredentialsUnavailable credentials_unavailable "$TPM_SOCK" tpm down
judge tpmfail-credentials-down-tpm-lacking "$(cat "$TF/norsa/problems")"

# the host-bound kind (no TPM: a missing path): the import succeeds with the credential service up before, fails with it stopped, and succeeds again once it is started
dirty=1
tf_point "$TF_MISSING"
alice "$TF/host-before" import tf-host-up
scenario tf-host host-down "$TF_MISSING" CredentialsUnavailable credentials_unavailable "$TF_MISSING" encrypted-host down
judge tpmfail-credentials-down-host "$(tf kind "$TF/host-before/import.out" "$TF/host-before/list.out" tf-host-up encrypted-host)
$(cat "$TF/host-down/problems")"

# the end: the TPM of the run is back (e), the keys of the step are deleted, nothing of it is listed
tf_restore
dirty=''
alice "$TF/end" delete tf-control tf-dev tf-err tf-cred tf-host-up tf-host
if grep -qE '^tf-' "$TF/end/list.out"; then problems="$problems
end:
a key of the cases is still listed"; fi
ready=$(ready_problems)
[ -z "$ready" ] || problems="$problems
end:
$ready"
[ -z "$problems" ] || fail "tpmfail cases:$problems"
echo "tpmfail-run: passed"
