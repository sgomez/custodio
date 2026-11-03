#!/usr/bin/env bash
# Root side of the replace-* and delete-* cases (F93, acceptance 5 and 6 of SPEC.md). Usage: rd-run.sh replace|delete, with WORK and MODULE set. Alice, in a login
# session of her own with a test agent (rd-user.sh), replaces a certificate or deletes a key through the shipped service, CLI and PKCS#11 module with the agent
# approving; this script makes the fixtures, serves her snapshots of the state directory (she cannot read it) and judges the evidence (rd-lib.sh).
# Placement: guest.sh runs each group after the ops-polkit step and before the upgrade. Every key a group makes is deleted by alice at its end, and the state
# directory is compared with the one at the start, so TOTAL, the journal window and the state upgrade and lifecycle start from are as before.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
GROUP=${1:?usage: rd-run.sh replace|delete}
: "${WORK:?}" "${MODULE:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/rd-lib.sh
source "$here/rd-lib.sh"
# shellcheck source=e2e/upgrade-lib.sh
source "$here/upgrade-lib.sh"
bash "$here/rd-selftest.sh" || fail "the rd self-test failed"

RD=$WORK/rd-$GROUP
rm -rf "$RD"
mkdir "$RD"
chmod 1777 "$RD"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$RD/k.key" 2> /dev/null
mkcert() { openssl req -new -x509 -key "$1" -subj "/CN=$2" -days 30 -out "$3.pem" && openssl x509 -in "$3.pem" -outform DER -out "$3.der"; }
mkcert "$RD/k.key" f93-old "$RD/cert1"
head -c 64 /dev/urandom > "$RD/data.bin"
if [ "$GROUP" = replace ]; then
    mkcert "$RD/k.key" f93-new "$RD/cert2"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$RD/other.key" 2> /dev/null
    mkcert "$RD/other.key" f93-other "$RD/cert-other"
    rm -f "$RD/other.key"
fi
openssl pkcs12 -export -inkey "$RD/k.key" -in "$RD/cert1.pem" -name f93 -passout pass:e2e-password -out "$RD/k.p12"
rm -f "$RD/k.key"
chmod 644 "$RD"/*

snapshot_state > "$RD/start.state" || fail "cannot snapshot the state directory"
trap '[ -z "${upid:-}" ] || kill "$upid" 2> /dev/null || true' EXIT
timeout 900 su -l alice -c "GROUP=$GROUP WORK=$WORK MODULE=$MODULE bash /e2e/rd-user.sh" > "$RD/alice.out" 2>&1 &
upid=$!
serve() {
    local f name
    while kill -0 "$upid" 2> /dev/null; do
        for f in "$RD"/want-*; do
            [ -e "$f" ] || continue
            name=${f##*/want-}
            [ ! -e "$RD/have-$name" ] || continue
            case $name in
            snap-*) snapshot_state > "$RD/${name#snap-}.state" || { echo "snapshot failed" >&2; return 1; }; chmod 644 "$RD/${name#snap-}.state" ;;
            *) echo "unknown request '$name'" >&2; return 1 ;;
            esac
            touch "$RD/have-$name"
        done
        sleep 0.1
    done
}
serve || { cat "$RD/alice.out" >&2; fail "serving alice's session failed"; }
wait "$upid" || { cat "$RD/alice.out" >&2; fail "alice's session failed"; }
upid=''
snapshot_state > "$RD/end.state"
CALLS=$RD/calls

problems=''
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p=$2
    p=$(printf '%s\n' "$p" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
call_p() { ops_call_problems "$CALLS" "$@"; }
snap_p() { # LABEL A B: list/certificates part and state directory part equal
    ops_state_problems "$1 (list and certificates)" "$RD/$2.user" "$RD/$3.user"
    ops_state_problems "$1 (state directory)" "$RD/$2.state" "$RD/$3.state"
}
approve() { echo "approve $1"; }

case $GROUP in
replace)
    # Acceptance 5: the certificate for the same key replaces the old one. The count of replace-certificate requests is F92's evidence; a sanity check here.
    judge replace-same-key "$(call_p replace-same ok "$(approve $OPS_ACTION_REPLACE)"
        rd_sha_problems "certificate before the replace is certificate 1" "$RD/before.der" "$RD/cert1.der"
        rd_sha_problems "certificate after the replace is certificate 2" "$RD/after.der" "$RD/cert2.der"
        rd_not_sha_problems "the replace changed the certificate" "$RD/after.der" "$RD/before.der"
        ops_differ_problems "replace-same (snapshot)" "$RD/r0.user" "$RD/r1.user")"
    judge replace-list-shows-new "$(rd_subject_problems "$RD/list-after" rep-key f93-new f93-old
        grep -qxF '  type: rsa2048' "$RD/list-after" || echo "type of rep-key is not rsa2048 or the block is gone"
        list_problems "$RD/list-after" +rep-key)"
    judge replace-module-shows-new "$(rd_sha_problems "module certificate after the replace" "$RD/after.der" "$RD/cert2.der"
        rd_not_sha_problems "module certificate is not the old one" "$RD/after.der" "$RD/cert1.der")"
    # the certificate is read back from the module after the signature; the key of certificates 1 and 2 is the same, so the signature cannot tell them apart:
    # the byte check above does. The signature must verify against the module's certificate, and not against the unrelated key's.
    judge replace-sign-verifies "$(rd_sha_problems "module certificate after the signature" "$RD/module-after-sign.der" "$RD/cert2.der"
        verify_problems "$RD/sig" "$RD/data.bin" "$RD/module-after-sign.der"
        verify_fails_problems "$RD/sig" "$RD/data.bin" "$RD/cert-other.der")"
    judge replace-different-key "$(call_p replace-mismatch "$RD_MISMATCH" "$(approve $OPS_ACTION_REPLACE)"
        snap_p "mismatch" r1 r2
        rd_sha_problems "module certificate after the mismatch" "$RD/after-mismatch.der" "$RD/cert2.der"
        rd_subject_problems "$RD/list-mismatch" rep-key f93-new f93-old
        verify_problems "$RD/sig2" "$RD/data.bin" "$RD/after-mismatch.der")"
    ;;
delete)
    judge delete-list-absent "$(call_p delete-cli ok "$(approve $OPS_ACTION_DELETE)"
        list_problems "$RD/d2.user" +del-key +del-keep
        list_problems "$RD/d3.user" -del-key +del-keep)"
    judge delete-module-no-token "$(rd_token_problems "$RD/slots-before" +del-key +del-keep
        rd_token_problems "$RD/slots-after" -del-key +del-keep
        grep -q "^cert del-keep [0-9a-f]\{64\}$" "$RD/d3.user" || echo "no certificate hash of del-keep after the delete"
        ! grep -q "^cert del-key " "$RD/d3.user" || echo "the module still shows a certificate of del-key")"
    judge delete-sign-no-such-key "$(call_p sign-before ok "$(approve $RD_ACTION_SIGN)"
        call_p sign-after "$NO_SUCH_KEY" ''
        call_p sign-keep ok "$(approve $RD_ACTION_SIGN)")"
    # the files of the key were in the state directory before the delete (d2 differs from d1), and the directory after equals the one before the import (d1)
    judge delete-state-file-gone "$(ops_differ_problems "the import of del-key changed the state directory" "$RD/d1.state" "$RD/d2.state"
        ops_state_problems "state directory after the delete, compared with before the import" "$RD/d1.state" "$RD/d3.state")"
    judge delete-reimport "$(list_problems "$RD/d4.user" +del-key +del-keep
        call_p sign-reimport ok "$(approve $RD_ACTION_SIGN)"
        awk '{ print $NF }' "$RD/d2.state" > "$RD/d2.paths"
        awk '{ print $NF }' "$RD/d4.state" > "$RD/d4.paths"
        ops_state_problems "files with the key imported again, compared with the first import (paths)" "$RD/d2.paths" "$RD/d4.paths"
        ops_state_problems "state directory after the cleanup deletes" "$RD/d0.state" "$RD/d5.state")"
    ;;
*) fail "unknown group '$GROUP'" ;;
esac
ops_state_problems "the state directory after the step" "$RD/start.state" "$RD/end.state" > "$RD/end.problems"
if [ -s "$RD/end.problems" ]; then problems="$problems
end:
$(cat "$RD/end.problems")"; fi
[ -z "$problems" ] || fail "$GROUP cases:$problems"
echo "rd-run: $GROUP passed"
