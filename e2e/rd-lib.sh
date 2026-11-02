# shellcheck shell=bash
# Sourced by rd-run.sh and rd-selftest.sh (F93): the judgements of the replace-* and delete-* cases, as functions of the files alice's session leaves. Each prints one
# problem per line and nothing when the evidence is right, so rd-selftest.sh can show that every judgement fails on bad evidence. The call record, state snapshots,
# list and signature judgements are those of ops-lib.sh and owner-lib.sh (sourced here).
# shellcheck source=e2e/ops-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/ops-lib.sh"
# shellcheck source=e2e/owner-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/owner-lib.sh"
# shellcheck disable=SC2034 # used by the scripts that source this file
RD_MISMATCH="error com.rfirma.Custodio1.Error.CertificateMismatch"
# shellcheck disable=SC2034
RD_ACTION_SIGN=com.rfirma.custodio.sign

# rd_sha_problems LABEL FILE WANT-FILE: the bytes of FILE are exactly those of WANT-FILE, and not empty (the certificate the module shows is the expected one)
rd_sha_problems() {
    [ -s "$2" ] || { echo "$1: $2 is empty or missing"; return; }
    [ -s "$3" ] || { echo "$1: $3 is empty or missing"; return; }
    same_file "$2" "$3" || echo "$1: $2 is not the certificate in $3"
}
# rd_not_sha_problems LABEL FILE OTHER-FILE: FILE is not OTHER-FILE (but exists)
rd_not_sha_problems() {
    [ -s "$2" ] || { echo "$1: $2 is empty or missing"; return; }
    [ -s "$3" ] || { echo "$1: $3 is empty or missing"; return; }
    if same_file "$2" "$3"; then echo "$1: $2 is the same certificate as $3"; fi
}
# rd_subject_problems LISTFILE ID WANT UNWANTED: the block of ID in `custodio list` has a subject line with WANT and without UNWANTED (the two must not contain each other)
rd_subject_problems() {
    local subject
    subject=$(awk -v id="id: $2" '$0 == id { on = 1; next } /^id: / { on = 0 } on && /^  subject: / { print }' "$1")
    [ -n "$subject" ] || { echo "$1: no subject line for $2"; return; }
    case $subject in *"$3"*) ;; *) echo "$2: subject '$subject' lacks '$3'" ;; esac
    case $subject in *"$4"*) echo "$2: subject '$subject' has '$4'" ;; esac
}
# rd_token_problems SLOTS-FILE +ID|-ID...: the output of `pkcs11-tool --list-token-slots` has (+) or has no (-) token with the label ID, judged on the "token label" lines
# of the output, not on an exit status (which is non-zero also when the module fails to load: an output with no token at all proves nothing, so one + is needed)
rd_token_problems() {
    local file=$1 spec id any=0
    shift
    grep -q 'token label' "$file" || { echo "$file: no token label at all (module not loaded?)"; return; }
    for spec in "$@"; do
        id=${spec#?}
        if grep -qE "^[[:space:]]*token label[[:space:]]*:[[:space:]]*${id}[[:space:]]*\$" "$file"; then
            [ "${spec%"$id"}" = + ] || echo "$file has a token for $id"
        else
            [ "${spec%"$id"}" = - ] || echo "$file has no token for $id"
        fi
        [ "${spec%"$id"}" = + ] && any=1
    done
    [ "$any" -eq 1 ] || echo "$file: no + token given: a missing token proves nothing without one that is there"
}
