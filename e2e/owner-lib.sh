# shellcheck shell=bash
# Sourced by owner.sh and owner-selftest.sh (F91): the judgements of the owner-* cases, as functions of the files the two user sessions leave. Each
# prints one problem per line and nothing when the evidence is right, so owner-selftest.sh can show that every judgement fails on bad input.
NO_SUCH_KEY="error com.rfirma.Custodio1.Error.NoSuchKey"
OWNER_CALLS="sign delete replace"

# call_problems FILE: FILE holds lines "foreign-CALL RESULT" and "control-CALL RESULT" (RESULT as owner-call.py prints it) for the three calls on
# another uid's id and on an id nobody has. Each must be NoSuchKey, so the pair is the same by construction and the control is what makes the
# match mean something (a control that failed otherwise would show the call, not the ownership, was wrong).
call_problems() {
    local file=$1 c kind got
    for c in $OWNER_CALLS; do
        for kind in foreign control; do
            got=$(grep -c "^$kind-$c " "$file" || true)
            if [ "$got" -ne 1 ]; then echo "$kind-$c: $got results, expected 1"; continue; fi
            got=$(sed -n "s/^$kind-$c //p" "$file")
            [ "$got" = "$NO_SUCH_KEY" ] || echo "$kind-$c: '$got', expected '$NO_SUCH_KEY'"
        done
        [ "$(sed -n "s/^foreign-$c //p" "$file")" = "$(sed -n "s/^control-$c //p" "$file")" ] || echo "$c: the call on the other uid's id differs from the call on the id nobody has"
    done
}

# count_problems WHAT BEFORE AFTER: a counter of a log (agent requests, journal entries) did not move between two readings, or is not a number
count_problems() {
    local what=$1 before=$2 after=$3
    case $before$after in '' | *[!0-9]*) echo "$what: not numbers: '$before' '$after'"; return ;; esac
    [ "$before" -eq "$after" ] || echo "$what: went from $before to $after"
}

# list_problems FILE ID...: FILE (custodio list) has a block for every ID given as "+ID" and none for an ID given as "-ID"
list_problems() {
    local file=$1 spec id
    shift
    for spec in "$@"; do
        id=${spec#?}
        if grep -qxF "id: $id" "$file"; then
            [ "${spec%"$id"}" = + ] || echo "$file lists $id"
        else
            [ "${spec%"$id"}" = - ] || echo "$file does not list $id"
        fi
    done
}

# verify_problems SIG DATA CERT: SIG is a SHA-256 signature of DATA by the key of the certificate CERT (DER)
verify_problems() {
    local sig=$1 data=$2 cert=$3 pub
    pub=$(mktemp)
    if ! openssl x509 -inform DER -in "$cert" -pubkey -noout > "$pub" 2> /dev/null; then rm -f "$pub"; echo "$cert: not a certificate"; return; fi
    openssl dgst -sha256 -verify "$pub" -signature "$sig" "$data" > /dev/null 2>&1 || echo "$sig does not verify against $cert"
    rm -f "$pub"
}
# verify_fails_problems SIG DATA CERT: the opposite
verify_fails_problems() {
    if [ -z "$(verify_problems "$@")" ]; then echo "$1 verifies against $3"; fi
}
