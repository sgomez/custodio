# shellcheck shell=bash
# Sourced by ops-run.sh and ops-selftest.sh (F92): the judgements of the ops-polkit-* cases, as functions of the files the user session leaves. Each prints
# one problem per line and nothing when the evidence is right, so ops-selftest.sh can show that every judgement fails on bad evidence.
# The call record (ops-user.sh): one line per call, "LABEL<TAB>RESULT<TAB>LOGGED". RESULT is what owner-call.py printed ("ok" or "error NAME"), or for the CLI
# "ok", "cli-denied" (non-zero exit and "not authorized" in its output) or "cli-failed". LOGGED is the lines the agent's request log gained during the
# call, "<mode> <action>" joined by ";" (empty: none).
# shellcheck disable=SC2034 # used by the scripts that source this file
# shellcheck source=e2e/same-file.sh
source "$(dirname "${BASH_SOURCE[0]}")/same-file.sh"
OPS_DENIED="error com.rfirma.Custodio1.Error.PolkitDenied"
OPS_UNAVAILABLE="error com.rfirma.Custodio1.Error.AuthorizationUnavailable"
OPS_WRONG_PASSWORD="error com.rfirma.Custodio1.Error.WrongPasswordOrBadP12"
OPS_ACTION_IMPORT=com.rfirma.custodio.import-certificate
OPS_ACTION_DELETE=com.rfirma.custodio.delete-certificate
OPS_ACTION_REPLACE=com.rfirma.custodio.replace-certificate

# ops_call_problems FILE LABEL RESULT LOGGED: (RESULT '*' leaves the result unjudged: asks-again judges the count of the first call only) the one call LABEL of FILE has exactly this result, and the agent logged exactly these lines for it (so the number
# of requests and the action of each are judged together: zero or two lines, or the line of another action, are problems)
ops_call_problems() {
    local file=$1 label=$2 result=$3 logged=$4 n got
    n=$(awk -F'\t' -v l="$label" '$1 == l' "$file" | wc -l)
    if [ "$n" -ne 1 ]; then echo "$label: $n records, expected 1"; return; fi
    got=$(awk -F'\t' -v l="$label" '$1 == l { print $2 }' "$file")
    [ "$result" = '*' ] || [ "$got" = "$result" ] || echo "$label: result '$got', expected '$result'"
    got=$(awk -F'\t' -v l="$label" '$1 == l { print $3 }' "$file")
    [ "$got" = "$logged" ] || echo "$label: the agent logged '$got', expected '$logged'"
}

# ops_state_problems LABEL BEFORE AFTER: the snapshots (files with the same content) are equal, and not empty (an empty snapshot proves nothing)
ops_state_problems() {
    local label=$1 before=$2 after=$3
    [ -s "$before" ] || { echo "$label: the snapshot before is empty or missing"; return; }
    [ -s "$after" ] || { echo "$label: the snapshot after is empty or missing"; return; }
    same_file "$before" "$after" || echo "$label: the state changed: $(diff "$before" "$after" | head -n 4 | tr '\n' '|')"
}

# ops_listed_problems FILE ID...: "+ID" must be listed in the snapshot (custodio list part: a line "id: ID"), "-ID" must not
ops_listed_problems() {
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

# ops_differ_problems LABEL A B: the two snapshots differ (the replace changed the certificate shown)
ops_differ_problems() {
    if same_file "$2" "$3"; then echo "$1: the snapshot did not change"; fi
}
