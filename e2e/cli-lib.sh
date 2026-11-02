# shellcheck shell=bash
# Sourced by cli-run.sh and cli-selftest.sh (F97, acceptance 11 of SPEC.md): the judgements of the cli-* cases, as functions of the files the sessions leave. Each prints
# one problem per line and nothing when the evidence is right, so cli-selftest.sh can show that every judgement fails on bad evidence. The list, state, call and token
# judgements are those of ops-lib.sh and rd-lib.sh (sourced here).
# shellcheck source=e2e/rd-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/rd-lib.sh"
# shellcheck disable=SC2034 # used by the scripts that source this file
CLI_ACTION_DELETE=com.rfirma.custodio.delete-certificate
# shellcheck disable=SC2034
CLI_ACTION_IMPORT=com.rfirma.custodio.import-certificate

# cli_list_block_problems LISTFILE ID TYPE SUBJECT ENDDATE: the block of ID in `custodio list` has exactly this type, the subject line `subject: SUBJECT` and the line
# `valid until: ENDDATE` (all taken from OpenSSL on the key and certificate that were imported, not from what the CLI might print for every key)
cli_list_block_problems() {
    local file=$1 id=$2 block
    block=$(awk -v id="id: $id" '$0 == id { on = 1; print; next } /^id: / { on = 0 } on { print }' "$file")
    [ -n "$block" ] || { echo "$file: no block for $id"; return; }
    printf '%s\n' "$block" | grep -qxF "  type: $3" || echo "$id: the block has no line '  type: $3': $(printf '%s' "$block" | tr '\n' '|')"
    printf '%s\n' "$block" | grep -qxF "  subject: $4" || echo "$id: the block has no line '  subject: $4'"
    printf '%s\n' "$block" | grep -qxF "  valid until: $5" || echo "$id: the block has no line '  valid until: $5'"
}
# cli_list_only_problems LISTFILE ID...: the ids listed are exactly these (no other key, e.g. another account's)
cli_list_only_problems() {
    local file=$1 want got
    shift
    want=$(printf '%s\n' "$@" | sort)
    got=$(sed -n 's/^id: //p' "$file" | sort)
    [ "$want" = "$got" ] || echo "$file lists '$(printf '%s' "$got" | tr '\n' ' ')', expected '$(printf '%s' "$want" | tr '\n' ' ')'"
}
# cli_none_problems LISTFILE EXIT: the list of an account with no keys: exit 0, the sentence, no key block
cli_none_problems() {
    [ "$2" = 0 ] || echo "the list of an account with no keys exited $2, expected 0"
    grep -qxF 'You have no keys in the custodio service.' "$1" || echo "$1 does not say that there are no keys"
    ! grep -q '^id: ' "$1" || echo "$1 shows a key block although the account has none"
}
# cli_has_keys_problems LISTFILE: the list is not the none sentence (the control that the other account's list is not empty at the same time)
cli_has_keys_problems() {
    grep -q '^id: ' "$1" || echo "$1 shows no key: the none case proves nothing without a non-empty list beside it"
    ! grep -qF 'You have no keys' "$1" || echo "$1 says there are no keys"
}
# cli_confirm_problems TRANSCRIPT EVENTS: the confirmation question (it says the key cannot be recovered) is in the transcript, and the agent had logged no request when the
# question was shown (EVENTS: "expect<TAB>PATTERN<TAB>requests=N", one line per prompt the driver saw)
cli_confirm_problems() {
    grep -qF 'cannot be recovered' "$1" || echo "$1: the confirmation question (cannot be recovered) is not in the output"
    awk -F'\t' '$1 == "expect" && $2 ~ /recovered/ { found = 1; if ($3 != "requests=0" && $3 != "requests=-") bad = $3 } END { if (!found) print "the driver never saw the question"; else if (bad != "") print "polkit was asked before the confirmation was answered (" bad ")" }' "$2"
}
# cli_agent_prompt_problems TRANSCRIPT EVENTS ACTION ACCOUNT: pkttyagent asked: its header names the ACTION and the account, and the driver saw the account's password prompt
cli_agent_prompt_problems() {
    grep -qF "AUTHENTICATING FOR $3" "$1" || echo "$1: no pkttyagent header for $3"
    grep -qiE "authenticating as:.*\\($4\\)|authenticating as:.*\\b$4\\b" "$1" || echo "$1: the pkttyagent prompt does not name the account $4"
    awk -F'\t' '$1 == "expect" && $2 ~ /Password:/ { found = 1 } END { if (!found) print "the driver never saw the account password prompt" }' "$2"
}
# cli_no_leftover_problems LABEL FILE; cli_no_test_agent_problems FILE: the listing of the account's processes has no pkttyagent / no test agent
cli_no_leftover_problems() {
    [ -f "$2" ] || { echo "$1: no process listing"; return; }
    ! grep -qE 'pkttyagent' "$2" || echo "$1: a pkttyagent is left: $(grep pkttyagent "$2" | head -n 1)"
}
cli_no_test_agent_problems() {
    [ -f "$1" ] || { echo "no process listing"; return; }
    ! grep -qE 'agent\.py' "$1" || echo "a test agent runs: $(grep 'agent\.py' "$1" | head -n 1)"
}
# cli_no_secret_problems JOURNAL SECRET...: none of the secrets is in the journal text
cli_no_secret_problems() {
    local file=$1 s
    shift
    [ -s "$file" ] || { echo "$file: empty journal: nothing is proven"; return; }
    for s in "$@"; do ! grep -qF -- "$s" "$file" || echo "$file holds a secret"; done
}
# cli_events_problems EVENTS: the driver found every prompt it was told to wait for ("missing" lines are prompts that did not come)
cli_events_problems() {
    [ -f "$1" ] || { echo "$1: no events file"; return; }
    ! grep -q '^missing' "$1" || echo "$1: a prompt did not come: $(grep '^missing' "$1" | cut -f2 | head -n 1)"
}
# cli_state_key_problems STATE ID present|absent: the state snapshot (snapshot_state lines, path last) holds, or holds no, file of the key ID
cli_state_key_problems() {
    local n
    n=$(grep -cE "/$2(-cert)?\$" "$1" || true)
    case $3 in
    present) [ "$n" -gt 0 ] || echo "$1: no file of the key $2" ;;
    absent) [ "$n" -eq 0 ] || echo "$1: $n files of the key $2 are left" ;;
    esac
}
# cli_state_only_problems BEFORE AFTER ID: AFTER is BEFORE without the files of ID, and not empty (the other keys' files are unchanged)
cli_state_only_problems() {
    [ -s "$2" ] || { echo "$2: the snapshot is empty or missing"; return; }
    grep -vE "/$3(-cert)?\$" "$1" | cmp -s - "$2" || echo "$2 is not $1 without the files of $3"
}
# cli_pam_problems FILE: the PAM file of service polkit-1 as it was while the pkttyagent cases ran: it checks the password (pam_unix) and does not accept anything
cli_pam_problems() {
    [ -s "$1" ] || { echo "$1: no PAM file recorded"; return; }
    grep -qE '^auth[[:space:]]+(required|requisite)[[:space:]]+pam_unix\.so' "$1" || echo "$1: the auth stack does not use pam_unix"
    ! grep -qE 'pam_permit' "$1" || echo "$1: the stack accepts any password (pam_permit)"
}
# cli_exit_problems LABEL EXIT: the exit status is 0
cli_exit_problems() { [ "$2" = 0 ] || echo "$1 exited $2, expected 0"; }
# cli_no_token_problems FILE ID: the output of `pkcs11-tool --list-token-slots` shows no token ID, and is not the output of a module that failed to load (non-empty, no error text)
cli_no_token_problems() {
    [ -s "$1" ] || { echo "$1: empty output: nothing is proven"; return; }
    ! grep -qiE 'failed|error|cannot' "$1" || echo "$1: the module failed: $(grep -iE 'failed|error|cannot' "$1" | head -n 1)"
    ! grep -qE "^[[:space:]]*token label[[:space:]]*:[[:space:]]*$2[[:space:]]*\$" "$1" || echo "$1 has a token for $2"
}
# cli_agent_outcome_problems TRANSCRIPT complete|failed: pkttyagent ended the authentication as the case expects (its own banner)
cli_agent_outcome_problems() {
    case $2 in
    complete) grep -qF '==== AUTHENTICATION COMPLETE ====' "$1" || echo "$1: pkttyagent did not complete the authentication" ;;
    failed)
        grep -qF '==== AUTHENTICATION FAILED ====' "$1" || echo "$1: pkttyagent did not report a failed authentication"
        ! grep -qF '==== AUTHENTICATION COMPLETE ====' "$1" || echo "$1: pkttyagent completed the authentication" ;;
    esac
}
