# shellcheck shell=bash
# Sourced by report.sh and guest.sh: which cases of the suite a run was asked for (F63, `just e2e-cases`). The guest writes the selection, one
# case id per line, to E2E_SELECT_FILE (default /run/custodio-e2e-select), a file because `su -l` drops the environment; with no such file every case
# is selected (`just e2e`). `selected ID` says whether a case is selected; `phase_runs PHASE` whether a step of guest.sh runs at all.
E2E_SELECT_FILE=${E2E_SELECT_FILE:-/run/custodio-e2e-select}

selected() { [ ! -f "$E2E_SELECT_FILE" ] || grep -qxF -- "$1" "$E2E_SELECT_FILE"; }

# case_group ID: the step of guest.sh that reports a case
case_group() {
    case $1 in
    polkit-unavailable) echo unavailable ;;
    journal-entries | journal-catalog) echo journal ;;
    upgrade-oldpath-*) echo other-mode ;; # reported by its own guest run (oldpath)
    upgrade-*) echo upgrade ;;
    removal-* | reinstall-* | purge-*) echo lifecycle ;;
    owner-*) echo owner ;;
    ops-polkit-*) echo ops-polkit ;;
    replace-*) echo replace ;;
    delete-*) echo delete ;;
    journal-ops-*) echo journal-ops ;;
    appid-*) echo appid ;;
    cli-*) echo cli ;;
    tpm-kind-*) echo tpm-kind ;;
    sign-*) echo sign ;;
    noplain-*) echo noplain ;;
    tpm-dup-*) echo tpmdup ;;
    pcr-*) echo pcr ;;
    fallback-*) echo fallback ;;
    tpmfail-*) echo tpmfail ;;
    tpm-clear-*) echo tpmclear ;; # before tpm-*, which the end of guest.sh reports
    tpm-*) echo tpm ;; # reported by the end of guest.sh, whose TPM setup always runs
    refusal-*) echo refusal ;;
    *) echo user ;;
    esac
}

# selected_in GROUP: some selected case is reported by GROUP
selected_in() {
    local id
    while IFS= read -r id; do
        [ -n "$id" ] || continue
        [ "$(case_group "$id")" = "$1" ] && return 0
    done < "$E2E_SELECT_FILE"
    return 1
}

# phase_runs PHASE: whether a step runs. A step that only unselected cases need does not; a step a selected case needs for its state does, and
# reports nothing of what is not selected. user: the signatures (the agent, the evidence, the ledger of the journal check); unavailable: needs
# the signatures' evidence; journal: counts every signature and the unavailable one; upgrade: lifecycle starts from the state it leaves;
# owner (F91): its own cases, with two accounts and keys of its own; it needs only the setup, and runs after journal so that the counts
# of the journal step do not see it; ops-polkit (F92): the same, it imports, deletes and replaces for real and stops polkit for a while, so it runs
# after owner and before upgrade; replace, delete (F93): the same, each with keys of its own, after ops-polkit; journal-ops (F94): the same, with the journal of every operation, after delete; appid (F95): the same, with callers in scopes of alice's user manager, after journal-ops; cli (F97): the same, with the CLI on a pseudo-terminal and a second account, after appid; tpm-kind (F133): the same, with an RSA and a P-256 key and the kind they get, after cli; sign (F134): the same, with an RSA and a P-256 key and every mechanism, after tpm-kind; noplain (F135): the same, with an RSA and a P-256 key and the state directory scanned for their plaintext, after sign; tpmdup (F136): the same, with an RSA and a P-256 key and the stored records read with tpm2-tools, a second swtpm started, after noplain; pcr (F137): the same, with an RSA and a P-256 key, PCRs extended and the TPM and the service restarted, after tpmdup; fallback (F138): the same, with an RSA and a P-256 key and what `custodio import` and `custodio list` say about their kind, after pcr; tpmfail (F139): the same, with an RSA key and the TPM and the credential service made to fail, after fallback; tpmclear (F140): the same, with an RSA and a P-256 key on a second swtpm that is cleared, after tpmfail; lifecycle, refusal: their own cases.
phase_runs() {
    [ -f "$E2E_SELECT_FILE" ] || return 0
    case $1 in
    user) selected_in user || selected_in unavailable || selected_in journal ;;
    unavailable) selected_in unavailable || selected_in journal ;;
    journal) selected_in journal ;;
    owner) selected_in owner ;;
    ops-polkit) selected_in ops-polkit ;;
    replace) selected_in replace ;;
    delete) selected_in delete ;;
    journal-ops) selected_in journal-ops ;;
    appid) selected_in appid ;;
    cli) selected_in cli ;;
    tpm-kind) selected_in tpm-kind ;;
    sign) selected_in sign ;;
    noplain) selected_in noplain ;;
    tpmdup) selected_in tpmdup ;;
    pcr) selected_in pcr ;;
    fallback) selected_in fallback ;;
    tpmfail) selected_in tpmfail ;;
    tpmclear) selected_in tpmclear ;;
    upgrade) selected_in upgrade || selected_in lifecycle ;;
    lifecycle) selected_in lifecycle ;;
    refusal) selected_in refusal ;;
    *) echo "select.sh: unknown phase '$1'" >&2; return 2 ;;
    esac
}
