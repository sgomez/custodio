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
# lifecycle, refusal: their own cases.
phase_runs() {
    [ -f "$E2E_SELECT_FILE" ] || return 0
    case $1 in
    user) selected_in user || selected_in unavailable || selected_in journal ;;
    unavailable) selected_in unavailable || selected_in journal ;;
    journal) selected_in journal ;;
    upgrade) selected_in upgrade || selected_in lifecycle ;;
    lifecycle) selected_in lifecycle ;;
    refusal) selected_in refusal ;;
    *) echo "select.sh: unknown phase '$1'" >&2; return 2 ;;
    esac
}
