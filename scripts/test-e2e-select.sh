#!/usr/bin/env bash
# F63: the guest side of `just e2e-cases`, with no container: e2e/report.sh reports only the selected cases (case_run and case_skip of an unselected
# case print nothing), and e2e/select.sh decides which steps of guest.sh run for a selection. NOT checked here: a real guest (the verify of F63).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export E2E_TARGET_DIR=$ROOT/e2e/targets/debian13 # the target whose own list owes the M4 cases
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-select: $*" >&2; fail=1; }

# reported SELECTION...: the output of case_run and case_skip for every id of cases.list, run by the code path of the normal run
reported() {
    if [ "$#" -gt 0 ]; then printf '%s\n' "$@" > "$tmp/sel"; else rm -f "$tmp/sel"; fi
    E2E_SELECT_FILE=$tmp/sel bash -c '
        source "$1/e2e/report.sh"
        while IFS= read -r id; do
            case $id in "" | "#"*) continue ;; esac
            case_run "$id"
        done < "$1/e2e/cases.list"
        case_skip upgrade-oldpath-keys-listed "no old path"
        case_skip nss-deny "no reason"' _ "$ROOT" | sed -n 's/^E2E-CASE //p' | sort | tr '\n' ' '
}
total=$(grep -vc '^[[:space:]]*\(#\|$\)' "$ROOT/e2e/cases.list")
[ "$(reported | wc -w)" -eq $(((total + 2) * 2)) ] || bad "no selection: not every case is reported: $(reported | wc -w)"
[ "$(reported nss-approve pkcs11-tool-deny)" = "run nss-approve run pkcs11-tool-deny " ] || bad "two selected cases: got '$(reported nss-approve pkcs11-tool-deny)'"
[ "$(reported nss-deny)" = "run nss-deny skipped nss-deny " ] || bad "a selected case is not reported by case_run and case_skip: '$(reported nss-deny)'"
[ "$(reported upgrade-oldpath-keys-listed)" = "run upgrade-oldpath-keys-listed skipped upgrade-oldpath-keys-listed " ] || bad "a selected skipped case: '$(reported upgrade-oldpath-keys-listed)'"
[ -z "$(reported no-such-case)" ] || bad "a selection of no case of the list reports something"
# a prefix is not a match
[ "$(reported nss)" = "" ] || bad "a prefix of an id selected it"
# the output of an unselected case is empty, not only the E2E-CASE line
out=$(E2E_SELECT_FILE=$tmp/sel bash -c 'source "$1/e2e/report.sh"; case_run other; case_skip other why' _ "$ROOT")
[ -z "$out" ] || bad "an unselected case printed '$out'"

# phase_runs SELECTION...: the steps of guest.sh that run
phases() {
    printf '%s\n' "$@" > "$tmp/sel"
    E2E_SELECT_FILE=$tmp/sel bash -c '
        source "$1/e2e/select.sh"
        for p in user unavailable journal owner ops-polkit replace delete journal-ops appid cli tpm-kind sign noplain tpmdup pcr fallback tpmfail tpmclear tpmslots journalkind upgrade lifecycle; do phase_runs "$p" && printf "%s " "$p"; done
        true' _ "$ROOT"
}
want() { # want NAME "PHASES" SELECTION...
    local n=$1 w=$2 got; shift 2
    got=$(phases "$@")
    [ "$got" = "$w" ] || bad "$n: the steps are '$got', expected '$w'"
}
want users "user " pkcs11-tool-approve-rsa nss-approve
want user-all "user " no-key-read composed-SHA256-RSA-PKCS provider-rsa1 login-deny journal-signatures
want unavailable "user unavailable " polkit-unavailable
want journal "user unavailable journal " journal-entries
want journal-catalog "user unavailable journal " journal-catalog
want owner "owner " owner-list-isolated
want owner-all "owner " owner-list-isolated owner-foreign-id-no-such-key owner-foreign-id-no-polkit owner-foreign-id-journal owner-same-id-own-key
want ops-polkit "ops-polkit " ops-polkit-denied
want ops-polkit-all "ops-polkit " ops-polkit-import-asks-once ops-polkit-delete-asks-once ops-polkit-replace-asks-once ops-polkit-denied ops-polkit-unavailable ops-polkit-asks-again ops-polkit-wrong-password-denied ops-polkit-wrong-password-approved
want replace "replace " replace-same-key
want replace-all "replace " replace-same-key replace-list-shows-new replace-module-shows-new replace-sign-verifies replace-different-key
want delete "delete " delete-list-absent
want delete-all "delete " delete-list-absent delete-module-no-token delete-sign-no-such-key delete-state-file-gone delete-reimport
want replace-and-delete "replace delete " replace-different-key delete-reimport
want replace-and-ops "ops-polkit replace " replace-same-key ops-polkit-denied
want ops-polkit-and-owner "owner ops-polkit " ops-polkit-asks-again owner-list-isolated
want owner-and-user "user owner " owner-same-id-own-key nss-approve
want journal-ops "journal-ops " journal-ops-sign
want journal-ops-all "journal-ops " journal-ops-sign journal-ops-import journal-ops-delete journal-ops-replace journal-ops-exactly-one journal-ops-no-secrets journal-ops-queries
want journal-ops-and-journal "user unavailable journal journal-ops " journal-entries journal-ops-queries
want journal-ops-not-signatures "user " journal-signatures
want delete-and-journal-ops "delete journal-ops " delete-reimport journal-ops-sign
want appid "appid " appid-flatpak
want appid-all "appid " appid-flatpak appid-flatpak-max appid-cap appid-operations appid-none appid-hostile appid-outcome appid-bound appid-queries
want appid-and-journal-ops "journal-ops appid " journal-ops-sign appid-none
want appid-not-user "user " pkcs11-tool-approve-rsa
want appid-and-upgrade "appid upgrade " appid-bound upgrade-keys-listed
want cli "cli " cli-list-keys
want cli-all "cli " cli-list-keys cli-list-none cli-delete-confirms cli-delete-declined-confirmation cli-delete-declined-polkit cli-no-agent-precondition cli-import-pkttyagent cli-import-pkttyagent-wrong-password cli-delete-pkttyagent
want cli-and-upgrade "cli upgrade " cli-delete-pkttyagent upgrade-keys-listed
want upgrade "upgrade " upgrade-keys-listed
want lifecycle "upgrade lifecycle " removal-service-stopped
want reinstall "upgrade lifecycle " reinstall-keys-listed
want purge "upgrade lifecycle " purge-account-kept
want old-modes-only "" upgrade-oldpath-version-greater
want mixed "user upgrade " nss-deny upgrade-no-manual-step
all=$(cd "$ROOT" && grep -vh '^[[:space:]]*\(#\|$\)' e2e/cases.list e2e/targets/*/cases.list | sort -u)
# shellcheck disable=SC2086 # one id per word
want every-case "user unavailable journal owner ops-polkit replace delete journal-ops appid cli tpm-kind sign noplain tpmdup pcr fallback tpmfail tpmclear tpmslots journalkind upgrade lifecycle " $all
# no selection file: everything runs, and a phase name that is none is refused
got=$(E2E_SELECT_FILE=$tmp/none bash -c 'source "$1/e2e/select.sh"; for p in user unavailable journal owner ops-polkit replace delete journal-ops appid cli tpm-kind sign noplain tpmdup pcr fallback tpmfail tpmclear tpmslots journalkind upgrade lifecycle; do phase_runs "$p" && printf "%s " "$p"; done; true' _ "$ROOT")
[ "$got" = "user unavailable journal owner ops-polkit replace delete journal-ops appid cli tpm-kind sign noplain tpmdup pcr fallback tpmfail tpmclear tpmslots journalkind upgrade lifecycle " ] || bad "no selection: the steps are '$got'"
if E2E_SELECT_FILE=$tmp/sel bash -c 'source "$1/e2e/select.sh"; phase_runs nonsense' _ "$ROOT" 2> /dev/null; then bad "an unknown phase was accepted"; fi
# every id of the lists belongs to a group, and each script that reports ids of one step is in that group
for id in $all; do
    g=$(bash -c 'source "$1/e2e/select.sh"; case_group "$2"' _ "$ROOT" "$id")
    case $g in user | unavailable | journal | owner | ops-polkit | replace | delete | journal-ops | appid | cli | tpm | tpm-kind | sign | noplain | tpmdup | pcr | fallback | tpmfail | tpmclear | tpmslots | journalkind | upgrade | lifecycle | other-mode) ;; *) bad "$id: group '$g'" ;; esac
done
# the guest uses the decision: each step is behind phase_runs
for p in user unavailable journal owner ops-polkit replace delete journal-ops appid cli tpm-kind sign noplain tpmdup pcr fallback tpmfail tpmclear tpmslots journalkind upgrade lifecycle; do grep -q "phase_runs $p" "$ROOT/e2e/guest.sh" || bad "guest.sh does not ask phase_runs $p"; done
# a target whose own list owes no M4 case does not run the M4 steps, with or without a selection (alma10 reported cases its accounting does not know)
for tgt in alma10 "$tmp/no-such-dir"; do
    for sel in none "$tmp/sel"; do
        got=$(E2E_TARGET_DIR=$ROOT/e2e/targets/$tgt E2E_SELECT_FILE=$sel bash -c 'source "$1/e2e/select.sh"; for p in tpm-kind sign noplain tpmdup pcr fallback tpmfail tpmclear tpmslots journalkind user; do phase_runs "$p" && printf "%s " "$p"; done; true' _ "$ROOT")
        case $sel in none) [ "$got" = "user " ] || bad "target $tgt, no selection: the steps are '$got', expected only 'user '" ;; *) [ -z "${got//user /}" ] || bad "target $tgt: M4 steps run: '$got'" ;; esac
    done
done
[ -d "$ROOT/e2e/targets/alma10" ] && [ ! -f "$ROOT/e2e/targets/alma10/cases.list" ] || bad "alma10 now has its own list: this control needs another target"

exit "$fail"
