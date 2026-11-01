#!/usr/bin/env bash
# F63: the guest side of `just e2e-cases`, with no container: e2e/report.sh reports only the selected cases (case_run and case_skip of an unselected
# case print nothing), and e2e/select.sh decides which steps of guest.sh run for a selection. NOT checked here: a real guest (the verify of F63).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
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
        for p in user unavailable journal upgrade lifecycle refusal; do phase_runs "$p" && printf "%s " "$p"; done
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
want upgrade "upgrade " upgrade-keys-listed
want lifecycle "upgrade lifecycle " removal-service-stopped
want reinstall "upgrade lifecycle " reinstall-keys-listed
want purge "upgrade lifecycle " purge-account-kept
want old-modes-only "" upgrade-cargo-deb-keys-listed upgrade-oldpath-version-greater
want mixed "user upgrade " nss-deny upgrade-no-manual-step
want refusal "refusal " refusal-nothing-listens
all=$(cd "$ROOT" && grep -vh '^[[:space:]]*\(#\|$\)' e2e/cases.list e2e/targets/*/cases.list | sort -u)
# shellcheck disable=SC2086 # one id per word
want every-case "user unavailable journal upgrade lifecycle refusal " $all
# no selection file: everything runs, and a phase name that is none is refused
got=$(E2E_SELECT_FILE=$tmp/none bash -c 'source "$1/e2e/select.sh"; for p in user unavailable journal upgrade lifecycle refusal; do phase_runs "$p" && printf "%s " "$p"; done; true' _ "$ROOT")
[ "$got" = "user unavailable journal upgrade lifecycle refusal " ] || bad "no selection: the steps are '$got'"
if E2E_SELECT_FILE=$tmp/sel bash -c 'source "$1/e2e/select.sh"; phase_runs nonsense' _ "$ROOT" 2> /dev/null; then bad "an unknown phase was accepted"; fi
# every id of the lists belongs to a group, and each script that reports ids of one step is in that group
for id in $all; do
    g=$(bash -c 'source "$1/e2e/select.sh"; case_group "$2"' _ "$ROOT" "$id")
    case $g in user | unavailable | journal | upgrade | lifecycle | refusal | other-mode) ;; *) bad "$id: group '$g'" ;; esac
done
# the guest uses the decision: each step is behind phase_runs
for p in user unavailable journal upgrade lifecycle; do grep -q "phase_runs $p" "$ROOT/e2e/guest.sh" || bad "guest.sh does not ask phase_runs $p"; done
grep -q 'phase_runs refusal' "$ROOT/e2e/guest.sh" || bad "guest.sh does not ask phase_runs refusal"

exit "$fail"
