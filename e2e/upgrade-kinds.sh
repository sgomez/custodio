#!/usr/bin/env bash
# The kinds part of the upgrade case (F141, acceptance 5 of SPEC.md, second part), run as root by upgrade.sh. It rides on the keys that upgrade-accts.sh seeds
# (alice: ec1, rsa1; bob: bobonly, rsa1): the kind of each is the mode's, judged by upgradekinds.py, before the install, after it and after the signing round.
#   upgrade-kinds.sh enabled ID    exit 0 when the kinds cases are reported here: ID is "upgrade" (the N to N+1 run, not the old-path one), the target lists
#                                  upgrade-kinds-before in its cases.list (the kind depends on the TPM, not on the distribution), and a kinds case is selected
#   upgrade-kinds.sh collect PHASE each user's ListKeys and `custodio list` into $WORK/upgrade-acct/kinds/PHASE (before | after | round); no polkit call
#   upgrade-kinds.sh before        judges PHASE before, reports upgrade-kinds-before
#   upgrade-kinds.sh kept          judges before against after, reports upgrade-kinds-kept
#   upgrade-kinds.sh cursor        records the journal position just before the signing round
#   upgrade-kinds.sh signs         judges the journal entries since the cursor and the listing of PHASE round against before, reports upgrade-kinds-signs
#   upgrade-kinds.sh reader        (VM, lacking) the reader of F157 on the credential of each seeded key; a failing reader stops the run; nothing in the other modes
#   upgrade-kinds.sh tpmbound      container: reports upgrade-kinds-tpmbound skipped (deviation F134); VM: the reader once more, after the upgrade, and reports it run
# Needs WORK; E2E_TPM is the mode (default swtpm); E2E_TARGET_DIR is where the target's cases.list is (default /e2e-target).
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
: "${WORK:?}"
mode=${E2E_TPM:-swtpm}
# F163: in a VM run (E2E_VM=1) the TPM is the VM's own: swtpm is the full mode (kind tpm), lacking the lacking mode (kind encrypted-tpm, and `reader` reads each credential, F157)
vm=${E2E_VM:-}
if [ -n "$vm" ]; then
    case $mode in
    swtpm) mode='vm-full' ;;
    lacking) mode='vm-lacking' ;;
    *) fail "a VM run has the TPM mode swtpm or lacking, not '$mode'" ;;
    esac
fi
ACC=$WORK/upgrade-acct
K=$ACC/kinds
uk() { python3 -I "$here/upgradekinds.py" "$@"; }
# judged CASE PROBLEMS: report the case when the judgement printed nothing
judged() {
    local p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    [ -z "$p" ] || { printf '%s\n' "$p" >&2; fail "$1: the kinds are not right (see above)"; }
    case_run "$1"
}

reader() { # the credential of every seeded key passes the reader (lacking in a VM only)
    [ "$mode" = vm-lacking ] || return 0
    # shellcheck source=e2e/vm/cred-lib.sh
    source "${E2E_DIR:-/e2e}/vm/cred-lib.sh"
    local user key
    for user in alice bob; do
        for key in $(uk keys "$user"); do
            vm_read_credential "$key" "$(id -u "$user")" > /dev/null || fail "the credential of $user's $key did not pass the reader"
        done
    done
}

case ${1:-} in
enabled)
    [ "${2:-}" = upgrade ] || exit 1
    grep -qx upgrade-kinds-before "${E2E_TARGET_DIR:-/e2e-target}/cases.list" 2> /dev/null || exit 1
    for c in $(uk cases); do selected "$c" && exit 0; done
    exit 1
    ;;
collect)
    phase=${2:?}
    [[ $phase =~ ^(before|after|round)$ ]] || fail "bad phase '$phase'"
    mkdir -p "$K/$phase"
    chmod 1777 "$K" "$K/$phase"
    for u in alice bob; do
        timeout 300 su -l "$u" -c "WORK=$WORK MODULE=${MODULE:-} bash /e2e/upgrade-accts-user.sh kinds $phase" > "$K/$phase/$u.out" 2>&1 \
            || { cat "$K/$phase/$u.out" >&2; fail "$u: the kinds listing ($phase) failed"; }
    done
    ;;
before)
    p=$(uk listing "$mode" "$K/before") || fail "upgrade-kinds-before: the judgement did not run"
    judged upgrade-kinds-before "$p"
    ;;
kept)
    p=$(uk kept "$mode" "$K/before" "$K/after") || fail "upgrade-kinds-kept: the judgement did not run"
    judged upgrade-kinds-kept "$p"
    ;;
cursor)
    journalctl --sync
    journalctl -n1 --show-cursor --no-pager | sed -n 's/^-- cursor: //p' > "$K/cursor"
    [ -s "$K/cursor" ] || fail "no journal cursor"
    ;;
signs)
    [ -s "$K/cursor" ] || fail "the journal cursor was not taken before the round"
    journalctl --sync
    journalctl --after-cursor="$(cat "$K/cursor")" _SYSTEMD_UNIT=custodio.service -o json --no-pager > "$K/journal.json"
    # one entry per Sign call, and every call asks the user's agent once: alice's two agents (the direct round and upgrade-accts.sh's) and bob's
    requests=0
    for log in "$WORK/agent-upgrade/requests" "$ACC/agent-alice/requests" "$ACC/agent-bob/requests"; do
        [ -f "$log" ] || fail "no agent log $log"
        requests=$((requests + $(wc -l < "$log")))
    done
    read -r ua ub _ <<< "$(id -u alice) $(id -u bob)"
    p=$(uk journal "$mode" "$K/journal.json" "$ua" "$ub" "$requests") || fail "upgrade-kinds-signs: the journal judgement did not run"
    q=$(uk kept "$mode" "$K/before" "$K/round") || fail "upgrade-kinds-signs: the listing judgement did not run"
    judged upgrade-kinds-signs "$p
$q"
    ;;
reader) reader ;;
tpmbound)
    if [ -n "$vm" ]; then
        reader
        case_run upgrade-kinds-tpmbound
        exit 0
    fi
    case_skip upgrade-kinds-tpmbound "the container cannot make the kind encrypted-tpm (SPEC_DEVIATIONS.md F134); the kinds, owners and certificates surviving a store opened again over one state directory are covered by the custodiod integration test state_format reload (cargo test -p custodiod --test state_format reload), not an end-to-end proof"
    ;;
*) fail "usage: upgrade-kinds.sh enabled ID | collect PHASE | before | kept | cursor | signs | reader | tpmbound" ;;
esac
