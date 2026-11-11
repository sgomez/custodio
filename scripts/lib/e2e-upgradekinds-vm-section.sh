# shellcheck shell=bash
# shellcheck disable=SC2154,SC2086,SC2016,SC2015 # variables come from the sourcing test; the ids are words; stub text and sed programs are in single quotes
# Sourced by scripts/test-e2e-upgradekinds.sh (F163): the VM section. Uses ROOT, tmp, D, ids, bad and the helpers mklist/round/entry of the caller.
# --- F163: a VM run (E2E_VM=1) of upgrade-kinds.sh. swtpm is vm-full (kind tpm), lacking is vm-lacking (kind encrypted-tpm and the reader on the credential of each seeded key before and after
# the upgrade); upgrade-kinds-tpmbound is reported run, not skipped. The reader is the real one on synthetic stored records (alice 1000: ec1, rsa1; bob 1001: bobonly, rsa1).
# shellcheck source=scripts/lib/e2e-vm-cred-fixtures.sh
source "$ROOT/scripts/lib/e2e-vm-cred-fixtures.sh"
cred "$tmp/ok.cred" ef4ac13679a9480ea7db68897f9f165d 0
cred "$tmp/pcrmask.cred" ef4ac13679a9480ea7db68897f9f165d 0x80
mkst() { # DIR BOBCRED: alice's two keys with ok.cred, bob's with BOBCRED (kind encrypted-tpm)
    rec "$1" ec1 2 "$tmp/ok.cred"; rec "$1" rsa1 2 "$tmp/ok.cred"
    mkdir -p "$1/1001"
    rec "$1.b" bobonly 2 "$2"; rec "$1.b" rsa1 2 "$2"
    mv "$1.b"/1000/* "$1/1001/"
}
mkst "$tmp/vst-ok" "$tmp/ok.cred"
mkst "$tmp/vst-pcr" "$tmp/pcrmask.cred"
mkdir -p "$tmp/vst-none"
mkdir "$tmp/vctl"
cp "$ROOT/e2e/report.sh" "$ROOT/e2e/select.sh" "$ROOT/e2e/upgradekinds.py" "$tmp/vctl/"
sed 's/vm_read_credential "\$key"/true/' "$ROOT/e2e/upgrade-kinds.sh" > "$tmp/vctl/upgrade-kinds.sh"
cmp -s "$tmp/vctl/upgrade-kinds.sh" "$ROOT/e2e/upgrade-kinds.sh" && bad "the control copy without the reader call changes nothing"
# runvm MODE KIND EVDIR STATE SCRIPT: all steps in the VM form, output $tmp/out
runvm() {
    local step
    rm -rf "$tmp/work/upgrade-acct/kinds"
    : > "$tmp/out"
    for step in "collect before" before reader "collect after" kept cursor "collect round" signs tpmbound; do
        env PATH="$tmp/bin:$PATH" EV="$3" WORK="$tmp/work" E2E_VM=1 E2E_TPM="$1" E2E_DIR="$ROOT/e2e" VM_STATE_DIR="$4" VM_CRED_DIR="$ROOT/e2e/vm" VM_SYSTEMD_VERSION=259 \
            bash "$5" $step >> "$tmp/out" 2>&1 || return 1
    done
}
for pair in swtpm:tpm:vst-none lacking:encrypted-tpm:vst-ok; do
    IFS=: read -r m k st <<< "$pair"
    ev=$tmp/vev-$m
    mkdir -p "$ev"
    for p in before after round; do mklist "$ev/$p" "$k"; done
    round "$k" > "$ev/journal.json"
    if runvm $m $k "$ev" "$tmp/$st" "$ROOT/e2e/upgrade-kinds.sh"; then
        for id in $ids; do grep -qx "E2E-CASE run $id" "$tmp/out" || bad "VM $m: $id is not reported run"; done
        [ "$(grep -c '^E2E-CASE' "$tmp/out")" = 4 ] || bad "VM $m: not exactly four cases reported"
    else
        bad "VM $m: good evidence stopped the run: $(tail -n 3 "$tmp/out")"
    fi
    # the kind of the other mode, in each phase, and the journal of another kind, stop the run
    other=$([ "$k" = tpm ] && echo encrypted-tpm || echo tpm)
    for pair2 in before:before after:kept round:signs; do
        rm -rf "$tmp/vev2"; cp -r "$ev" "$tmp/vev2"
        mklist "$tmp/vev2/${pair2%%:*}" "$other"
        ! runvm $m $k "$tmp/vev2" "$tmp/$st" "$ROOT/e2e/upgrade-kinds.sh" || bad "VM $m: the kind $other in ${pair2%%:*} did not stop the run"
    done
    rm -rf "$tmp/vev2"; cp -r "$ev" "$tmp/vev2"
    { entry 1000 rsa1 "$other"; round "$k" | sed 1d; } > "$tmp/vev2/journal.json"
    ! runvm $m $k "$tmp/vev2" "$tmp/$st" "$ROOT/e2e/upgrade-kinds.sh" || bad "VM $m: a journal entry of the other kind did not stop the run"
done
# lacking: a credential bound to a PCR (bob's) stops the run at the reader, with its reason; the control copy without the reader call does not see it
ev=$tmp/vev-lacking
! runvm lacking encrypted-tpm "$ev" "$tmp/vst-pcr" "$ROOT/e2e/upgrade-kinds.sh" || bad "VM lacking: a credential the reader refuses did not stop the run"
grep -q "bob's .* did not pass the reader" "$tmp/out" || bad "VM lacking: the failing reader is not named"
runvm lacking encrypted-tpm "$ev" "$tmp/vst-pcr" "$tmp/vctl/upgrade-kinds.sh" || bad "VM lacking: the control copy without the reader call should pass the refused credential"
# a missing credential (no records) stops the run in lacking
! runvm lacking encrypted-tpm "$ev" "$tmp/vst-none" "$ROOT/e2e/upgrade-kinds.sh" || bad "VM lacking: keys without stored credentials did not stop the run"
# full does not call the reader: records that the reader would refuse do not matter
runvm swtpm tpm "$tmp/vev-swtpm" "$tmp/vst-pcr" "$ROOT/e2e/upgrade-kinds.sh" || bad "VM full: the reader was called"
# a VM run with the mode none is refused; the container run still skips upgrade-kinds-tpmbound (above)
! runvm none encrypted-host "$tmp/ev-none" "$tmp/vst-none" "$ROOT/e2e/upgrade-kinds.sh" || bad "VM: mode none is accepted"
# accounting in a VM run: all four run is accepted, any skipped is refused even if a skip list names it
printf '%s: stub\n' $ids > "$tmp/vmskip"
for m in swtpm lacking; do
    CHECK_VM=1 CHECK_TPM_MODE=$m bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$D/skip.list" "$tmp/out-run" > /dev/null 2>&1 || bad "VM $m: four cases run are refused"
    ! CHECK_VM=1 CHECK_TPM_MODE=$m bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$tmp/vmskip" "$tmp/out-ok" > /dev/null 2>&1 || bad "VM $m: upgrade-kinds-tpmbound skipped is accepted"
done

# the owner of the state files in a VM is pinned to 65534 (docs/findings/F163.md): the judge accepts that owner and refuses another one
cat > "$tmp/own.good" <<'S'
d 65534 65534 700 - .
d 65534 65534 700 - ./1000
d 65534 65534 700 - ./4711
f 65534 65534 600 aaaa ./1000/ec1
f 65534 65534 600 bbbb ./1000/rsa1
f 65534 65534 600 cccc ./4711/bobonly
f 65534 65534 600 dddd ./4711/rsa1
S
(
    # shellcheck source=e2e/upgrade-accts-lib.sh
    source "$ROOT/e2e/upgrade-accts-lib.sh"
    [ -z "$(acct_state_problems "$tmp/own.good" 1000 4711 65534)" ] || bad "VM: the pinned owner 65534 is refused: $(acct_state_problems "$tmp/own.good" 1000 4711 65534 | head -n 1)"
    sed 's#^f 65534 65534 600 cccc#f 998 998 600 cccc#' "$tmp/own.good" > "$tmp/own.bad"
    acct_state_problems "$tmp/own.bad" 1000 4711 65534 | grep -q 'owned by 998, not custodio' || bad "VM: a key file of another owner than 65534 is accepted"
) || bad "VM: the owner fixture failed to run"
