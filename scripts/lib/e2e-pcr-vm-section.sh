# shellcheck shell=bash
# shellcheck disable=SC2154,SC2086,SC2016,SC2015 # variables come from the sourcing test; the ids are words; stub text and sed programs are in single quotes
# Sourced by scripts/test-e2e-pcr.sh (F163): the VM sections (two halves around a power cycle; the driver with a stub vm.sh). Uses ROOT, tmp, bad of the caller.
# shellcheck disable=SC2086,SC2015,SC2016
# ---- F163: a VM run (E2E_VM=1) of pcr-run.sh on fixtures, in the two halves around a power cycle. The stub guest (scripts/lib/e2e-pcr-stub.py) is a TPM in a directory: PCRs that
# extend, a PolicyPCR object, a `cycle` that puts the PCRs back; alice signs with real openssl keys, the reader is the real one on synthetic stored records.
# shellcheck source=scripts/lib/e2e-vm-cred-fixtures.sh
source "$ROOT/scripts/lib/e2e-vm-cred-fixtures.sh"
E=$ROOT/e2e
STUB=$ROOT/scripts/lib/e2e-pcr-stub.py
cred "$tmp/ok.cred" ef4ac13679a9480ea7db68897f9f165d 0
cred "$tmp/pcrmask.cred" ef4ac13679a9480ea7db68897f9f165d 0x80
for k in pr-rsa pr-ec; do rec "$tmp/st-ok" $k 2 "$tmp/ok.cred"; done
rec "$tmp/st-pcr" pr-rsa 2 "$tmp/ok.cred"; rec "$tmp/st-pcr" pr-ec 2 "$tmp/pcrmask.cred"
mkdir -p "$tmp/st-none" "$tmp/stub"
for t in tpm2_pcrread tpm2_pcrextend tpm2_createprimary tpm2_create tpm2_load tpm2_unseal tpm2_startauthsession tpm2_policypcr tpm2_flushcontext systemctl busctl su; do
    printf '#!/usr/bin/env bash\nexec python3 -I -S %s %s "$@"\n' "$STUB" "$t" > "$tmp/stub/$t"
    chmod +x "$tmp/stub/$t"
done
# half NAME HALF TPM STATE [ENV=VAL...]: one invocation of pcr-run.sh (or $RUN_COPY) in the VM form; output $tmp/NAME.HALF.out, status $tmp/NAME.HALF.rc
half() {
    local n=$1 h=$2 m=$3 st=$4 w rc=0
    shift 4
    w=$tmp/v-$n
    mkdir -p "$w/stub" "$w/work"
    env PATH="$tmp/stub:$PATH" WORK="$w/work" MODULE=/nonexistent E2E_SELECT_FILE=/nonexistent E2E_VM=1 E2E_TPM="$m" PCR_HALF="$h" PCR_DIR="$w/pc" STUB_STATE="$w/stub" \
        BOOT_ID_FILE="$w/stub/boot" VM_STATE_DIR="$st" VM_CRED_DIR="$E/vm" VM_SYSTEMD_VERSION=259 "$@" bash "${RUN_COPY:-$E/pcr-run.sh}" > "$tmp/$n.$h.out" 2>&1 || rc=$?
    echo $rc > "$tmp/$n.$h.rc"
}
# scen NAME TPM STATE [ENV=VAL...]: first half, the power cycle (unless NOCYCLE), second half
scen() {
    local n=$1 m=$2 st=$3 w
    w=$tmp/v-$n
    mkdir -p "$w/stub"
    cat /proc/sys/kernel/random/uuid > "$w/stub/boot"
    shift 3
    half "$n" first "$m" "$st" "$@"
    [ -n "${NOCYCLE:-}" ] || env STUB_STATE="$w/stub" "$@" python3 -I "$STUB" cycle
    half "$n" second "$m" "$st" "$@"
}
# a copy of the runner without the reader call (the control: the failing reader is then ignored)
mkdir "$tmp/ctl"
cp "$E"/pcr-run.sh "$E"/pcr-vm.sh "$E"/pcr.py "$E"/pcr-cases.sh "$E"/report.sh "$E"/select.sh "$E"/tpmkind-lib.sh "$E"/tpm-lib.sh "$tmp/ctl/"
cp -r "$E/vm" "$tmp/ctl/vm"
# shellcheck disable=SC2016 # the pattern is literal text of the script
sed -i 's/vm_read_credential "\$id"/true/' "$tmp/ctl/pcr-vm.sh"
cmp -s "$E/pcr-vm.sh" "$tmp/ctl/pcr-vm.sh" && bad "the control copy of pcr-vm.sh without the reader call changes nothing"
export -f half scen
export tmp ROOT E STUB
scen full swtpm "$tmp/st-none" STUB_KIND=tpm &
scen lack lacking "$tmp/st-ok" STUB_KIND=encrypted-tpm &
scen full-etpm swtpm "$tmp/st-none" STUB_KIND=encrypted-tpm &
scen lack-tpm lacking "$tmp/st-ok" STUB_KIND=tpm &
scen lack-host lacking "$tmp/st-ok" STUB_KIND=encrypted-host &
scen lack-pcr lacking "$tmp/st-pcr" STUB_KIND=encrypted-tpm &
scen lack-nocred lacking "$tmp/st-none" STUB_KIND=encrypted-tpm &
RUN_COPY=$tmp/ctl/pcr-run.sh scen lack-noreader lacking "$tmp/st-pcr" STUB_KIND=encrypted-tpm &
scen noext swtpm "$tmp/st-none" STUB_NOEXTEND=1 &
scen nopid swtpm "$tmp/st-none" STUB_NOPID=1 &
scen badsig-ext swtpm "$tmp/st-none" STUB_BADSIG=ext &
scen sigfail-restart swtpm "$tmp/st-none" STUB_SIGFAIL=restart &
scen badsig-cycle swtpm "$tmp/st-none" STUB_BADSIG=cycle &
scen sigfail-cycle swtpm "$tmp/st-none" STUB_SIGFAIL=cycle &
scen drop-cycle swtpm "$tmp/st-none" STUB_DROPKEY=cycle &
scen kind-cycle swtpm "$tmp/st-none" STUB_KINDAFTER=cycle:encrypted-host &
scen cyc-keep swtpm "$tmp/st-none" STUB_CYCLE=keep &
scen cyc-other swtpm "$tmp/st-none" STUB_CYCLE=other &
scen cyc-sameboot swtpm "$tmp/st-none" STUB_CYCLE=sameboot &
NOCYCLE=1 scen nocycle swtpm "$tmp/st-none" &
scen unsealed swtpm "$tmp/st-none" STUB_UNSEALALWAYS=1 &
wait
r() { cat "$tmp/$1.$2.rc" 2> /dev/null || echo missing; }
ran() { grep -q "^E2E-CASE run $3\$" "$tmp/$1.$2.out"; }
good() { # NAME: both halves pass and report the three cases once
    [ "$(r "$1" first)" = 0 ] && [ "$(r "$1" second)" = 0 ] || { bad "VM $1: a good run fails ($(r "$1" first)/$(r "$1" second)): $(tail -n 3 "$tmp/$1.second.out" "$tmp/$1.first.out")"; return; }
    ran "$1" first pcr-extended-signs || bad "VM $1: the first half does not report pcr-extended-signs"
    ran "$1" second pcr-restarted-signs || bad "VM $1: the second half does not report pcr-restarted-signs"
    ran "$1" second pcr-signs-every-key || bad "VM $1: the second half does not report pcr-signs-every-key"
    [ "$(cat "$tmp/$1".{first,second}.out | grep -c '^E2E-CASE run ')" = 3 ] || bad "VM $1: the cases are not reported exactly once"
}
refused() { # NAME HALF CASE-THAT-MUST-NOT-RUN...: the half fails and the cases of the later judgement are not reported
    local n=$1 h=$2
    shift 2
    [ -s "$tmp/$n.$h.out" ] || { bad "VM $n: the $h half left no output (it did not run)"; return; }
    [ "$(r "$n" "$h")" != 0 ] || { bad "VM $n: the $h half passes on bad evidence"; return; }
    for c in "$@"; do ! ran "$n" "$h" "$c" || bad "VM $n: $c is reported run on bad evidence"; done
}
good full
good lack
grep -q '^reader: key pr-rsa' "$tmp/lack.first.out" || bad "VM lacking: the reader was not run on pr-rsa"
! grep -q '^reader:' "$tmp/full.first.out" || bad "VM full: the reader was called"
refused full-etpm first pcr-extended-signs   # the wrong kind in full
refused lack-tpm first pcr-extended-signs    # the wrong kind in lacking
refused lack-host first pcr-extended-signs
refused lack-pcr first                       # the credential is bound to a PCR: the reader refuses
grep -q 'did not pass the reader' "$tmp/lack-pcr.first.out" || bad "VM lacking: a failing reader is not named"
refused lack-nocred first                    # no stored credential
[ "$(r lack-noreader first)" = 0 ] || true   # (the control: see below)
grep -q '^reader:' "$tmp/lack-noreader.first.out" && bad "VM lacking: the control copy still calls the reader"
[ "$(r lack-noreader first)" = 0 ] || bad "VM lacking: the control copy without the reader call should pass the PCR-bound credential (the test would not see a missing call)"
refused noext first pcr-extended-signs
refused unsealed first pcr-extended-signs
refused badsig-ext first pcr-extended-signs
refused nopid first pcr-extended-signs
refused sigfail-restart first pcr-extended-signs
refused badsig-cycle second pcr-signs-every-key
refused sigfail-cycle second pcr-signs-every-key
refused drop-cycle second pcr-restarted-signs
refused kind-cycle second pcr-restarted-signs
refused cyc-keep second pcr-restarted-signs     # the extended PCRs are still in place
refused cyc-other second pcr-restarted-signs    # neither the extended values nor the first reading
refused cyc-sameboot second pcr-restarted-signs # the boot id did not change
refused nocycle second pcr-restarted-signs      # no cycle at all
# the second half alone has nothing to check
rm -rf "$tmp/v-alone"
half alone second swtpm "$tmp/st-none"
[ "$(r alone second)" != 0 ] || bad "VM: the second half passes without a first half"
# the container run is not touched: without E2E_VM the runner does not use pcr-vm.sh
grep -q 'E2E_VM' "$E/pcr-run.sh" || bad "pcr-run.sh does not dispatch on E2E_VM"
bash -n "$ROOT/e2e/pcr-vm.sh" || bad "pcr-vm.sh does not parse"
# ---- the driver (e2e/vm/run.sh) with a stub vm.sh: the guest runs twice around one power cycle when a pcr-* case is selected
STUB=$ROOT/scripts/lib/e2e-vm-stub
R=$tmp/droot
mkdir -p "$R/docs" "$R/scripts" "$R/crates/custodiod/src" "$tmp/dpk" "$tmp/dpkn"
cp -a "$ROOT/e2e" "$R/e2e"; find "$R/e2e" -name __pycache__ -prune -exec rm -rf {} +
cp "$ROOT/docs/audit.md" "$R/docs/"; cp "$ROOT"/scripts/check-no-plaintext.sh "$ROOT"/scripts/check_no_plaintext.py "$R/scripts/"
cp "$ROOT/crates/custodiod/src/app_id_source.rs" "$R/crates/custodiod/src/"
for v in 1.2.3:dpk 1.2.4:dpkn; do
    d=$tmp/b-${v%%:*}; mkdir -p "$d/DEBIAN"
    printf 'Package: custodio\nVersion: %s\nArchitecture: amd64\nMaintainer: t <t@example.org>\nDescription: fake\nDepends: libtss2-rc0t64\n' "${v%%:*}" > "$d/DEBIAN/control"
    dpkg-deb --root-owner-group -b "$d" "$tmp/${v##*:}/custodio_${v%%:*}_amd64.deb" > /dev/null
done
DRV=$R/e2e/vm/run.sh
# controls: a driver that never cycles; one that cycles before the first half
cp "$DRV" "$R/e2e/vm/run-nocycle.sh"; sed -i '/"\$VM_SH" cycle/d' "$R/e2e/vm/run-nocycle.sh"; cmp -s "$DRV" "$R/e2e/vm/run-nocycle.sh" && bad "driver control nocycle changes nothing"
cp "$DRV" "$R/e2e/vm/run-onehalf.sh"; sed -i 's/guest "E2E_PCR_HALF=second" "\$pcr_sel"/true/' "$R/e2e/vm/run-onehalf.sh"; cmp -s "$DRV" "$R/e2e/vm/run-onehalf.sh" && bad "driver control onehalf changes nothing"
dlaunch() { # NAME DRIVER MODE [VAR=VALUE...]
    local n=$1 drv=$2 mode=$3; shift 3
    mkdir -p "$tmp/d-$n/tmp" "$tmp/d-$n/vmdir" "$tmp/d-$n/out"
    (
        env STUB_LOG="$tmp/d-$n/log" STUB_VMDIR="$tmp/d-$n/vmdir" TMPDIR="$tmp/d-$n/tmp" E2E_OUT="$tmp/d-$n/out" STUB_CASES= \
            VM_SH="$STUB/vm.sh" VM_IMAGE_SH="$STUB/image.sh" VM_SWTPM="$STUB/swtpm" E2E_PACKAGES="$tmp/dpk" E2E_PACKAGES_NEXT="$tmp/dpkn" "$@" \
            bash "$drv" "$mode" "${SEL[@]}" > "$tmp/d-$n/out.txt" 2>&1 && echo 0 > "$tmp/d-$n/rc" || echo $? > "$tmp/d-$n/rc"
    ) &
}
SEL=()
dlaunch full "$DRV" full
dlaunch lacking "$DRV" lacking
dlaunch failfirst "$DRV" lacking STUB_FAIL_HALF=first
dlaunch failcycle "$DRV" lacking STUB_FAIL_CYCLE=1
dlaunch failsecond "$DRV" lacking STUB_FAIL_HALF=second
dlaunch nocycle "$R/e2e/vm/run-nocycle.sh" lacking
dlaunch onehalf "$R/e2e/vm/run-onehalf.sh" lacking
SEL=('sign-*')
dlaunch nopcr "$DRV" lacking
SEL=(pcr-restarted-signs)
dlaunch only "$DRV" full
wait
dr() { cat "$tmp/d-$1/rc" 2> /dev/null || echo none; }
dcount() { grep -c -- "$2" "$tmp/d-$1/log" || true; }
dorder() { # NAME: the first half, then one cycle, then the second half, then stop
    local f c s st
    f=$(grep -n 'E2E_PCR_HALF=first' "$tmp/d-$1/log" | head -n 1 | cut -d: -f1); c=$(grep -n '^vm cycle' "$tmp/d-$1/log" | head -n 1 | cut -d: -f1)
    s=$(grep -n 'E2E_PCR_HALF=second' "$tmp/d-$1/log" | head -n 1 | cut -d: -f1); st=$(grep -n '^vm stop' "$tmp/d-$1/log" | head -n 1 | cut -d: -f1)
    [ -n "$f" ] && [ -n "$c" ] && [ -n "$s" ] && [ -n "$st" ] && [ "$f" -lt "$c" ] && [ "$c" -lt "$s" ] && [ "$s" -lt "$st" ]
}
for m in full lacking; do
    [ "$(dr $m)" = 0 ] || bad "driver $m: exit $(dr $m): $(tail -n 3 "$tmp/d-$m/out.txt")"
    [ "$(dcount $m '^vm cycle')" = 1 ] || bad "driver $m: the guest was cycled $(dcount $m '^vm cycle') times, not once"
    dorder $m || bad "driver $m: the halves and the cycle are not in order"
    [ "$(dcount $m '^vm stop')" = 1 ] || bad "driver $m: stop is not called once"
    [ "$(grep -c '^step_pcr=' "$tmp/d-$m/out/vm.$m.record")" = 1 ] || bad "driver $m: the pcr step is not one entry in the record"
    grep -q '^step_cycle=' "$tmp/d-$m/out/vm.$m.record" || bad "driver $m: no time for the cycle"
    # the second invocation carries only the pcr cases, not the setup of the others
    sec=$(grep 'E2E_PCR_HALF=second' "$tmp/d-$m/log"); case $sec in *"sign-"*|*"noplain-"*|*"upgrade-"*) bad "driver $m: the second half selects other cases" ;; esac
    ! grep 'E2E_PCR_HALF=first' "$tmp/d-$m/log" | grep -q 'E2E_PCR_HALF=second' || bad "driver $m: both halves on one command"
    [ "$(grep -c 'apt-get install' "$tmp/d-$m/log")" = 2 ] || bad "driver $m: the install ran again after the cycle"
done
[ "$(dr only)" = 0 ] && [ "$(dcount only '^vm cycle')" = 1 ] && dorder only || bad "driver: a selection of one second-half case does not run both halves around one cycle"
[ "$(dr nopcr)" = 0 ] && [ "$(dcount nopcr '^vm cycle')" = 0 ] && ! grep -q 'E2E_PCR_HALF' "$tmp/d-nopcr/log" || bad "driver: a selection without a pcr case cycles or sets a half"
for n in failfirst failcycle failsecond; do
    [ "$(dr $n)" != 0 ] && [ "$(dr $n)" != none ] || bad "driver $n: the run did not fail"
    [ "$(dcount $n '^vm stop')" = 1 ] || bad "driver $n: the VM was not stopped once"
    [ -z "$(ls -A "$tmp/d-$n/tmp")" ] || bad "driver $n: temporary files are left"
done
[ "$(dcount failfirst '^vm cycle')" = 0 ] || bad "driver failfirst: the guest was cycled after a failed first half"
! grep -q 'E2E_PCR_HALF=second' "$tmp/d-failfirst/log" || bad "driver failfirst: the second half ran after a failed first half"
grep -q 'power cycle of the guest failed' "$tmp/d-failcycle/out.txt" || bad "driver failcycle: the failure is not named"
! grep -q 'E2E_PCR_HALF=second' "$tmp/d-failcycle/log" || bad "driver failcycle: the second half ran after a failed cycle"
# the controls are told apart
[ "$(dcount nocycle '^vm cycle')" = 0 ] && { dorder nocycle && bad "driver control nocycle: the order check passed"; }
[ "$(dr nocycle)" != 0 ] || true
dorder onehalf && bad "driver control onehalf: the order check passed without a second half"
# accounting: a pcr case skipped in a VM run is refused in both modes, even when a skip list names it
printf '%s\n' pcr-extended-signs pcr-restarted-signs pcr-signs-every-key > "$tmp/vmcases"
printf '%s: stub\n' pcr-extended-signs pcr-restarted-signs pcr-signs-every-key > "$tmp/vmskip"
: > "$tmp/vmnoskip"
for tm in swtpm lacking; do
    for id in $ids; do
        { for i in $ids; do if [ "$i" = "$id" ]; then echo "E2E-CASE skipped $i"; else echo "E2E-CASE run $i"; fi; done; } > "$tmp/vmout"
        CHECK_VM=1 CHECK_TPM_MODE=$tm bash "$ROOT/e2e/check-cases.sh" check "$tmp/vmcases" "$tmp/vmskip" "$tmp/vmout" > /dev/null 2>&1 && bad "VM $tm: $id skipped is accepted with a skip list entry"
    done
    # control: the same skipped line, in a container without a TPM (mode none), is accepted, so the refusals above are the VM rule's
    { echo "E2E-CASE skipped pcr-extended-signs"; echo "E2E-CASE skipped pcr-restarted-signs"; echo "E2E-CASE skipped pcr-signs-every-key"; } > "$tmp/vmout"
    [ "$tm" != swtpm ] || CHECK_TPM_MODE=none bash "$ROOT/e2e/check-cases.sh" check "$tmp/vmcases" "$tmp/vmskip" "$tmp/vmout" > /dev/null 2>&1 || bad "control: the skipped lines are not in the format of check-cases.sh"
    for i in $ids; do echo "E2E-CASE run $i"; done > "$tmp/vmout"
    CHECK_VM=1 CHECK_TPM_MODE=$tm bash "$ROOT/e2e/check-cases.sh" check "$tmp/vmcases" "$tmp/vmnoskip" "$tmp/vmout" > /dev/null 2>&1 || bad "VM $tm: all pcr cases run is refused"
done
exit "$fail"
