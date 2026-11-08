#!/usr/bin/env bash
# F137: container-free checks of the pcr-* cases: the placement (debian13 list and skip list, group), the accounting (a skip refused in swtpm and lacking, accepted in none), the
# judgements of e2e/pcr.py on good and bad evidence (PCRs not changed by the extension, PCRs not reset by the restart, an unchanged service pid, a signature that does not verify,
# a signing refusal, a kind that changed, a missing key, fewer than two tpm keys, a control that proves nothing), and the restart helper's mode check. NOT checked here: a real
# run (`just e2e-cases debian13 'pcr-*'` in swtpm, lacking and none).
# shellcheck disable=SC2086,SC2015,SC2016 # SC2086: the ids are words; SC2015: A && B || bad is the check; SC2016: stub text and sed programs in single quotes
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-pcr: $*" >&2; fail=1; }
D=$ROOT/e2e/targets/debian13
ids="pcr-extended-signs pcr-restarted-signs pcr-signs-every-key"
pc() { python3 -I "$ROOT/e2e/pcr.py" "$@"; }

# placement
for id in $ids; do
    grep -qx "$id" "$D/cases.list" || bad "$id is not in $D/cases.list"
    grep -q "^$id:" "$D/skip.list" || bad "$id is not on the skip list of debian13"
    ! grep -qx "$id" "$ROOT/e2e/cases.list" || bad "$id is in e2e/cases.list (every target)"
    ! grep -rlx "$id" "$ROOT"/e2e/targets/*/cases.list | grep -qv debian13 || bad "$id is listed by another target"
done
[ "$(grep -c '^pcr-' "$D/cases.list")" = 3 ] || bad "debian13 cases.list lists other pcr cases than the three"
# shellcheck source=e2e/select.sh
source "$ROOT/e2e/select.sh"
for id in $ids pcr-x; do [ "$(case_group "$id")" = pcr ] || bad "case_group $id is '$(case_group "$id")', expected pcr"; done
# shellcheck source=e2e/pcr-cases.sh
source "$ROOT/e2e/pcr-cases.sh"
[ "$(printf '%s\n' $PCR_CASES | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "PCR_CASES differ from the listed cases"
[ "$(pc cases | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "pcr.py cases differ from the listed cases"

# accounting
printf '%s\n' $ids > "$tmp/cases"
( E2E_SELECT_FILE=$tmp/cases; export E2E_SELECT_FILE; pcr_skip_all none ) > "$tmp/out-all"
[ "$(grep -c '^E2E-CASE skipped pcr-' "$tmp/out-all")" = 3 ] || bad "the guest does not report three skips"
grep -q 'E2E_TPM=none' "$tmp/out-all" || bad "the skip reason does not name the mode"
sed 's/^E2E-CASE skipped /E2E-CASE run /' "$tmp/out-all" > "$tmp/out-run"
awk '/^E2E-CASE run / && !done { sub(/run/, "skipped"); done = 1 } { print }' "$tmp/out-run" > "$tmp/out-one"
sed -n 's/^E2E-CASE skipped \(.*\)/\1: not applicable/p' "$tmp/out-all" > "$tmp/skip-all"
check() { CHECK_TPM_MODE=$1 bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$2" "$3" > /dev/null 2>&1; }
check none "$D/skip.list" "$tmp/out-all" || bad "mode none: the skips are refused"
check none "$D/skip.list" "$tmp/out-run" || bad "mode none: run cases are refused"
echo "# none" > "$tmp/skip-empty"
! check none "$tmp/skip-empty" "$tmp/out-all" || bad "mode none: skips are accepted with no skip list"
for m in swtpm lacking; do
    check $m "$D/skip.list" "$tmp/out-run" || bad "mode $m: run cases are refused"
    ! check $m "$D/skip.list" "$tmp/out-all" || bad "mode $m: skipped cases are accepted"
    ! check $m "$D/skip.list" "$tmp/out-one" || bad "mode $m: one skipped case is accepted"
    ! check $m "$tmp/skip-all" "$tmp/out-all" || bad "mode $m: a skip list naming the cases lets the skips through"
done

expect_ok() { local out; out=$("$@") || { bad "failed to run: $*"; return; }; [ -z "$out" ] || bad "good evidence rejected ($*): $out"; }
expect_bad() { local out; out=$("$@" 2>&1) || true; [ -n "$out" ] || bad "bad evidence accepted ($*)"; }

# PCR readings (tpm2_pcrread output)
h() { printf '%064d' "$1"; }
reading() { # FILE V0 V7 V11
    printf 'sha256:\n  0 : 0x%s\n  7 : 0x%s\n  11: 0x%s\n' "$(h "$2")" "$(h "$3")" "$(h "$4")" > "$1"
}
reading "$tmp/first" 0 0 0
reading "$tmp/ext" 1 2 3
reading "$tmp/ext-no7" 1 0 3
reading "$tmp/ext-no0" 0 2 3
reading "$tmp/ext-no11" 1 2 0
reading "$tmp/again" 9 9 9
reading "$tmp/after-ext2" 4 5 6
reading "$tmp/after-7" 0 2 0
reading "$tmp/after-0" 1 0 0
printf 'sha256:\n  7 : 0x%s\n' "$(h 0)" > "$tmp/only7"
printf 'ERROR: no tpm\n' > "$tmp/pcr-error"
expect_ok pc extended "$tmp/first" "$tmp/ext"
expect_bad pc extended "$tmp/first" "$tmp/ext-no7"
expect_bad pc extended "$tmp/first" "$tmp/ext-no0"
expect_bad pc extended "$tmp/first" "$tmp/ext-no11"
expect_bad pc extended "$tmp/first" "$tmp/first"
expect_bad pc extended "$tmp/first" "$tmp/only7"
expect_bad pc extended "$tmp/first" "$tmp/pcr-error"
expect_bad pc extended "$tmp/first" "$tmp/missing"
expect_ok pc restarted "$tmp/first" "$tmp/ext" "$tmp/first"
expect_bad pc restarted "$tmp/first" "$tmp/ext" "$tmp/ext"        # not reset
expect_bad pc restarted "$tmp/first" "$tmp/ext" "$tmp/after-7"    # PCR 7 still extended
expect_bad pc restarted "$tmp/first" "$tmp/ext" "$tmp/after-ext2" # extended again, different from the extended ones but not the first reading
expect_bad pc restarted "$tmp/first" "$tmp/ext" "$tmp/again"
expect_bad pc restarted "$tmp/first" "$tmp/ext" "$tmp/pcr-error"
# pids
echo 100 > "$tmp/p100"; echo 200 > "$tmp/p200"; echo 0 > "$tmp/p0"; echo abc > "$tmp/pabc"
expect_ok pc pid "$tmp/p100" "$tmp/p200"
expect_bad pc pid "$tmp/p100" "$tmp/p100"
expect_bad pc pid "$tmp/p100" "$tmp/p0"
expect_bad pc pid "$tmp/p0" "$tmp/p200"
expect_bad pc pid "$tmp/p100" "$tmp/pabc"
expect_bad pc pid "$tmp/p100" "$tmp/missing"
# lists
printf 'pr-rsa\trsa2048\ttpm\npr-ec\tecdsa-p256\ttpm\nrsa1\trsa2048\ttpm\n' > "$tmp/list"
printf 'pr-rsa\trsa2048\ttpm\npr-ec\tecdsa-p256\ttpm\n' > "$tmp/list2"
printf 'pr-rsa\trsa2048\ttpm\npr-ec\tecdsa-p256\tencrypted-host\n' > "$tmp/list-kind"
printf 'pr-rsa\trsa2048\ttpm\n' > "$tmp/list-one"
printf 'pr-rsa\trsa2048\ttpm\nother\tecdsa-p256\ttpm\n' > "$tmp/list-missing"
printf 'pr-rsa\trsa2048\ttpm\npr-ec\tecdsa-p256\ttpm\nrsa1\trsa2048\tencrypted-host\n' > "$tmp/list-changed"
specs="pr-rsa:rsa2048 pr-ec:ecdsa-p256"
for m in swtpm lacking; do
    expect_ok pc keys "$tmp/list" "$tmp/list" $m $specs
    expect_ok pc keys "$tmp/list2" "$tmp/list2" $m $specs
    expect_bad pc keys "$tmp/list" "$tmp/list-kind" $m $specs   # a kind that changed
    expect_bad pc keys "$tmp/list" "$tmp/list-missing" $m $specs # a missing key
    expect_bad pc keys "$tmp/list" "$tmp/list-one" $m $specs     # fewer than two tpm keys, a missing key
    expect_bad pc keys "$tmp/list" "$tmp/list-changed" $m $specs # another key's kind changed
    expect_bad pc keys "$tmp/list" "$tmp/missing" $m $specs
done
expect_bad pc keys "$tmp/list" "$tmp/list" none $specs
[ "$(pc enumerate "$tmp/list" | wc -l)" = 3 ] || bad "enumerate does not list every tpm key"
[ "$(pc enumerate "$tmp/list-kind" | wc -l)" = 1 ] || bad "enumerate lists a key that is not of kind tpm"

# signatures, made by openssl
S=$tmp/s
mkdir -p "$S/in" "$S/out"
head -c 300 /dev/urandom > "$S/in/msg.bin"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/rsa.key" 2> /dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/ec.key" 2> /dev/null
openssl pkey -in "$tmp/rsa.key" -pubout -out "$S/in/pr-rsa.pub.pem"
openssl pkey -in "$tmp/ec.key" -pubout -out "$S/in/pr-ec.pub.pem"
openssl pkey -in "$tmp/rsa.key" -pubout -out "$S/in/rsa1.pub.pem"
mksigs() { # TAG
    openssl dgst -sha256 -sign "$tmp/rsa.key" -out "$S/out/$1-pr-rsa.sig" "$S/in/msg.bin"
    openssl dgst -sha256 -sign "$tmp/rsa.key" -out "$S/out/$1-rsa1.sig" "$S/in/msg.bin"
    openssl dgst -sha256 -sign "$tmp/ec.key" -out "$S/out/$1-pr-ec.sig" "$S/in/msg.bin"
    for k in pr-rsa rsa1 pr-ec; do echo 0 > "$S/out/$1-$k.rc"; done
}
mksigs g
expect_ok pc sigs "$S" g "$tmp/list"
cp -r "$S" "$tmp/S2"
echo 2 > "$tmp/S2/out/g-pr-ec.rc"; echo CKR_FUNCTION_FAILED > "$tmp/S2/out/g-pr-ec.log"
expect_bad pc sigs "$tmp/S2" g "$tmp/list" # a signing refusal
cp -r "$S" "$tmp/S3"
head -c 256 /dev/urandom > "$tmp/S3/out/g-pr-rsa.sig"
expect_bad pc sigs "$tmp/S3" g "$tmp/list" # a signature that does not verify
cp -r "$S" "$tmp/S4"
openssl dgst -sha256 -sign "$tmp/ec.key" -out "$tmp/S4/out/g-pr-rsa.sig" "$S/in/msg.bin"
expect_bad pc sigs "$tmp/S4" g "$tmp/list" # a signature of another key
cp -r "$S" "$tmp/S5"
head -c 70 /dev/urandom > "$tmp/S5/out/g-pr-ec.sig"
expect_bad pc sigs "$tmp/S5" g "$tmp/list" # garbage in place of a DER signature
cp -r "$S" "$tmp/S6"
rm "$tmp/S6/out/g-rsa1.sig"
expect_bad pc sigs "$tmp/S6" g "$tmp/list" # a listed tpm key that did not sign
: > "$tmp/S6/out/g-rsa1.sig"
expect_bad pc sigs "$tmp/S6" g "$tmp/list" # an empty signature
expect_bad pc sigs "$S" g "$tmp/list-one" # fewer than two tpm keys: nothing to prove
expect_bad pc sigs "$S" other "$tmp/list" # a round that did not happen

# the control
printf 'custodio-pcr-secret' > "$tmp/c-ok"
printf 'ERROR: Esys_Unseal(0x99D) - tpm:session(1):a policy check failed\n' > "$tmp/c-policy"
printf 'ERROR: Unable to run tpm2_unseal\n' > "$tmp/c-other"
expect_ok pc control 0 "$tmp/c-ok" 1 "$tmp/c-policy" custodio-pcr-secret
expect_bad pc control 1 "$tmp/c-policy" 1 "$tmp/c-policy" custodio-pcr-secret # never satisfied
expect_bad pc control 0 "$tmp/c-ok" 0 "$tmp/c-ok" custodio-pcr-secret        # still satisfied: the extension did nothing
expect_bad pc control 0 "$tmp/c-ok" 1 "$tmp/c-other" custodio-pcr-secret     # failed, not for the policy
expect_bad pc control 0 "$tmp/c-other" 1 "$tmp/c-policy" custodio-pcr-secret  # before: no secret
expect_bad pc control 0 "$tmp/c-ok" 1 "$tmp/missing" custodio-pcr-secret

# the restart helper refuses a mode with no TPM and the guest scripts parse
( source "$ROOT/e2e/tpm-lib.sh"; ! tpm_swtpm_restart none 2> /dev/null ) || bad "tpm_swtpm_restart accepts mode none"
for f in pcr-run.sh pcr-user.sh pcr-cases.sh; do bash -n "$ROOT/e2e/$f" || bad "$f does not parse"; done
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
