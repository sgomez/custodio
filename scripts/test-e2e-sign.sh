#!/usr/bin/env bash
# F134: container-free checks of the sign-* cases: the judgements pass their self-test, the placement (debian13 list, not the every-target list, never on the skip list, group),
# that the guest's cases are the listed ones, and the accounting rejecting a sign-* skip in each TPM mode. NOT checked here: a real run
# (`just e2e-cases debian13 'sign-*'` in swtpm, none and lacking).
# shellcheck disable=SC2086,SC2013,SC2015,SC2016 # the ids are words; the reader line is cut by sed on purpose (single quotes keep the $)
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap "[ -n \"\${KEEP:-}\" ] || rm -rf \"\$tmp\"" EXIT
fail=0
bad() { echo "test-e2e-sign: $*" >&2; fail=1; }
D=$ROOT/e2e/targets/debian13
ids="sign-kind-matches-mode sign-rsa-pkcs sign-rsa-pss-sha256 sign-rsa-pss-sha384 sign-rsa-pss-sha512 sign-rsa-composed sign-ec-ecdsa sign-ec-composed"

bash "$ROOT/e2e/sign-selftest.sh" > /dev/null || bad "the self-test of the sign judgements fails"

# placement
for id in $ids; do
    grep -qx "$id" "$D/cases.list" || bad "$id is not in $D/cases.list"
    ! grep -q "^$id:" "$D/skip.list" || bad "$id is on the skip list of debian13"
    ! grep -qx "$id" "$ROOT/e2e/cases.list" || bad "$id is in e2e/cases.list (every target)"
    ! grep -rlx "$id" "$ROOT"/e2e/targets/*/cases.list | grep -qv debian13 || bad "$id is listed by another target"
done
grep -rh '^sign-' "$ROOT"/e2e/targets/*/skip.list "$ROOT/e2e/cases.list" 2> /dev/null | grep -q . && bad "a sign-* case is on a skip list or in the every-target list"
[ "$(grep -c '^sign-' "$D/cases.list")" = 8 ] || bad "debian13 cases.list lists other sign cases than the eight"
# shellcheck source=e2e/select.sh
source "$ROOT/e2e/select.sh"
for id in $ids sign-x; do [ "$(case_group "$id")" = sign ] || bad "case_group $id is '$(case_group "$id")', expected sign"; done
# the cases sign-run.sh reports are the listed ones: the judgements' groups and the kind case
got=$( (echo sign-kind-matches-mode; python3 -I "$ROOT/e2e/sign.py" groups) | sort)
[ "$got" = "$(printf '%s\n' $ids | sort)" ] || bad "the cases of sign.py differ from the listed ones"

# accounting: as if the guest ran or skipped them, in each mode (run.sh sets CHECK_TPM_MODE)
printf '%s\n' $ids > "$tmp/cases"
sed 's/^/E2E-CASE run /' "$tmp/cases" > "$tmp/out-run"
sed 's/^E2E-CASE run /E2E-CASE skipped /' "$tmp/out-run" > "$tmp/out-all"
awk '/^E2E-CASE run / && !done { sub(/run/, "skipped"); done = 1 } { print }' "$tmp/out-run" > "$tmp/out-one"
sed 's/^E2E-CASE skipped \(.*\)/\1: not applicable/' "$tmp/out-all" > "$tmp/skip-all"
check() { CHECK_TPM_MODE=$1 bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$2" "$3" > /dev/null 2>&1; }
for m in swtpm none lacking; do
    check $m "$D/skip.list" "$tmp/out-run" || bad "mode $m: the run sign cases are refused"
    ! check $m "$D/skip.list" "$tmp/out-one" || bad "mode $m: one skipped sign case is accepted"
    ! check $m "$D/skip.list" "$tmp/out-all" || bad "mode $m: skipped sign cases are accepted"
    # even a skip list that names every case does not help
    ! check $m "$tmp/skip-all" "$tmp/out-all" || bad "mode $m: a skip list naming the cases lets the skips through"
    ! check $m "$tmp/skip-all" "$tmp/out-one" || bad "mode $m: a skip list naming the cases lets one skip through"
done

# ---- F162: a VM run (E2E_VM=1) of sign-run.sh on fixtures. `su` is a stub that runs scripts/lib/e2e-sign-alice.py: it takes the keys out of the run's own .p12 files and signs every job with
# the real openssl (so sign.py's real openssl verification is what judges them); the reader is the real one on synthetic stored records.
# shellcheck source=scripts/lib/e2e-vm-cred-fixtures.sh
source "$ROOT/scripts/lib/e2e-vm-cred-fixtures.sh"
E=$ROOT/e2e
cred "$tmp/ok.cred" ef4ac13679a9480ea7db68897f9f165d 0
cred "$tmp/pcr.cred" ef4ac13679a9480ea7db68897f9f165d 0x80
for k in sg-rsa sg-ec; do rec "$tmp/st-ok" $k 2 "$tmp/ok.cred"; done
rec "$tmp/st-pcr" sg-rsa 2 "$tmp/ok.cred"; rec "$tmp/st-pcr" sg-ec 2 "$tmp/pcr.cred"
mkdir -p "$tmp/st-none" "$tmp/stub"
cat > "$tmp/stub/su" << STUB
#!/usr/bin/env bash
case "\$4" in *SG_READ=1*) export SG_READ=1 ;; esac
exec python3 -I "$ROOT/scripts/lib/e2e-sign-alice.py" "\${STUB_E2E:-$E}" "\$WORK"
STUB
chmod +x "$tmp/stub/su"
# sgrun NAME STATE [ENV=VAL...]: sign-run.sh (or $RUN_COPY) in its own work directory; output into $tmp/NAME.out, exit status into $tmp/NAME.rc. E2E_VM/E2E_TPM come from the caller's SG_VM/SG_TPM.
sgrun() {
    local n=$1 st=$2 w rc=0
    shift 2
    w=$tmp/w-$n
    mkdir -p "$w"
    env PATH="$tmp/stub:$PATH" WORK="$w" MODULE=/nonexistent E2E_SELECT_FILE=/nonexistent ${SG_VM:+E2E_VM=1} E2E_TPM="${SG_TPM:-swtpm}" VM_STATE_DIR="$st" \
        VM_CRED_DIR="$E/vm" VM_SYSTEMD_VERSION=259 "$@" bash "${RUN_COPY:-$E/sign-run.sh}" > "$tmp/$n.out" 2>&1 || rc=$?
    echo $rc > "$tmp/$n.rc"
}
# a copy of sign-run.sh without the reader call (the control: the stub reader's failure is then ignored)
mkdir "$tmp/ctl"
cp "$E"/sign-run.sh "$E"/sign.py "$E"/sign-selftest.sh "$E"/sign-selftest.py "$E"/report.sh "$E"/select.sh "$E"/tpmkind-lib.sh "$tmp/ctl/"
cp "$E"/fixtures.sh "$tmp/ctl/" 2> /dev/null || true
cp -r "$E/vm" "$tmp/ctl/vm"
sed -i 's/vm_read_credential "\$id"/true/' "$tmp/ctl/sign-run.sh"
cmp -s "$E/sign-run.sh" "$tmp/ctl/sign-run.sh" && bad "the control copy of sign-run.sh without the reader call changes nothing"
export -f sgrun
export tmp ROOT E
SG_VM=1 SG_TPM=swtpm sgrun vfull "$tmp/st-none" STUB_KIND=tpm &
SG_VM=1 SG_TPM=lacking sgrun vlack "$tmp/st-ok" STUB_KIND=encrypted-tpm &
SG_VM=1 SG_TPM=swtpm sgrun vfull-etpm "$tmp/st-none" STUB_KIND=encrypted-tpm &
SG_VM=1 SG_TPM=lacking sgrun vlack-tpm "$tmp/st-ok" STUB_KIND=tpm &
SG_VM=1 SG_TPM=lacking sgrun vlack-host "$tmp/st-ok" STUB_KIND=encrypted-host &
SG_VM=1 SG_TPM=lacking sgrun vlack-pcr "$tmp/st-pcr" STUB_KIND=encrypted-tpm &
SG_VM=1 SG_TPM=lacking sgrun vlack-nocred "$tmp/st-none" STUB_KIND=encrypted-tpm &
SG_VM=1 SG_TPM=lacking sgrun vlack-noimp "$tmp/st-ok" STUB_KIND=encrypted-tpm STUB_NOIMPORTED=1 &
SG_VM=1 SG_TPM=swtpm sgrun vfull-bad "$tmp/st-none" STUB_KIND=tpm STUB_BADSIG=pss-sha384-hash &
SG_VM=1 SG_TPM=none sgrun vnone "$tmp/st-none" STUB_KIND=encrypted-host &
SG_VM=1 SG_TPM=lacking RUN_COPY=$tmp/ctl/sign-run.sh STUB_E2E=$tmp/ctl sgrun vctl "$tmp/st-pcr" STUB_KIND=encrypted-tpm &
SG_TPM=swtpm sgrun ctr-swtpm "$tmp/st-none" STUB_KIND=tpm &
wait
rcof() { cat "$tmp/$1.rc" 2> /dev/null || echo missing; }
nrun() { grep -c '^E2E-CASE run' "$tmp/$1.out" || true; }
for n in vfull vlack ctr-swtpm; do
    [ "$(rcof $n)" = 0 ] || bad "$n: the good run fails: $(tail -n 5 "$tmp/$n.out")"
    [ "$(nrun $n)" = 8 ] || bad "$n: $(nrun $n) cases reported run, expected all 8"
done
grep -q 'reader: key sg-rsa' "$tmp/vlack.out" && grep -q 'reader: key sg-ec' "$tmp/vlack.out" || bad "vlack: the reader did not run on both keys"
grep -q 'reader: key' "$tmp/vfull.out" && bad "vfull: the reader ran in the full mode"
for n in vfull-etpm vlack-tpm vlack-host vlack-pcr vlack-nocred vlack-noimp vfull-bad vnone; do
    [ "$(rcof $n)" != 0 ] && [ "$(rcof $n)" != missing ] || bad "$n: the run passes"
    grep -q '^E2E-CASE run sign-kind-matches-mode' "$tmp/$n.out" && [[ $n == v*-etpm || $n == vlack-tpm || $n == vlack-host ]] && bad "$n: the kind case is reported run"
done
grep -q 'sg-ec' "$tmp/vlack-pcr.out" || bad "vlack-pcr: the reader failure does not name sg-ec"
grep -q 'never imported' "$tmp/vlack-noimp.out" || bad "vlack-noimp: the failure is not the never-imported one"
grep -q 'pss-sha384-hash\|sign-rsa-pss-sha384' "$tmp/vfull-bad.out" || bad "vfull-bad: the failure does not name the bad signature's case"
grep -q 'sign-rsa-pss-sha384' "$tmp/vfull-bad.out" && grep -q '^E2E-CASE run sign-rsa-pss-sha384' "$tmp/vfull-bad.out" && bad "vfull-bad: the bad case is reported run"
grep -q 'TPM mode' "$tmp/vnone.out" || bad "vnone: E2E_TPM=none in a VM run is not refused with its reason"
[ "$(rcof vctl)" = 0 ] || bad "the control copy without the reader call does not pass the nonzero PCR mask: $(tail -n 3 "$tmp/vctl.out")"

# accounting of a VM run (CHECK_VM=1): all run accepted, one skipped refused, all skipped refused even with a skip list naming them
cp "$E/vm/cases.list" "$tmp/vmcases"
for id in $ids; do grep -qx "$id" "$tmp/vmcases" || bad "$id is not in e2e/vm/cases.list"; done
for id in $(grep -v '^[[:space:]]*\(#\|$\)' "$tmp/vmcases"); do echo "E2E-CASE run $id"; done > "$tmp/vm-run"
for id in $ids; do
    sed "s/^E2E-CASE run $id\$/E2E-CASE skipped $id/" "$tmp/vm-run" > "$tmp/vm-sk"
    printf '%s: x\n' $ids > "$tmp/vm-skiplist"
    for m in swtpm lacking; do
        vcheck() { CHECK_VM=1 CHECK_TPM_MODE=$m bash "$E/check-cases.sh" check "$tmp/vmcases" "$1" "$2" > /dev/null 2>&1; }
        vcheck "$E/vm/skip.list" "$tmp/vm-run" || bad "VM $m: all cases run is refused"
        ! vcheck "$E/vm/skip.list" "$tmp/vm-sk" || bad "VM $m: $id skipped is accepted"
        ! vcheck "$tmp/vm-skiplist" "$tmp/vm-sk" || bad "VM $m: $id skipped is accepted with a skip list naming it"
    done
done
exit "$fail"
