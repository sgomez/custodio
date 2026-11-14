#!/usr/bin/env bash
# F134: container-free checks of the sign-* cases: the judgements pass their self-test and the job list. NOT checked here: a real run
# (`just e2e-cases debian13 'sign-*'` in swtpm, none and lacking).
# shellcheck disable=SC2086,SC2013,SC2015,SC2016 # the ids are words; the reader line is cut by sed on purpose (single quotes keep the $)
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap "[ -n \"\${KEEP:-}\" ] || rm -rf \"\$tmp\"" EXIT
fail=0
bad() { echo "test-e2e-sign: $*" >&2; fail=1; }

bash "$ROOT/e2e/sign-selftest.sh" > /dev/null || bad "the self-test of the sign judgements fails"

# the job list, against a table written here independently of sign.py (a shorter list is consistent with itself everywhere else)
cat > "$tmp/expected-jobs" << 'EOT'
sign-rsa-pkcs rsa-pkcs-sha256 digest:sha256
sign-rsa-pkcs rsa-pkcs-sha384 digest:sha384
sign-rsa-pkcs rsa-pkcs-sha512 digest:sha512
sign-rsa-pkcs rsa-pkcs-md5sha1 recover:md5sha1.bin
sign-rsa-pkcs rsa-pkcs-arbitrary recover:arbitrary.bin
sign-rsa-pkcs rsa-pkcs-too-long refused
sign-rsa-pss-sha256 pss-sha256-0 pss:sha256:0
sign-rsa-pss-sha256 pss-sha256-hash pss:sha256:32
sign-rsa-pss-sha256 pss-sha256-max pss:sha256:222
sign-rsa-pss-sha256 pss-sha256-over refused
sign-rsa-pss-sha384 pss-sha384-0 pss:sha384:0
sign-rsa-pss-sha384 pss-sha384-hash pss:sha384:48
sign-rsa-pss-sha384 pss-sha384-max pss:sha384:206
sign-rsa-pss-sha384 pss-sha384-over refused
sign-rsa-pss-sha512 pss-sha512-0 pss:sha512:0
sign-rsa-pss-sha512 pss-sha512-hash pss:sha512:64
sign-rsa-pss-sha512 pss-sha512-max pss:sha512:190
sign-rsa-pss-sha512 pss-sha512-over refused
sign-rsa-composed rsa-sha256 dgst:sha256
sign-rsa-composed rsa-sha384 dgst:sha384
sign-rsa-composed rsa-sha512 dgst:sha512
sign-ec-ecdsa ecdsa-sha256 ec:sha256
sign-ec-ecdsa ecdsa-sha384 ec:sha384
sign-ec-ecdsa ecdsa-sha512 ec:sha512
sign-ec-composed ecdsa-sha256-composed ecdgst:sha256
sign-ec-composed ecdsa-sha384-composed ecdgst:sha384
sign-ec-composed ecdsa-sha512-composed ecdgst:sha512
EOT
dump_jobs() { python3 -I -c 'import importlib.util,sys
sp=importlib.util.spec_from_file_location("sg",sys.argv[1]); m=importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
for g,n,k,f,a,e in m.jobs(): print(g,n,e)' "$1"; }
dump_jobs "$ROOT/e2e/sign.py" > "$tmp/got-jobs"
diff -u "$tmp/expected-jobs" "$tmp/got-jobs" > /dev/null || bad "the job list of sign.py differs from the expected mechanisms and salt lengths"
# controls: a copy of sign.py without one salt job, and one without one mechanism, must differ from the table
sed '/for label, salt in/s/(("0", 0), ("hash", n), ("max", MAX_SALT\[h\]))/(("0", 0), ("hash", n))/' "$ROOT/e2e/sign.py" > "$tmp/sign-nosalt.py"
sed '/"rsa-pkcs-{h}"/d' "$ROOT/e2e/sign.py" > "$tmp/sign-nomech.py"
for c in nosalt nomech; do
    ! cmp -s "$ROOT/e2e/sign.py" "$tmp/sign-$c.py" || bad "control $c: the mutation did not change the copy"
    dump_jobs "$tmp/sign-$c.py" > "$tmp/got-$c" 2> /dev/null || true
    ! diff -q "$tmp/expected-jobs" "$tmp/got-$c" > /dev/null 2>&1 || bad "control $c: the job list check accepts a list without a salt or a mechanism"
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
grep -q 'pss-sha384-hash' "$tmp/vfull-bad.out" || bad "vfull-bad: the failure does not name the bad signature's case"
grep -q 'sign-rsa-pss-sha384' "$tmp/vfull-bad.out" && grep -q '^E2E-CASE run sign-rsa-pss-sha384' "$tmp/vfull-bad.out" && bad "vfull-bad: the bad case is reported run"
grep -q 'TPM mode' "$tmp/vnone.out" || bad "vnone: E2E_TPM=none in a VM run is not refused with its reason"
[ "$(rcof vctl)" = 0 ] || bad "the control copy without the reader call does not pass the nonzero PCR mask: $(tail -n 3 "$tmp/vctl.out")"

exit "$fail"
