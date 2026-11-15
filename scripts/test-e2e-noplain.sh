#!/usr/bin/env bash
# F135: container-free checks of the noplain-* cases: the no-key-file judgement rejects each planted unencrypted form and accepts an encrypted-only directory (an encrypted PEM
# never prompts), the kind judgement accepts only the mode's kinds. NOT checked here: a real run (`just e2e-cases debian13 'noplain-*'` in swtpm, none and lacking).
# shellcheck disable=SC2086,SC2013,SC2015,SC2016 # the ids are words; the reader line is cut by sed on purpose (single quotes keep the $)
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap "[ -n \"\${KEEP:-}\" ] || rm -rf \"\$tmp\"" EXIT
fail=0
bad() { echo "test-e2e-noplain: $*" >&2; fail=1; }
np() { python3 -I "$ROOT/e2e/noplain.py" "$@"; }

# kind judgement
printf 'np-rsa\trsa2048\ttpm\nnp-ec\tecdsa-p256\ttpm\n' > "$tmp/k-tpm"
printf 'np-rsa\trsa2048\tencrypted-host\nnp-ec\tecdsa-p256\tencrypted-host\n' > "$tmp/k-host"
printf 'np-rsa\trsa2048\tencrypted-tpm\nnp-ec\tecdsa-p256\tencrypted-tpm\n' > "$tmp/k-etpm"
printf 'np-rsa\trsa2048\ttpm\n' > "$tmp/k-one"
specs="np-rsa:rsa2048 np-ec:ecdsa-p256"
for m in swtpm lacking; do
    [ -z "$(np kind "$tmp/k-tpm" $m $specs)" ] || bad "mode $m: kinds tpm/tpm are refused"
    for f in k-host k-etpm k-one; do [ -n "$(np kind "$tmp/$f" $m $specs)" ] || bad "mode $m: $f is accepted"; done
done
[ -z "$(np kind "$tmp/k-host" none $specs)" ] || bad "mode none: encrypted-host is refused"
for f in k-tpm k-etpm k-one; do [ -n "$(np kind "$tmp/$f" none $specs)" ] || bad "mode none: $f is accepted"; done

# no-key-file judgement: planted forms (in parallel) and a directory that holds only protected files
(
    cd "$tmp"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.pem 2> /dev/null
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.pem 2> /dev/null
    openssl req -new -x509 -key rsa.pem -subj /CN=x -days 1 -out rsa.crt
    for n in pkcs8 pkcs1 der p12 sec1 enc good; do mkdir "d-$n"; done
    cp rsa.pem d-pkcs8/key.pem
    openssl rsa -in rsa.pem -traditional -out d-pkcs1/key.pem 2> /dev/null
    openssl pkey -in rsa.pem -outform DER -out d-der/key.bin
    openssl pkcs12 -export -inkey rsa.pem -in rsa.crt -passout pass: -out d-p12/key.bin 2> /dev/null || openssl pkcs12 -export -legacy -inkey rsa.pem -in rsa.crt -passout pass: -out d-p12/key.bin
    openssl ec -in ec.pem -out d-sec1/key.pem 2> /dev/null
    openssl pkey -in rsa.pem -aes256 -passout pass:secret -out d-enc/key.pem
    cp d-enc/key.pem d-good/key.pem
    head -c 300 /dev/urandom > d-good/opaque.bin
    printf 'x\n' > d-good/record.txt
)
for n in pkcs8 pkcs1 der p12 sec1; do
    (
        out=$(np files "$tmp/d-$n") || true
        [ -n "$out" ] || echo "the planted form '$n' is accepted"
        grep -q "d-$n/key" <<< "$out" || [ -z "$out" ] || echo "the judgement for '$n' does not name the file"
    ) > "$tmp/res-$n" &
done
wait
for n in pkcs8 pkcs1 der p12 sec1; do
    while IFS= read -r l; do bad "$l"; done < "$tmp/res-$n"
done
start=$SECONDS
out=$(timeout 60 python3 -I "$ROOT/e2e/noplain.py" files "$tmp/d-good") || bad "judging the encrypted-only directory failed"
[ -z "$out" ] || bad "an encrypted-only directory is rejected: $out"
[ $((SECONDS - start)) -lt 30 ] || bad "judging the encrypted directory took $((SECONDS - start)) s (a prompt?)"
[ -n "$(np list "$tmp/d-good")" ] || bad "the listing of a directory is empty"

# ---- F162: a VM run (E2E_VM=1) of noplain-run.sh on fixtures. `su` is a stub: `import T` writes the ListKeys row (kind STUB_KIND) and, with STUB_PLANT=1, the PKCS#8 DER of the key
# (taken from the run's own .p12) into the state directory; `delete` writes the empty list. The scan is the unchanged scripts/check-no-plaintext.sh on a fixture state directory.
# shellcheck source=scripts/lib/e2e-vm-cred-fixtures.sh
source "$ROOT/scripts/lib/e2e-vm-cred-fixtures.sh"
E=$ROOT/e2e
cred "$tmp/ok.cred" ef4ac13679a9480ea7db68897f9f165d 0
cred "$tmp/pcr.cred" ef4ac13679a9480ea7db68897f9f165d 0x80
for k in np-rsa np-ec; do rec "$tmp/st-ok" $k 2 "$tmp/ok.cred"; done
rec "$tmp/st-pcr" np-rsa 2 "$tmp/ok.cred"; rec "$tmp/st-pcr" np-ec 2 "$tmp/pcr.cred"
mkdir -p "$tmp/st-none" "$tmp/stub"
cat > "$tmp/stub/su" << 'STUB'
#!/usr/bin/env bash
set -e
cmd=$4
np=$WORK/noplain
case $cmd in
*"noplain-user.sh import rsa"*) t=rsa ty=rsa2048 ;;
*"noplain-user.sh import ec"*) t=ec ty=ecdsa-p256 ;;
*) : > "$np/list-after.out"; exit 0 ;;
esac
[ -z "${STUB_NOIMPORT:-}" ] || exit 0
printf 'np-%s\t%s\t%s\n' $t $ty "${STUB_KIND:-tpm}" > "$np/list-$t.out"
if [ -n "${STUB_PLANT:-}" ]; then
    openssl pkcs12 -in "$np/$t.p12" -passin pass:e2e-password -nocerts -noenc 2> /dev/null | openssl pkey -outform DER -out "$VM_STATE_DIR/leak-$t.der"
fi
STUB
chmod +x "$tmp/stub/su"
mkdir "$tmp/ctl"
cp "$E"/noplain-run.sh "$E"/noplain.py "$E"/report.sh "$E"/select.sh "$E"/tpmkind-lib.sh "$tmp/ctl/"
cp -r "$E/vm" "$tmp/ctl/vm"
sed -i 's/vm_read_credential "\$id"/true/' "$tmp/ctl/noplain-run.sh"
cmp -s "$E/noplain-run.sh" "$tmp/ctl/noplain-run.sh" && bad "the control copy of noplain-run.sh without the reader call changes nothing"
# nprun NAME STATE [ENV=VAL...]: on its own copy of STATE; SG_VM / SG_TPM choose E2E_VM and E2E_TPM
nprun() {
    local n=$1 w rc=0
    w=$tmp/w-$n
    mkdir -p "$w"
    cp -a "$2" "$w/state"
    shift 2
    env PATH="$tmp/stub:$PATH" WORK="$w" E2E_SELECT_FILE=/nonexistent ${SG_VM:+E2E_VM=1} E2E_TPM="${SG_TPM:-swtpm}" NP_STATE_DIR="$w/state" VM_STATE_DIR="$w/state" \
        NP_CHECK="$ROOT/scripts/check-no-plaintext.sh" VM_CRED_DIR="$E/vm" VM_SYSTEMD_VERSION=259 "$@" bash "${RUN_COPY:-$E/noplain-run.sh}" > "$tmp/$n.out" 2>&1 || rc=$?
    echo $rc > "$tmp/$n.rc"
}
SG_VM=1 SG_TPM=swtpm nprun vfull "$tmp/st-none" STUB_KIND=tpm &
SG_VM=1 SG_TPM=lacking nprun vlack "$tmp/st-ok" STUB_KIND=encrypted-tpm &
SG_VM=1 SG_TPM=swtpm nprun vfull-etpm "$tmp/st-none" STUB_KIND=encrypted-tpm &
SG_VM=1 SG_TPM=lacking nprun vlack-tpm "$tmp/st-ok" STUB_KIND=tpm &
SG_VM=1 SG_TPM=lacking nprun vlack-host "$tmp/st-ok" STUB_KIND=encrypted-host &
SG_VM=1 SG_TPM=lacking nprun vlack-pcr "$tmp/st-pcr" STUB_KIND=encrypted-tpm &
SG_VM=1 SG_TPM=lacking nprun vlack-nocred "$tmp/st-none" STUB_KIND=encrypted-tpm &
SG_VM=1 SG_TPM=lacking nprun vlack-noimp "$tmp/st-ok" STUB_KIND=encrypted-tpm STUB_NOIMPORT=1 &
SG_VM=1 SG_TPM=swtpm nprun vfull-leak "$tmp/st-none" STUB_KIND=tpm STUB_PLANT=1 &
SG_VM=1 SG_TPM=lacking nprun vlack-leak "$tmp/st-ok" STUB_KIND=encrypted-tpm STUB_PLANT=1 &
SG_VM=1 SG_TPM=none nprun vnone "$tmp/st-none" STUB_KIND=encrypted-host &
SG_VM=1 SG_TPM=lacking RUN_COPY=$tmp/ctl/noplain-run.sh nprun vctl "$tmp/st-pcr" STUB_KIND=encrypted-tpm &
SG_TPM=swtpm nprun ctr-swtpm "$tmp/st-none" STUB_KIND=tpm &
SG_TPM=none nprun ctr-none "$tmp/st-none" STUB_KIND=encrypted-host &
wait
rcof() { cat "$tmp/$1.rc" 2> /dev/null || echo missing; }
nrun() { grep -c '^E2E-CASE run' "$tmp/$1.out" || true; }
for n in vfull vlack ctr-swtpm ctr-none; do
    [ "$(rcof $n)" = 0 ] || bad "$n: the good run fails: $(tail -n 5 "$tmp/$n.out")"
    [ "$(nrun $n)" = 3 ] || bad "$n: $(nrun $n) cases reported run, expected all 3"
done
grep -q 'reader: key np-rsa' "$tmp/vlack.out" && grep -q 'reader: key np-ec' "$tmp/vlack.out" || bad "vlack: the reader did not run on both keys"
grep -q 'reader: key' "$tmp/vfull.out" && bad "vfull: the reader ran in the full mode"
grep -q 'check-no-plaintext on rsa.p12 (rsa) exit 0' "$tmp/vlack.out" || bad "vlack: the scan after the import did not run"
for n in vfull-etpm vlack-tpm vlack-host vlack-pcr vlack-nocred vlack-noimp vfull-leak vlack-leak vnone; do
    [ "$(rcof $n)" != 0 ] && [ "$(rcof $n)" != missing ] || bad "$n: the run passes"
done
for n in vfull-leak vlack-leak; do
    grep -q 'leak-' "$tmp/$n.out" || bad "$n: the scan does not name the planted file"
    grep -q '^E2E-CASE run noplain-rsa' "$tmp/$n.out" && bad "$n: noplain-rsa is reported run with the key in the state directory"
done
grep -q 'np-ec: the credential .* did not pass the reader' "$tmp/vlack-pcr.out" || bad "vlack-pcr: the reader failure does not name np-ec"
grep -q 'TPM mode' "$tmp/vnone.out" || bad "vnone: E2E_TPM=none in a VM run is not refused with its reason"
[ "$(rcof vctl)" = 0 ] || bad "the control copy without the reader call does not pass the nonzero PCR mask: $(tail -n 3 "$tmp/vctl.out")"

exit "$fail"
