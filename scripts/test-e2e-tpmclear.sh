#!/usr/bin/env bash
# F140: container-free checks of the tpm-clear-* cases: the placement (debian13 list and skip list, group, not in e2e/cases.list), the accounting (a skip accepted in none, refused in swtpm
# and lacking), and the judgements of e2e/tpmclear.py on good and bad evidence (a signature that succeeded after the clear, a wrong error name or text, a wrong CKR, zero or two entries per
# attempt, a wrong cause, kind, uid or key, a secret in an entry, a key missing from a list, a changed kind, a changed state directory, a failed delete, a record left, an unchanged
# owner-hierarchy name). NOT checked here: a real run (`just e2e-cases debian13 'tpm-clear-*'` in swtpm, lacking and none).
# shellcheck disable=SC2086 # the ids are words
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-tpmclear: $*" >&2; fail=1; }
D=$ROOT/e2e/targets/debian13
ids="tpm-clear-sign-fails tpm-clear-keys-listed tpm-clear-delete"
tc() { python3 -I "$ROOT/e2e/tpmclear.py" "$@"; }

# placement
for id in $ids; do
    grep -qx "$id" "$D/cases.list" || bad "$id is not in $D/cases.list"
    grep -q "^$id:" "$D/skip.list" || bad "$id is not on the skip list of debian13"
    ! grep -qx "$id" "$ROOT/e2e/cases.list" || bad "$id is in e2e/cases.list (every target)"
done
[ "$(grep -c '^tpm-clear-' "$D/cases.list")" = 3 ] || bad "debian13 cases.list lists other tpm-clear cases than the three"
# shellcheck source=e2e/select.sh
source "$ROOT/e2e/select.sh"
for id in $ids tpm-clear-x; do [ "$(case_group "$id")" = tpmclear ] || bad "case_group $id is '$(case_group "$id")', expected tpmclear"; done
for id in tpm-dup-x tpm-kind-x tpmfail-x tpm-installed-unit-clean; do [ "$(case_group "$id")" != tpmclear ] || bad "case_group $id is tpmclear"; done
# shellcheck source=e2e/tpmclear-cases.sh
source "$ROOT/e2e/tpmclear-cases.sh"
[ "$(printf '%s\n' $TPMCLEAR_CASES | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "TPMCLEAR_CASES differ from the listed cases"
[ "$(tc cases | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "tpmclear.py cases differ from the listed cases"

# accounting
printf '%s\n' $ids > "$tmp/cases"
( E2E_SELECT_FILE=$tmp/cases; export E2E_SELECT_FILE; tpmclear_skip_all none ) > "$tmp/out-all"
[ "$(grep -c '^E2E-CASE skipped tpm-clear-' "$tmp/out-all")" = 3 ] || bad "the guest does not report three skips"
grep -q 'E2E_TPM=none' "$tmp/out-all" || bad "the skip reason does not name the mode"
sed 's/^E2E-CASE skipped /E2E-CASE run /' "$tmp/out-all" > "$tmp/out-run"
awk '/^E2E-CASE run / && !done { sub(/run/, "skipped"); done = 1 } { print }' "$tmp/out-run" > "$tmp/out-one"
sed -n 's/^E2E-CASE skipped \(.*\)/\1: not applicable/p' "$tmp/out-all" > "$tmp/skip-all"
check() { CHECK_VM=${CHECK_VM:-} CHECK_TPM_MODE=$1 bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$2" "$3" > /dev/null 2>&1; }
check none "$D/skip.list" "$tmp/out-all" || bad "mode none: the skips are refused"
echo "# none" > "$tmp/skip-empty"
! check none "$tmp/skip-empty" "$tmp/out-all" || bad "mode none: skips are accepted with no skip list"
for m in swtpm lacking; do
    check $m "$D/skip.list" "$tmp/out-run" || bad "mode $m: run cases are refused"
    ! check $m "$D/skip.list" "$tmp/out-all" || bad "mode $m: skipped cases are accepted"
    ! check $m "$D/skip.list" "$tmp/out-one" || bad "mode $m: one skipped case is accepted"
    ! check $m "$tmp/skip-all" "$tmp/out-all" || bad "mode $m: a skip list naming the cases lets the skips through"
done

for m in swtpm lacking; do # F163: a VM run accounts the same way
    ( export CHECK_VM=1
      check $m "$tmp/skip-empty" "$tmp/out-run" || bad "VM $m: run cases are refused"
      ! check $m "$tmp/skip-empty" "$tmp/out-all" || bad "VM $m: skipped cases are accepted"
      ! check $m "$tmp/skip-all" "$tmp/out-all" || bad "VM $m: a skip list naming the cases lets the skips through" )
done

expect_ok() { local out; out=$("$@") || { bad "failed to run: $*"; return; }; [ -z "$out" ] || bad "good evidence rejected ($*): $out"; }
expect_bad() { local out; out=$("$@" 2>&1) || true; [ -n "$out" ] || bad "bad evidence accepted ($*)"; }
# many judgements in parallel would only hide which one failed; the files are tiny, so they run one after another

# D-Bus replies
E=com.rfirma.Custodio1.Error
echo "error $E.KeyLost: the stored key can no longer be used" > "$tmp/d-lost"
echo ok > "$tmp/d-ok"
echo "error $E.Internal: internal error" > "$tmp/d-internal"
echo "error $E.KeyLost: something else" > "$tmp/d-text"
echo "error $E.TemporarilyUnavailable: the stored key can no longer be used" > "$tmp/d-temp"
expect_ok tc dbus "$tmp/d-lost" KeyLost
expect_ok tc dbus "$tmp/d-ok" ok
expect_bad tc dbus "$tmp/d-ok" KeyLost # signed after the clear
expect_bad tc dbus "$tmp/d-internal" KeyLost
expect_bad tc dbus "$tmp/d-text" KeyLost
expect_bad tc dbus "$tmp/d-temp" KeyLost
expect_bad tc dbus "$tmp/d-lost" ok
expect_bad tc dbus "$tmp/missing" KeyLost
# pkcs11-tool
echo 1 > "$tmp/rc1"; echo 0 > "$tmp/rc0"
echo 'error: PKCS11 function C_Sign failed: rv = CKR_DEVICE_ERROR (0x5)' > "$tmp/l-dev"
echo 'error: PKCS11 function C_Sign failed: rv = CKR_DATA_INVALID (0x20)' > "$tmp/l-data"
echo 'Using signature algorithm SHA256-RSA-PKCS' > "$tmp/l-fine"
expect_ok tc p11fail "$tmp/rc1" "$tmp/l-dev"
expect_bad tc p11fail "$tmp/rc0" "$tmp/l-dev"  # signed
expect_bad tc p11fail "$tmp/rc1" "$tmp/l-data" # a wrong CKR
expect_bad tc p11fail "$tmp/rc1" "$tmp/l-fine"
expect_bad tc p11fail "$tmp/missing" "$tmp/l-dev"
# a signature that verifies (openssl is in the dev container and the CI)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/k.pem" 2> /dev/null
openssl pkey -in "$tmp/k.pem" -pubout -out "$tmp/pub.pem"
head -c 100 /dev/urandom > "$tmp/msg"
openssl dgst -sha256 -sign "$tmp/k.pem" -out "$tmp/sig" "$tmp/msg"
head -c 100 /dev/urandom > "$tmp/msg2"
: > "$tmp/sig-empty"
expect_ok tc p11ok "$tmp/rc0" "$tmp/l-fine" "$tmp/pub.pem" "$tmp/msg" "$tmp/sig"
expect_bad tc p11ok "$tmp/rc0" "$tmp/l-fine" "$tmp/pub.pem" "$tmp/msg2" "$tmp/sig" # does not verify
expect_bad tc p11ok "$tmp/rc0" "$tmp/l-fine" "$tmp/pub.pem" "$tmp/msg" "$tmp/sig-empty"
expect_bad tc p11ok "$tmp/rc1" "$tmp/l-dev" "$tmp/pub.pem" "$tmp/msg" "$tmp/sig"
# the journal of the failing signatures
entry() { # UID KIND KEY [OP OUTCOME CAUSE]
    python3 -I - "$@" << 'PY'
import json, sys
uid, kind, key, op, outcome, cause = (sys.argv[1:] + ["sign", "signing_failed", "key_lost"][len(sys.argv) - 4:])[:6]
e = {"SYSLOG_IDENTIFIER": "custodiod", "CUSTODIO_OPERATION": op, "CUSTODIO_OUTCOME": outcome, "CUSTODIO_KEY_ID": key, "CUSTODIO_UID": uid}
if cause != "-":
    e["CUSTODIO_CAUSE"] = cause
if kind != "-":
    e["CUSTODIO_STORAGE_KIND"] = kind
print(json.dumps(e))
PY
}
{ entry 1000 tpm a; entry 1000 tpm a; entry 1000 tpm b; entry 1000 tpm b; entry 1000 tpm b; } > "$tmp/j-ok"
{ entry 1000 tpm a; entry 1000 tpm a; entry 1000 tpm b; } > "$tmp/j-one-b"
{ entry 1000 tpm a; entry 1000 tpm a; entry 1000 tpm b; entry 1000 tpm b; entry 1000 tpm b; entry 1000 tpm b; } > "$tmp/j-extra"
{ entry 1000 tpm a; entry 1000 tpm a; entry 1000 tpm b; entry 1000 tpm b; entry 1000 tpm a delete deleted -; } > "$tmp/j-delete"
{ entry 1000 tpm a; entry 1000 tpm a; entry 1000 tpm b; entry 1000 tpm b; entry 1000 tpm b sign signing_failed temporarily_unavailable; } > "$tmp/j-cause"
{ entry 1000 tpm a; entry 1000 tpm a; entry 1000 tpm b; entry 1000 tpm b; entry 1000 tpm b sign signed -; } > "$tmp/j-signed"
{ entry 1000 tpm a; entry 1000 tpm a; entry 1000 tpm b; entry 1000 tpm b; entry 1001 tpm b; } > "$tmp/j-uid"
{ entry 1000 tpm a; entry 1000 tpm a; entry 1000 tpm b; entry 1000 tpm b; entry 1000 tpm z; } > "$tmp/j-key"
{ entry 1000 encrypted-host a; entry 1000 tpm a; entry 1000 tpm b; entry 1000 tpm b; entry 1000 tpm b; } > "$tmp/j-kind"
{ entry 1000 - a; entry 1000 tpm a; entry 1000 tpm b; entry 1000 tpm b; entry 1000 tpm b; } > "$tmp/j-nokind"
{ entry 1000 tpm a; entry 1000 tpm a; entry 1000 tpm b; entry 1000 tpm b; entry 1000 tpm b; } | sed 's/"CUSTODIO_UID": "1000"/"CUSTODIO_UID": "1000", "MESSAGE": "e2e-password"/' > "$tmp/j-secret"
: > "$tmp/j-none"
expect_ok tc journal "$tmp/j-ok" 1000 tpm 5 a,b e2e-password
expect_bad tc journal "$tmp/j-none" 1000 tpm 5 a,b   # zero entries
expect_bad tc journal "$tmp/j-extra" 1000 tpm 5 a,b  # two entries for one call
expect_bad tc journal "$tmp/j-ok" 1000 tpm 6 a,b     # more calls than entries
expect_bad tc journal "$tmp/j-one-b" 1000 tpm 3 a,b  # a key with one entry
expect_bad tc journal "$tmp/j-delete" 1000 tpm 5 a,b # another operation
expect_bad tc journal "$tmp/j-cause" 1000 tpm 5 a,b
expect_bad tc journal "$tmp/j-signed" 1000 tpm 5 a,b
expect_bad tc journal "$tmp/j-uid" 1000 tpm 5 a,b
expect_bad tc journal "$tmp/j-key" 1000 tpm 5 a,b
expect_bad tc journal "$tmp/j-kind" 1000 tpm 5 a,b
expect_bad tc journal "$tmp/j-nokind" 1000 tpm 5 a,b
expect_bad tc journal "$tmp/j-secret" 1000 tpm 5 a,b e2e-password
expect_bad tc journal "$tmp/missing" 1000 tpm 5 a,b
# the journal of the deletes
{ entry 1000 tpm a delete deleted -; entry 1000 tpm b delete deleted -; } > "$tmp/del-ok"
{ entry 1000 tpm a delete deleted -; } > "$tmp/del-one"
{ entry 1000 tpm a delete deleted -; entry 1000 tpm b delete deleted -; entry 1000 tpm b delete deleted -; } > "$tmp/del-twice"
{ entry 1000 tpm a delete deleted -; entry 1000 tpm b delete authorization_unavailable -; } > "$tmp/del-outcome"
{ entry 1000 tpm a delete deleted -; entry 1000 tpm b sign signing_failed key_lost; } > "$tmp/del-op"
expect_ok tc deljournal "$tmp/del-ok" 1000 a b
expect_bad tc deljournal "$tmp/del-one" 1000 a b
expect_bad tc deljournal "$tmp/del-twice" 1000 a b
expect_bad tc deljournal "$tmp/del-outcome" 1000 a b
expect_bad tc deljournal "$tmp/del-op" 1000 a b
expect_bad tc deljournal "$tmp/del-ok" 1001 tpm a b
# lists
printf 'a\trsa2048\ttpm\nb\tecdsa-p256\ttpm\nother\trsa2048\ttpm\n' > "$tmp/l1"
printf 'a\trsa2048\ttpm\nb\tecdsa-p256\ttpm\n' > "$tmp/l2"
printf 'a\trsa2048\ttpm\nb\tecdsa-p256\tencrypted-host\n' > "$tmp/l-kind"
printf 'a\trsa2048\ttpm\n' > "$tmp/l-one"
printf 'a\trsa2048\ttpm\na\trsa2048\ttpm\nb\tecdsa-p256\ttpm\n' > "$tmp/l-dup"
printf 'other\trsa2048\ttpm\n' > "$tmp/l-gone"
expect_ok tc listed "$tmp/l1" tpm a b
expect_bad tc listed "$tmp/l-one" tpm a b
expect_bad tc listed "$tmp/l-kind" tpm a b
expect_bad tc listed "$tmp/l-dup" tpm a b
expect_bad tc listed "$tmp/missing" tpm a b
expect_ok tc samelist "$tmp/l1" "$tmp/l2" a b
expect_bad tc samelist "$tmp/l1" "$tmp/l-kind" a b
expect_bad tc samelist "$tmp/l1" "$tmp/l-one" a b
expect_bad tc samelist "$tmp/l-one" "$tmp/l1" a b
expect_ok tc gone "$tmp/l-gone" a b
expect_bad tc gone "$tmp/l1" a b
expect_bad tc gone "$tmp/l-one" a b
printf 'id: a\n  type: rsa2048\n  kind: tpm\n\nid: b\n  type: ecdsa-p256\n  kind: tpm\n' > "$tmp/c-ok"
printf 'id: a\n  type: rsa2048\n  kind: tpm\n\nid: b\n  type: ecdsa-p256\n  kind: encrypted-tpm\n' > "$tmp/c-kind"
printf 'id: a\n  type: rsa2048\n  kind: tpm\n' > "$tmp/c-one"
expect_ok tc clilist "$tmp/c-ok" tpm a b
expect_bad tc clilist "$tmp/c-kind" tpm a b
expect_bad tc clilist "$tmp/c-one" tpm a b
expect_bad tc clilist "$tmp/missing" tpm a b
# the state directory
printf 'f /var/lib/custodio/1000/a 600 100\nabc  /var/lib/custodio/1000/a\n' > "$tmp/s1"
printf 'f /var/lib/custodio/1000/a 600 101\nabd  /var/lib/custodio/1000/a\n' > "$tmp/s2"
: > "$tmp/s-empty"
expect_ok tc state "$tmp/s1" "$tmp/s1"
expect_bad tc state "$tmp/s1" "$tmp/s2"
expect_bad tc state "$tmp/s-empty" "$tmp/s-empty"
expect_bad tc state "$tmp/s1" "$tmp/missing"
# records (tpmdup.py scan: uid, id, kind, parent name)
printf '1000\ta\ttpm\t0b\n1000\tb\ttpm\t0b\n' > "$tmp/r2"
printf '1000\ta\ttpm\t0b\n' > "$tmp/r1"
printf '1000\ta\ttpm\t0b\n1000\tb\tencrypted-host\t\n' > "$tmp/r-kind"
: > "$tmp/r0"
expect_ok tc records "$tmp/r2" present tpm a b
expect_bad tc records "$tmp/r1" present tpm a b
expect_bad tc records "$tmp/r-kind" present tpm a b
expect_ok tc records "$tmp/r0" absent tpm a b
expect_bad tc records "$tmp/r1" absent tpm a b
# the owner-hierarchy name
n1=$(printf '000b%064d' 1)
n2=$(printf '000b%064d' 2)
echo "$n1" > "$tmp/n1"; echo "$n2" > "$tmp/n2"; echo 'ERROR: no' > "$tmp/n-err"
expect_ok tc owner "$tmp/n1" "$tmp/n2"
expect_bad tc owner "$tmp/n1" "$tmp/n1" # the seed did not change
expect_bad tc owner "$tmp/n1" "$tmp/n-err"
expect_bad tc owner "$tmp/missing" "$tmp/n2"
# exit statuses
expect_ok tc rc "$tmp/rc0" delete
expect_bad tc rc "$tmp/rc1" delete
expect_bad tc rc "$tmp/missing" delete

# ---- F163: a VM run (E2E_VM=1) of tpmclear-run.sh on fixtures. The stub guest (scripts/lib/e2e-tpmclear-stub.py) is a TPM seed in a directory that tpm2_clear changes; alice keeps real openssl keys
# and her signatures fail after the clear; the reader is the real one on synthetic stored records. Route A: the clear goes to the guest's own TPM (the resource manager), no second swtpm, no drop-in.
# shellcheck source=scripts/lib/e2e-vm-cred-fixtures.sh
source "$ROOT/scripts/lib/e2e-vm-cred-fixtures.sh"
E=$ROOT/e2e
STUB=$ROOT/scripts/lib/e2e-tpmclear-stub.py
cred "$tmp/ok.cred" ef4ac13679a9480ea7db68897f9f165d 0
cred "$tmp/pcrmask.cred" ef4ac13679a9480ea7db68897f9f165d 0x80
for k in tc-rsa tc-ec rsa1 ec1; do rec "$tmp/st-ok" $k 2 "$tmp/ok.cred"; done
for k in tc-rsa tc-ec rsa1; do rec "$tmp/st-kpcr" $k 2 "$tmp/ok.cred"; done
rec "$tmp/st-kpcr" ec1 2 "$tmp/pcrmask.cred"
rec "$tmp/st-pcr" tc-rsa 2 "$tmp/ok.cred"; rec "$tmp/st-pcr" tc-ec 2 "$tmp/pcrmask.cred"
mkdir -p "$tmp/st-none" "$tmp/stub"
for t in tpm2_clear tpm2_createprimary tpm2_readpublic tpm2_flushcontext pkcs11-tool busctl journalctl systemctl id su scan; do
    printf '#!/usr/bin/env bash\nexec python3 -I -S %s %s "$@"\n' "$STUB" "$t" > "$tmp/stub/$t"
    chmod +x "$tmp/stub/$t"
done
# vmrun NAME TPM VMSTATE [ENV=VAL...]: one run of tpmclear-run.sh (or $RUN_COPY) in the VM form; output $tmp/NAME.out, status $tmp/NAME.rc
vmrun() {
    local n=$1 m=$2 st=$3 w rc=0
    shift 3
    w=$tmp/v-$n
    mkdir -p "$w/stub" "$w/work" "$w/state"
    # the setup keys guest.sh keeps in a VM run (F163); the runs of a name starting with nokeep have none
    case $n in nokeep*) ;; *) mkdir -p "$w/work/setup-keep" && : > "$w/work/setup-keep/rsa1.p12" && : > "$w/work/setup-keep/ec1.p12" ;; esac
    env PATH="$tmp/stub:$PATH" WORK="$w/work" MODULE=/nonexistent E2E_SELECT_FILE=/nonexistent E2E_VM=1 E2E_TPM="$m" STUB_STATE="$w/stub" TC_STATE_DIR="$w/state" TC_SCAN="$tmp/stub/scan" \
        STUB_TCTI_LOG="$w/tcti.log" TPM2TOOLS_TCTI=must-not-be-used VM_STATE_DIR="$st" VM_CRED_DIR="$E/vm" VM_SYSTEMD_VERSION=259 "$@" bash "${RUN_COPY:-$E/tpmclear-run.sh}" > "$tmp/$n.out" 2>&1 || rc=$?
    echo $rc > "$tmp/$n.rc"
}
mkdir "$tmp/ctl"
cp "$E"/tpmclear-run.sh "$E"/tpmclear.py "$E"/tpmclear-cases.sh "$E"/tpmdup.py "$E"/report.sh "$E"/select.sh "$E"/tpmkind-lib.sh "$E"/tpm-lib.sh "$tmp/ctl/"
cp -r "$E/vm" "$tmp/ctl/vm"
# shellcheck disable=SC2016 # the pattern is literal text of the script
sed -i 's/vm_read_credential "\$id"/true/' "$tmp/ctl/tpmclear-run.sh"
cmp -s "$E/tpmclear-run.sh" "$tmp/ctl/tpmclear-run.sh" && bad "the control copy of tpmclear-run.sh without the reader call changes nothing"
export -f vmrun
export tmp ROOT E STUB
vmrun full swtpm "$tmp/st-none" STUB_KIND=tpm &
vmrun lack lacking "$tmp/st-ok" STUB_KIND=encrypted-tpm &
vmrun full-etpm swtpm "$tmp/st-none" STUB_KIND=encrypted-tpm &
vmrun lack-tpm lacking "$tmp/st-ok" STUB_KIND=tpm &
vmrun lack-host lacking "$tmp/st-ok" STUB_KIND=encrypted-host &
vmrun lack-pcr lacking "$tmp/st-pcr" STUB_KIND=encrypted-tpm &
vmrun lack-nocred lacking "$tmp/st-none" STUB_KIND=encrypted-tpm &
RUN_COPY=$tmp/ctl/tpmclear-run.sh vmrun lack-noreader lacking "$tmp/st-pcr" STUB_KIND=encrypted-tpm &
vmrun none none "$tmp/st-none" &
vmrun nokeep-lack lacking "$tmp/st-ok" STUB_KIND=encrypted-tpm &
vmrun restdel swtpm "$tmp/st-none" STUB_RESTOREFAIL=delete &
vmrun restimp swtpm "$tmp/st-none" STUB_RESTOREFAIL=import &
vmrun lack-kpcr lacking "$tmp/st-kpcr" STUB_KIND=encrypted-tpm &
vmrun noclear swtpm "$tmp/st-none" STUB_NOCLEAR=1 &
vmrun signafter swtpm "$tmp/st-none" STUB_SIGNAFTER=1 &
vmrun nojournal swtpm "$tmp/st-none" STUB_NOJOURNAL=1 &
vmrun jr-sign swtpm "$tmp/st-none" STUB_JOURNAL=sign &
vmrun jr-secret swtpm "$tmp/st-none" STUB_JOURNAL=secret &
vmrun jr-kind swtpm "$tmp/st-none" STUB_JOURNAL=kind &
vmrun text swtpm "$tmp/st-none" STUB_TEXT=other &
vmrun lose swtpm "$tmp/st-none" STUB_LOSEKEY=1 &
vmrun kindafter swtpm "$tmp/st-none" STUB_KINDAFTER=encrypted-host &
vmrun delfail swtpm "$tmp/st-none" STUB_DELFAIL=1 &
wait
vr() { cat "$tmp/$1.rc" 2> /dev/null || echo missing; }
vran() { grep -q "^E2E-CASE run $2\$" "$tmp/$1.out"; }
vgood() { # NAME: the run passes and reports the three cases once
    [ "$(vr "$1")" = 0 ] || { bad "VM $1: a good run fails ($(vr "$1")): $(tail -n 4 "$tmp/$1.out")"; return; }
    for c in $ids; do vran "$1" "$c" || bad "VM $1: $c is not reported run"; done
    [ "$(grep -c '^E2E-CASE run ' "$tmp/$1.out")" = 3 ] || bad "VM $1: the cases are not reported exactly once"
}
vrefused() { # NAME CASE...: the run fails and the cases are not reported
    local n=$1
    shift
    [ -s "$tmp/$n.out" ] || { bad "VM $n: no output (it did not run)"; return; }
    [ "$(vr "$n")" != 0 ] || { bad "VM $n: passes on bad evidence"; return; }
    for c in "$@"; do ! vran "$n" "$c" || bad "VM $n: $c is reported run on bad evidence"; done
}
vgood full
vgood lack
# route A: the clear and the primary go to the guest's TPM; nothing is pointed at a second one
for n in full lack; do
    grep -q '^tpm2_clear device:/dev/tpmrm0$' "$tmp/v-$n/tcti.log" || bad "VM $n: tpm2_clear did not go to the guest's resource manager"
    ! grep -qv ' device:/dev/tpmrm0$' "$tmp/v-$n/tcti.log" || bad "VM $n: a tpm2 command used another TCTI"
    ! grep -q 'second TPM' "$tmp/$n.out" || bad "VM $n: a second TPM was started"
done
# F163: the setup keys are deleted and imported again after the clear (a real fault of the first real run), and the reader runs on them in lacking
for n in full lack; do
    [ "$(tr '\n' ' ' < "$tmp/v-$n/stub/restore.log" 2> /dev/null)" = "delete rsa1 import rsa1 delete ec1 import ec1 " ] || bad "VM $n: the setup keys rsa1 and ec1 were not deleted and imported again, in that order"
done
[ ! -e "$tmp/v-nokeep-lack/stub/restore.log" ] || bad "VM nokeep: restore ran without setup-keep"
vgood nokeep-lack
vrefused lack-kpcr
grep -q 'reader: ec1' "$tmp/lack-kpcr.out" || bad "VM lacking: the reader was not run on the restored ec1"
vrefused restdel
vrefused restimp
grep -q 'reader: tc-rsa\|key tc-rsa' "$tmp/lack.out" || bad "VM lacking: the reader was not run on tc-rsa"
! grep -q 'reader:' "$tmp/full.out" || bad "VM full: the reader was called"
vrefused full-etpm tpm-clear-sign-fails
vrefused lack-tpm tpm-clear-sign-fails
vrefused lack-host tpm-clear-sign-fails
vrefused lack-pcr
grep -q 'did not pass the reader' "$tmp/lack-pcr.out" || bad "VM lacking: a failing reader is not named"
vrefused lack-nocred
[ "$(vr lack-noreader)" = 0 ] || bad "VM lacking: the control copy without the reader call should pass the PCR-bound credential (the test would not see a missing call)"
vrefused none  # a VM has a TPM: mode none is not a VM mode
vrefused noclear tpm-clear-sign-fails
vrefused signafter tpm-clear-sign-fails
vrefused nojournal tpm-clear-sign-fails
vrefused jr-sign tpm-clear-sign-fails
vrefused jr-secret tpm-clear-sign-fails
vrefused jr-kind tpm-clear-sign-fails
vrefused text tpm-clear-sign-fails
vrefused lose tpm-clear-keys-listed
vrefused kindafter tpm-clear-keys-listed
vrefused delfail tpm-clear-delete

for f in tpmclear-run.sh tpmclear-user.sh tpmclear-cases.sh; do bash -n "$ROOT/e2e/$f" || bad "$f does not parse"; done
python3 -I -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$ROOT/e2e/tpmclear-sign.py" || bad "tpmclear-sign.py does not parse"
exit "$fail"
