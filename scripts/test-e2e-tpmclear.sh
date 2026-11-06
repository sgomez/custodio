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
check() { CHECK_TPM_MODE=$1 bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$2" "$3" > /dev/null 2>&1; }
check none "$D/skip.list" "$tmp/out-all" || bad "mode none: the skips are refused"
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

for f in tpmclear-run.sh tpmclear-user.sh tpmclear-cases.sh; do bash -n "$ROOT/e2e/$f" || bad "$f does not parse"; done
python3 -I -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$ROOT/e2e/tpmclear-sign.py" || bad "tpmclear-sign.py does not parse"
exit "$fail"
