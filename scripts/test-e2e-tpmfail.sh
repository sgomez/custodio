#!/usr/bin/env bash
# F139: container-free checks of the tpmfail-* cases: the placement (debian13 list and skip list, group), the accounting (a skip refused in swtpm, accepted in none and lacking; a
# case reported run refused in none and lacking), the judgements of e2e/tpmfail.py on good and bad records of each of the five facts, and the failing TPM stub against a fake
# upstream. NOT checked here: a real run (`just e2e-cases debian13 'tpmfail-*'` in swtpm, none and lacking).
# shellcheck disable=SC2086 # the ids are words
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-tpmfail: $*" >&2; fail=1; }
D=$ROOT/e2e/targets/debian13
ids="tpmfail-device-unopenable tpmfail-tpm-error tpmfail-credentials-down-tpm-lacking tpmfail-credentials-down-host"
tf() { python3 -I "$ROOT/e2e/tpmfail.py" "$@"; }

# placement
for id in $ids; do
    grep -qx "$id" "$D/cases.list" || bad "$id is not in $D/cases.list"
    grep -q "^$id:" "$D/skip.list" || bad "$id is not on the skip list of debian13"
    ! grep -qx "$id" "$ROOT/e2e/cases.list" || bad "$id is in e2e/cases.list (every target)"
    ! grep -rlx "$id" "$ROOT"/e2e/targets/*/cases.list | grep -qv debian13 || bad "$id is listed by another target"
done
[ "$(grep -c '^tpmfail-' "$D/cases.list")" = 4 ] || bad "debian13 cases.list lists other tpmfail cases than the four"
# shellcheck source=e2e/select.sh
source "$ROOT/e2e/select.sh"
for id in $ids tpmfail-x; do [ "$(case_group "$id")" = tpmfail ] || bad "case_group $id is '$(case_group "$id")', expected tpmfail"; done
# shellcheck source=e2e/tpmfail-cases.sh
source "$ROOT/e2e/tpmfail-cases.sh"
[ "$(printf '%s\n' $TPMFAIL_CASES | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "TPMFAIL_CASES differ from the listed cases"

# accounting
printf '%s\n' $ids > "$tmp/cases"
( E2E_SELECT_FILE=$tmp/cases; export E2E_SELECT_FILE; tpmfail_skip_all none ) > "$tmp/out-all"
[ "$(grep -c '^E2E-CASE skipped tpmfail-' "$tmp/out-all")" = 4 ] || bad "the guest does not report four skips"
grep -q 'E2E_TPM=none' "$tmp/out-all" || bad "the skip reason does not name the mode"
sed 's/^E2E-CASE skipped /E2E-CASE run /' "$tmp/out-all" > "$tmp/out-run"
awk '/^E2E-CASE run / && !done { sub(/run/, "skipped"); done = 1 } { print }' "$tmp/out-run" > "$tmp/out-one"
sed -n 's/^E2E-CASE skipped \(.*\)/\1: not applicable/p' "$tmp/out-all" > "$tmp/skip-all"
check() { CHECK_TPM_MODE=$1 bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$2" "$3" > /dev/null 2>&1; }
check swtpm "$D/skip.list" "$tmp/out-run" || bad "mode swtpm: run cases are refused"
! check swtpm "$D/skip.list" "$tmp/out-all" || bad "mode swtpm: skipped cases are accepted"
! check swtpm "$D/skip.list" "$tmp/out-one" || bad "mode swtpm: one skipped case is accepted"
! check swtpm "$tmp/skip-all" "$tmp/out-all" || bad "mode swtpm: a skip list naming the cases lets the skips through"
for m in none lacking; do
    check $m "$D/skip.list" "$tmp/out-all" || bad "mode $m: the skips are refused"
    ! check $m "$D/skip.list" "$tmp/out-run" || bad "mode $m: run cases are accepted"
    ! check $m "$D/skip.list" "$tmp/out-one" || bad "mode $m: one run case is accepted"
    echo "# none" > "$tmp/skip-empty"
    ! check $m "$tmp/skip-empty" "$tmp/out-all" || bad "mode $m: skips are accepted with no skip list"
done

expect_ok() { local out; out=$("$@") || { bad "failed to run: $*"; return; }; [ -z "$out" ] || bad "good evidence rejected ($*): $out"; }
expect_bad() { local out; out=$("$@" 2>&1) || true; [ -n "$out" ] || bad "bad evidence accepted ($*)"; }

# (a) the import failed with the documented error
E=com.rfirma.Custodio1.Error
printf 'Password for x.p12: \ncustodio: the service answered with an unknown error (%s.TpmFailed)\n' "$E" > "$tmp/out-ok"
printf 'Password for x.p12: \ncustodio: the service answered with an unknown error (%s.CredentialsUnavailable)\n' "$E" > "$tmp/out-cred"
printf "Password for x.p12: \nImported key 'k' (rsa2048).\nStorage: tpm. The key is in the TPM.\n" > "$tmp/out-success"
printf "custodio: the service answered with an unknown error (%s.TpmFailed)\nImported key 'k' (rsa2048).\n" "$E" > "$tmp/out-both"
printf 'custodio: internal error\n' > "$tmp/out-other"
echo 1 > "$tmp/rc1"; echo 0 > "$tmp/rc0"; echo x > "$tmp/rcx"
expect_ok tf failed "$tmp/out-ok" "$tmp/rc1" TpmFailed
expect_ok tf failed "$tmp/out-cred" "$tmp/rc1" CredentialsUnavailable
expect_bad tf failed "$tmp/out-ok" "$tmp/rc0" TpmFailed                  # exit status 0
expect_bad tf failed "$tmp/out-ok" "$tmp/rcx" TpmFailed                  # not a status
expect_bad tf failed "$tmp/out-ok" "$tmp/missing" TpmFailed              # no status at all
expect_bad tf failed "$tmp/out-success" "$tmp/rc0" TpmFailed             # a success line
expect_bad tf failed "$tmp/out-both" "$tmp/rc1" TpmFailed                # the error and a success line
expect_bad tf failed "$tmp/out-other" "$tmp/rc1" TpmFailed               # another error
expect_bad tf failed "$tmp/out-cred" "$tmp/rc1" TpmFailed                # the wrong documented error

# (b) nothing stored
printf 'd /var/lib/custodio/ 700 4096\nf /var/lib/custodio/1000/rsa1 600 100\n' > "$tmp/st-before"
cp "$tmp/st-before" "$tmp/st-same"
printf 'd /var/lib/custodio/ 700 4096\nf /var/lib/custodio/1000/rsa1 600 100\nf /var/lib/custodio/1000/.tmp-k 600 5\n' > "$tmp/st-temp"
printf 'd /var/lib/custodio/ 700 4096\nf /var/lib/custodio/1000/rsa1 600 101\n' > "$tmp/st-size"
: > "$tmp/st-empty"
printf 'rsa1\trsa2048\ttpm\n' > "$tmp/list-ok"
printf 'rsa1\trsa2048\ttpm\nk\trsa2048\ttpm\n' > "$tmp/list-k"
printf 'rsa1\trsa2048\ttpm\nk\trsa2048\tencrypted-host\n' > "$tmp/list-kweak"
expect_ok tf nothing "$tmp/st-before" "$tmp/st-same" "$tmp/list-ok" k
expect_bad tf nothing "$tmp/st-before" "$tmp/st-temp" "$tmp/list-ok" k   # a temporary file left
expect_bad tf nothing "$tmp/st-before" "$tmp/st-size" "$tmp/list-ok" k   # a file changed
expect_bad tf nothing "$tmp/st-before" "$tmp/st-same" "$tmp/list-k" k    # the id is listed
expect_bad tf nothing "$tmp/st-empty" "$tmp/st-empty" "$tmp/list-ok" k   # no listing to compare
expect_bad tf nothing "$tmp/st-before" "$tmp/missing" "$tmp/list-ok" k

# (c) one journal entry
entry() { # CAUSE [EXTRA-JSON-FIELDS]
    printf '{"CUSTODIO_OPERATION":"import","CUSTODIO_OUTCOME":"storage_failure","CUSTODIO_CAUSE":"%s","CUSTODIO_KEY_ID":"k","MESSAGE":"import failed after approval, key not stored"%s}\n' "$1" "${2:-}"
}
entry tpm_device > "$tmp/j-ok"
{ entry tpm_device; entry tpm_device; } > "$tmp/j-two"
: > "$tmp/j-none"
entry tpm_error > "$tmp/j-cause"
entry tpm_device ',"CUSTODIO_STORAGE_KIND":"encrypted-host"' > "$tmp/j-kind"
entry tpm_device ',"EXTRA":"the password e2e-password"' > "$tmp/j-secret"
entry tpm_device ',"EXTRA":"AABBCCDD"' > "$tmp/j-secret2"
sed 's/storage_failure/stored/' "$tmp/j-ok" > "$tmp/j-outcome"
sed 's/"CUSTODIO_KEY_ID":"k"/"CUSTODIO_KEY_ID":"other"/' "$tmp/j-ok" > "$tmp/j-id"
sed 's/"CUSTODIO_OPERATION":"import"/"CUSTODIO_OPERATION":"delete"/' "$tmp/j-ok" > "$tmp/j-op"
sed 's/"CUSTODIO_CAUSE":"tpm_device",//' "$tmp/j-ok" > "$tmp/j-nocause"
expect_ok tf journal "$tmp/j-ok" k tpm_device e2e-password AABBCCDD
expect_bad tf journal "$tmp/j-two" k tpm_device e2e-password   # two entries
expect_bad tf journal "$tmp/j-none" k tpm_device e2e-password  # no entry
expect_bad tf journal "$tmp/j-cause" k tpm_device e2e-password # a wrong cause
expect_bad tf journal "$tmp/j-kind" k tpm_device e2e-password  # a stored kind
expect_bad tf journal "$tmp/j-secret" k tpm_device e2e-password
expect_bad tf journal "$tmp/j-secret2" k tpm_device e2e-password AABBCCDD
expect_bad tf journal "$tmp/j-outcome" k tpm_device e2e-password
expect_bad tf journal "$tmp/j-id" k tpm_device e2e-password
expect_bad tf journal "$tmp/j-op" k tpm_device e2e-password
expect_bad tf journal "$tmp/j-nocause" k tpm_device e2e-password
expect_bad tf journal "$tmp/missing" k tpm_device e2e-password

# (d) no weaker kind, and a later import (or a control) with exactly the kind
expect_ok tf noweaker "$tmp/out-ok" "$tmp/list-ok" "$tmp/j-ok" k
printf 'rsa1\trsa2048\tencrypted-host\n' > "$tmp/list-other-weak"
expect_ok tf noweaker "$tmp/out-ok" "$tmp/list-other-weak" "$tmp/j-ok" k # another key's kind is not this attempt's
printf "Imported key 'k' (rsa2048).\nStorage: encrypted-host. This key is weaker than a TPM key.\n" > "$tmp/out-weak"
printf "Imported key 'k' (rsa2048).\nStorage: encrypted-tpm. This key is weaker.\n" > "$tmp/out-weak2"
expect_bad tf noweaker "$tmp/out-weak" "$tmp/list-ok" "$tmp/j-ok" k
expect_bad tf noweaker "$tmp/out-weak2" "$tmp/list-ok" "$tmp/j-ok" k
expect_bad tf noweaker "$tmp/out-ok" "$tmp/list-kweak" "$tmp/j-ok" k
expect_bad tf noweaker "$tmp/out-ok" "$tmp/list-ok" "$tmp/j-kind" k
printf "Password for x.p12: \nImported key 'k' (rsa2048).\nStorage: tpm. The key is in the TPM and cannot be copied out of it.\n" > "$tmp/out-tpm"
printf "Imported key 'k' (rsa2048).\nStorage: encrypted-tpm. The key is in a credential.\n" > "$tmp/out-etpm"
expect_ok tf kind "$tmp/out-tpm" "$tmp/list-k" k tpm
expect_ok tf kind "$tmp/out-weak" "$tmp/list-kweak" k encrypted-host
expect_bad tf kind "$tmp/out-tpm" "$tmp/list-kweak" k tpm              # listed with another kind
expect_bad tf kind "$tmp/out-weak" "$tmp/list-k" k tpm                 # the CLI says another kind
expect_bad tf kind "$tmp/out-etpm" "$tmp/list-k" k tpm                 # encrypted-tpm is not tpm
expect_bad tf kind "$tmp/out-tpm" "$tmp/list-ok" k tpm                 # not listed
expect_bad tf kind "$tmp/out-ok" "$tmp/list-k" k tpm                   # a failure, not an import
expect_bad tf kind "$tmp/out-tpm" "$tmp/list-k" other tpm
expect_bad tf kind "$tmp/out-tpm" "$tmp/missing" k tpm
expect_bad tf nothing
expect_bad tf bogus

# the failing TPM stub, against a fake upstream
python3 -I - "$ROOT/e2e/tpmfail-stub.py" "$tmp" << 'PY' || bad "the stub test failed"
import os, socket, struct, subprocess, sys, threading, time

stub, tmp = sys.argv[1:3]


def response(rc, body=b""):
    return struct.pack(">HII", 0x8001, 10 + len(body), rc) + body


def serve(path, seen):
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(4)

    def run():
        while True:
            c, _ = srv.accept()
            while True:
                head = c.recv(10, socket.MSG_WAITALL)
                if len(head) < 10:
                    break
                size = struct.unpack(">I", head[2:6])[0]
                rest = c.recv(size - 10, socket.MSG_WAITALL) if size > 10 else b""
                code = struct.unpack(">I", head[6:10])[0]
                seen.append(code)
                if code == 0x17A:  # three algorithms: rsa, sha256, ecc
                    ents = b"".join(struct.pack(">HI", a, 0) for a in (1, 0xB, 0x23))
                    c.sendall(response(0, b"\0" + struct.pack(">II", 0, 3) + ents))
                else:
                    c.sendall(response(0, b"ok"))
    threading.Thread(target=run, daemon=True).start()


def cmd(code, body=b""):
    return struct.pack(">HII", 0x8001, 10 + len(body), code) + body


def ask(path, message):
    s = socket.socket(socket.AF_UNIX)
    s.connect(path)
    s.sendall(message)
    head = s.recv(10, socket.MSG_WAITALL)
    size = struct.unpack(">I", head[2:6])[0]
    body = s.recv(size - 10, socket.MSG_WAITALL) if size > 10 else b""
    s.close()
    return struct.unpack(">I", head[6:10])[0], body


def start(mode):
    path = os.path.join(tmp, f"stub-{mode}.sock")
    p = subprocess.Popen([sys.executable, "-I", stub, path, up, mode], stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "ready"
    return p, path


up = os.path.join(tmp, "up.sock")
seen = []
serve(up, seen)
caps = cmd(0x17A, struct.pack(">III", 0, 0, 64))
parms = lambda alg: cmd(0x18A, struct.pack(">H", alg) + b"\0\0\0\0")
problems = []
p, path = start("fail-capability")
rc, _ = ask(path, caps)
if rc != 0x101:
    problems.append(f"fail-capability: GetCapability gave {rc:#x}")
before = len(seen)
if ask(path, cmd(0x144))[0] != 0 or len(seen) != before + 1:
    problems.append("fail-capability: another command does not pass through")
if 0x17A in seen:
    problems.append("fail-capability: the capability query reached the upstream")
p.kill()
p, path = start("lack-rsa")
rc, body = ask(path, parms(1))
if rc != 0x1CA:
    problems.append(f"lack-rsa: TestParms of RSA gave {rc:#x}")
if ask(path, parms(0x23))[0] != 0:
    problems.append("lack-rsa: TestParms of ECC does not pass")
rc, body = ask(path, caps)
algs = [struct.unpack(">H", body[9 + 6 * i:11 + 6 * i])[0] for i in range(struct.unpack(">I", body[5:9])[0])]
if rc != 0 or algs != [0xB, 0x23]:
    problems.append(f"lack-rsa: the algorithm list is {algs} with rc {rc:#x}")
p.kill()
if subprocess.run([sys.executable, "-I", stub, os.path.join(tmp, "x.sock"), up, "nonsense"], capture_output=True).returncode == 0:
    problems.append("an unknown mode is accepted")
print("\n".join(problems))
sys.exit(1 if problems else 0)
PY

[ "$fail" -eq 0 ] || exit 1
echo "test-e2e-tpmfail: passed"
