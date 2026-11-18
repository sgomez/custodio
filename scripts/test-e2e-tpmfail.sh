#!/usr/bin/env bash
# F139: container-free checks of the tpmfail-* cases: the judgements of e2e/tpmfail.py on good and bad records of each of the five facts, and the failing TPM stub against a fake
# upstream. NOT checked here: a real run (`just e2e-cases debian13 'tpmfail-*'` in swtpm, none and lacking).
# shellcheck disable=SC2086 # the ids are words
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-tpmfail: $*" >&2; fail=1; }
tf() { python3 -I "$ROOT/e2e/tpmfail.py" "$@"; }

expect_ok() { local out; out=$("$@") || { bad "failed to run: $*"; return; }; [ -z "$out" ] || bad "good evidence rejected ($*): $out"; }
expect_bad() { local out; out=$("$@" 2>&1) || true; [ -n "$out" ] || bad "bad evidence accepted ($*)"; }

# (a) the import failed with the documented error
printf 'Password for x.p12: \ncustodio: the TPM failed or cannot be used; nothing was stored\n' > "$tmp/out-ok"
printf 'Password for x.p12: \ncustodio: the credential service is unavailable; nothing was stored\n' > "$tmp/out-cred"
printf 'Password for x.p12: \nok    k  rsa2048  tpm\n' > "$tmp/out-success"
printf 'custodio: the TPM failed or cannot be used; nothing was stored\nok    k  rsa2048  tpm\n' > "$tmp/out-both"
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
printf 'warn  k  rsa2048  encrypted-host\n      root, and anyone with a copy of /var/lib, can use this key.\n' > "$tmp/out-weak"
printf 'warn  k  rsa2048  encrypted-tpm\n      root can use this key while the machine runs.\n' > "$tmp/out-weak2"
expect_bad tf noweaker "$tmp/out-weak" "$tmp/list-ok" "$tmp/j-ok" k
expect_bad tf noweaker "$tmp/out-weak2" "$tmp/list-ok" "$tmp/j-ok" k
expect_bad tf noweaker "$tmp/out-ok" "$tmp/list-kweak" "$tmp/j-ok" k
expect_bad tf noweaker "$tmp/out-ok" "$tmp/list-ok" "$tmp/j-kind" k
printf 'Password for x.p12: \nok    k  rsa2048  tpm\n\nNext:\n  shred -u x.p12   the file still holds your private key\n' > "$tmp/out-tpm"
printf 'warn  k  rsa2048  encrypted-tpm\n      root can use this key while the machine runs.\n' > "$tmp/out-etpm"
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
