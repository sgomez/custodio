#!/usr/bin/env bash
# Self-test of journal.py with synthetic journal streams: every check must pass on a clean stream and
# fail on each planted defect. Needs only bash and python3; runs locally and first in guest.sh.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT

# Writes the streams and $t/cases: "<pass|fail> <name> <journal.py arguments>".
T=$t HERE=$here python3 -I - <<'PY'
import base64, hashlib, json, os, random
T = os.environ["T"]
MID = "29c3d30e6c4242406c6db3f120d36401"
rng = random.Random()
cases = []

def w(name, data):
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(os.path.join(T, name), mode) as f:
        f.write(data)
    return os.path.join(T, name)

LEDGER = [("signed", "rsa1", "101", "1000"), ("denied", "ec1", "102", "1000"),
          ("authorization_unavailable", "rsa1", "103", "1000")]
TEXT = {"signed": ("signature made", "6"), "denied": ("signature denied", "5"),
        "authorization_unavailable": ("authorization unavailable, no signature", "4")}

def entry(outcome, key, pid, uid, **over):
    text, prio = TEXT[outcome]
    e = {"_SYSTEMD_UNIT": "custodio.service", "_UID": "990", "MESSAGE_ID": MID, "PRIORITY": prio,
         "CUSTODIO_UID": uid, "CUSTODIO_PID": pid, "CUSTODIO_KEY_ID": key, "CUSTODIO_OUTCOME": outcome,
         "MESSAGE": f"{text}: uid {uid} pid {pid} key {key}"}
    e.update(over)
    return {k: v for k, v in e.items() if v is not None}

def good():
    return [entry(*line) for line in LEDGER]

ledger = w("ledger", "".join(" ".join(line) + "\n" for line in LEDGER))

def entries_case(expect, name, entries, *extra):
    path = w(name + ".json", "".join(json.dumps(e) + "\n" for e in entries))
    cases.append(f"{expect} {name} entries --json {path} --ledger {ledger} --uid 990 {' '.join(extra)}")

entries_case("pass", "good", good(), "--expect-total 3 --forbid-pidless")
entries_case("pass", "ignores-no-unit", good() + [entry("signed", "rsa1", "101", "1000", _SYSTEMD_UNIT=None, _UID=None)])
entries_case("pass", "ignores-wrong-uid", good() + [entry("signed", "rsa1", "101", "1000", _UID="1000")])
entries_case("pass", "ignores-forged-duplicate", good() + [entry("signed", "rsa1", "102", "1000", _SYSTEMD_UNIT="other.service")])
g = good()
entries_case("fail", "no-entry", g[1:])
entries_case("fail", "two-entries", g + [g[0]])
entries_case("fail", "duplicate-other-key", g + [entry("signed", "ec1", "101", "1000")])
entries_case("fail", "wrong-uid", [entry("signed", "rsa1", "101", "1001")] + g[1:])
entries_case("fail", "wrong-pid", [entry("signed", "rsa1", "999", "1000")] + g[1:])
entries_case("fail", "wrong-key", [entry("signed", "ec1", "101", "1000")] + g[1:])
entries_case("fail", "wrong-outcome", [entry("signed", "rsa1", "101", "1000", CUSTODIO_OUTCOME="denied")] + g[1:])
entries_case("fail", "wrong-priority", [entry("signed", "rsa1", "101", "1000", PRIORITY="5")] + g[1:])
entries_case("fail", "wrong-message", [entry("signed", "rsa1", "101", "1000", MESSAGE="signature made: uid 1 pid 101 key rsa1")] + g[1:])
entries_case("fail", "forged-instead-of-real", g[1:] + [entry("signed", "rsa1", "101", "1000", _SYSTEMD_UNIT=None)])
# Without the pid filter only the whole-run count sees the extra entry, and without the count only the pid check does.
p = w("pidless.json", "".join(json.dumps(e) + "\n" for e in g + [entry("signed", "rsa1", None, "1000", CUSTODIO_PID=None)]))
cases.append(f"fail count-only entries --json {p} --ledger {ledger} --uid 990 --expect-total 3")
cases.append(f"fail pidless-only entries --json {p} --ledger {ledger} --uid 990 --forbid-pidless")

# Acceptance 8: secrets in an evidence directory, planted in a stream in every form and place.
ev = os.path.join(T, "evidence")
os.mkdir(ev)
data, sig = os.urandom(300), os.urandom(256)
w("evidence/in.bin", data)
w("evidence/sig.bin", sig)
digest = hashlib.sha256(data).digest()
info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
secrets = {"input": data, "digest": digest, "digestinfo": info, "signature": sig, "password": b"e2e-password"}
b64, ub64 = base64.b64encode, base64.urlsafe_b64encode
def hexsep(d, sep):
    h = d.hex()
    return sep.join(h[i:i + 2] for i in range(0, len(h), 2)).encode()
FORMS = {
    "raw": lambda d: d, "hex": lambda d: d.hex().encode(), "HEX": lambda d: d.hex().upper().encode(),
    "colon": lambda d: hexsep(d, ":"), "space": lambda d: hexsep(d, " "),
    "b64-0": lambda d: b64(b"abc" + d), "b64-1": lambda d: b64(b"abcd" + d), "b64-2": lambda d: b64(b"abcde" + d + b"xy"),
    "b64-urlsafe": lambda d: ub64(d), "b64-unpadded": lambda d: b64(d).rstrip(b"="),
    "list": lambda d: b"[" + b", ".join(str(b).encode() for b in d) + b"]",
    "inside-blob": lambda d: b64(b"user:" + d + b":more"),
}
PLACES = {
    "audit": b"_SYSTEMD_UNIT=custodio.service\n_UID=990\nMESSAGE_ID=" + MID.encode() + b"\nMESSAGE=signature made: ",
    "nonaudit": b"_SYSTEMD_UNIT=custodio.service\n_UID=990\nMESSAGE=started ",
    "unit-only": b"UNIT=custodio.service\nMESSAGE=Stopping ",
}
CLEAN = b"__REALTIME_TIMESTAMP=1\n" + PLACES["audit"] + b"uid 1000 pid 101 key rsa1\n\n"
def sweep_case(expect, name, stream, secret=None):
    path = w(name + ".export", stream)
    if secret is not None:
        w(name + ".forbid", secret.hex() + "\n" + b64(secret).decode() + "\n")
    cases.append(f"{expect} {name} sweep --export {path} --evidence {ev} --password e2e-password")
sweep_case("pass", "sweep-clean", CLEAN)
for sname, secret in secrets.items():
    for fname, build in FORMS.items():
        for place, head in PLACES.items():
            if sname == "password" or fname != "inside-blob":
                sweep_case("fail", f"leak-{sname}-{fname}-{place}", CLEAN + head + build(secret) + b"\n\n", secret)
with open(os.path.join(T, "cases"), "w") as f:
    f.write("\n".join(cases) + "\n")
PY

run=0
while read -r expect name args; do
    run=$((run + 1))
    # shellcheck disable=SC2086 # the arguments are words by construction
    if out=$(python3 -I "$here/journal.py" $args 2>&1); then status=0; else status=$?; fi
    case $expect in
        pass) [ "$status" -eq 0 ] || { echo "$out" >&2; echo "selftest: FAIL: $name should pass" >&2; exit 1; } ;;
        fail)
            [ "$status" -eq 1 ] || { echo "selftest: FAIL: $name should fail (exit $status)" >&2; exit 1; }
            # A failure never prints what it found.
            if [ -f "$t/$name.forbid" ] && grep -qFf "$t/$name.forbid" <<< "$out"; then
                echo "selftest: FAIL: $name printed the secret" >&2
                exit 1
            fi
            ;;
    esac
done < "$t/cases"
echo "selftest: $run journal.py cases ok"
