#!/usr/bin/env bash
# The swtpm profile of the `lacking` VM mode (e2e/vm/lacking-rsa.json, docs/findings/F152.md): swtpm's default commands minus exactly
# TPM2_RSA_Decrypt (0x159) and TPM2_Sign (0x15d), with rsa and P-256 kept. A real `lacking` run only shows those two are missing, not that
# nothing else is. Each control is a copy with one change, on which the check must fail.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PROFILE=$ROOT/e2e/vm/lacking-rsa.json
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-vm-profile: $*" >&2; fail=1; }

check() { # FILE: prints why the profile is wrong and fails
    python3 -I - "$1" 2>&1 << 'PY'
import json, sys

def cmds(s):
    out = set()
    for part in s.split(","):
        a, _, b = part.partition("-")
        out |= set(range(int(a, 16), int(b or a, 16) + 1))
    return out

DEFAULT = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197,0x199-0x19c"
text = open(sys.argv[1]).read()
p = json.loads(text)
got, want = cmds(p["Commands"]), cmds(DEFAULT) - {0x159, 0x15D}
if got != want:
    sys.exit("Commands differ from the default minus 0x159 and 0x15d: missing %s extra %s" % (sorted(map(hex, want - got)), sorted(map(hex, got - want))))
algs = set(p["Algorithms"].split(","))
if "rsa" not in algs or "ecc-nist-p256" not in algs:
    sys.exit("Algorithms lost rsa or ecc-nist-p256")
for b in ("ecc-min-size=384", "rsa-min-size=3072"):
    if b in text:
        sys.exit("profile holds " + b)
if p.get("Name") != "custom":
    sys.exit("Name is not custom")
PY
}

r=$(check "$PROFILE") || bad "$r"

control() { # NAME OLD NEW: a copy with OLD replaced by NEW must fail the check
    local c=$tmp/$1.json
    python3 -I - "$PROFILE" "$c" "$2" "$3" << 'PY'
import sys
src, dst, old, new = sys.argv[1:]
s = open(src).read()
if old not in s:
    sys.exit("control: text not found: %r" % old)
open(dst, "w").write(s.replace(old, new, 1))
PY
    if check "$c" > /dev/null; then bad "control $1: the check passed"; fi
}
control keep-sign '0x15b-0x15c,0x15e' '0x15b-0x15e'
control keep-decrypt '0x142-0x158' '0x142-0x159'
control drop-other '0x160-0x165' '0x161-0x165'
control ecc384 'ecc-min-size=192' 'ecc-min-size=384'
control rsa3072 'rsa-min-size=1024' 'rsa-min-size=3072'
control drop-alg 'ecc-nist-p256,' ''

[ "$fail" -eq 0 ] || exit 1
echo "test-vm-profile: ok"
