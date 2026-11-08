#!/usr/bin/env bash
# Self-test of the end-to-end harness's credential reader e2e/vm/credread.py (F157), on credentials made by the real
# systemd-creds with swtpm (e2e/vm/mkcreds.sh): each kind is told apart, --expect-tpm-bound passes only for the
# user-scoped host+TPM credential with PCR mask 0, and truncated or corrupted files are reported as malformed.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
READ=$ROOT/e2e/vm/credread.py
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-vm-credread: $*" >&2; fail=1; }

for tool in python3 systemd-creds swtpm unshare tpm2_startup; do
    command -v "$tool" > /dev/null 2>&1 || { echo "test-vm-credread: $tool is not installed" >&2; exit 127; }
done
mkdir "$tmp/c" "$tmp/empty"
"$ROOT/e2e/vm/mkcreds.sh" "$tmp/c" || { echo "test-vm-credread: mkcreds.sh failed" >&2; exit 1; }
c=$tmp/c

# rd FILE [ARGS]: runs the reader with -I from an empty directory; sets out, err, rc.
rd() {
    rc=0
    (cd "$tmp/empty" && python3 -I "$READ" "$@") > "$tmp/out" 2> "$tmp/err" || rc=$?
    out=$(cat "$tmp/out")
    err=$(cat "$tmp/err")
}
tb() { rd "$1" --expect-tpm-bound --systemd-version 257; }

# --- told apart: one name and mask per real credential
check_line() { # file expected-stdout
    rd "$c/$1"
    [ "$rc" = 0 ] && [ "$out" = "$2" ] || bad "$1: rc=$rc out='$out' err='$err', expected '$2'"
}
check_line scoped "host+tpm2-scoped mask 0x0"
check_line scoped-pcr7 "host+tpm2-scoped mask 0x80"
check_line host "host"
check_line host-scoped "host-scoped"
check_line null "null"
check_line tpm2 "tpm2 mask 0x0"
check_line host-tpm2 "host+tpm2 mask 0x0"

# --- --expect-tpm-bound: exit 0 only for the user-scoped host+TPM with mask 0
tb "$c/scoped"
[ "$rc" = 0 ] || bad "expect-tpm-bound: accepted credential rc=$rc err='$err'"
for v in 257 259; do
    rd "$c/scoped" --expect-tpm-bound --systemd-version "$v"
    [ "$rc" = 0 ] || bad "version $v: rc=$rc err='$err'"
done
rd "$c/scoped" --expect-tpm-bound --systemd-version 258
{ [ "$rc" != 0 ] && grep -q 258 <<< "$err"; } || bad "version 258: rc=$rc err='$err'"
rd "$c/scoped" --expect-tpm-bound
{ [ "$rc" != 0 ] && grep -q 'systemd-version' <<< "$err"; } || bad "no version: rc=$rc err='$err'"

declare -A reason=()
refuse() { # label file word
    tb "$2"
    if [ "$rc" = 0 ]; then bad "$1: accepted"; return; fi
    grep -q -- "$3" <<< "$err" || bad "$1: stderr '$err' lacks '$3'"
    grep -q Traceback <<< "$err" && bad "$1: traceback"
    reason[$1]=$err
}
refuse host "$c/host" host-only
refuse host-scoped "$c/host-scoped" host-only
refuse null "$c/null" null
refuse pcr7 "$c/scoped-pcr7" 'mask 0x80'
refuse tpm2 "$c/tpm2" 'TPM-only'
refuse host-tpm2 "$c/host-tpm2" 'not the user-scoped'

# The reasons differ from one another by class.
for pair in "host null" "host pcr7" "host tpm2" "null pcr7" "null tpm2" "pcr7 tpm2" "pcr7 host-tpm2"; do
    read -r a b <<< "$pair"
    [ "${reason[$a]:-x}" != "${reason[$b]:-x}" ] || bad "reasons for $a and $b are the same"
done

# --- binary controls: decode a real credential, cut or patch it, pass raw bytes
bin() { base64 -d "$c/$1" > "$2"; }
patch() { # in out offset hex(little endian, 4 bytes)  : writes a patched copy
    python3 -I - "$@" << 'PY'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
off = int(sys.argv[3])
data[off:off + len(sys.argv[4]) // 2] = bytes.fromhex(sys.argv[4])
open(sys.argv[2], "wb").write(data)
PY
}
bin scoped "$tmp/scoped.bin"
bin host "$tmp/host.bin"
# Raw bytes are accepted too.
tb "$tmp/scoped.bin"
[ "$rc" = 0 ] || bad "raw binary accepted credential: rc=$rc err='$err'"

# Cut points from the file's own sizes: the TPM section ends at 48+ALIGN8(20+blob+policy); the scoped flags follow.
end=$(python3 -I - "$tmp/scoped.bin" << 'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
mask, bank, alg, blob, pol = struct.unpack_from("<QHHII", d, 48)
print(48 + ((20 + blob + pol + 7) & ~7))
PY
)
[ "$end" = 344 ] || bad "TPM section ends at $end, not 344 as F153 says"
[ "$(stat -c %s "$tmp/scoped.bin")" -gt $((end + 8 + 16)) ] || bad "scoped credential is too short to cut"
for n in 0 10 31 47 60 200 $((end - 1)) $((end + 6)); do
    head -c "$n" "$tmp/scoped.bin" > "$tmp/cut"
    tb "$tmp/cut"
    if [ "$rc" = 0 ] || ! grep -q malformed <<< "$err" || grep -q Traceback <<< "$err"; then
        bad "cut to $n bytes: rc=$rc err='$err'"
    fi
done
# Cut after the flags: the ciphertext is out of the reader's sight, so it is accepted.
head -c $((end + 8)) "$tmp/scoped.bin" > "$tmp/cut"
tb "$tmp/cut"
[ "$rc" = 0 ] || bad "cut after the scoped flags: rc=$rc err='$err'"

patch "$tmp/scoped.bin" "$tmp/iv.bin" 24 ffffffff
patch "$tmp/scoped.bin" "$tmp/blob.bin" 60 ffffff7f
for f in iv blob; do
    tb "$tmp/$f.bin"
    if [ "$rc" = 0 ] || ! grep -q malformed <<< "$err" || grep -q Traceback <<< "$err"; then
        bad "corrupted $f: rc=$rc err='$err'"
    fi
done
printf 'this is not base64 !!\n' > "$tmp/text"
tb "$tmp/text"
{ [ "$rc" != 0 ] && grep -q malformed <<< "$err" && ! grep -q Traceback <<< "$err"; } || bad "non-base64 text: rc=$rc err='$err'"

# Unknown id: the first 16 bytes replaced.
patch "$tmp/scoped.bin" "$tmp/unk.bin" 0 00112233445566778899aabbccddeeff
tb "$tmp/unk.bin"
{ [ "$rc" != 0 ] && grep -q unknown <<< "$err" && ! grep -q Traceback <<< "$err"; } || bad "unknown id: rc=$rc err='$err'"
# A public-key id on a file without that section is malformed, not unknown: the id is known and its section is required.
patch "$tmp/scoped.bin" "$tmp/pk.bin" 0 faf7eb9341e3412ca1a436f95a29362f
tb "$tmp/pk.bin"
{ [ "$rc" != 0 ] && grep -q malformed <<< "$err"; } || bad "pk id without its section: rc=$rc err='$err'"

# The host credential reports no mask (byte 48 is ciphertext there).
rd "$c/host"
! grep -q mask <<< "$out" || bad "host credential printed a mask: '$out'"

# --- negative control: a reader that ignores the mask must fail the PCR 7 case
mkdir "$tmp/variant"
sed 's/if mask != 0:/if False:/' "$READ" > "$tmp/variant/credread.py"
if cmp -s "$READ" "$tmp/variant/credread.py"; then
    bad "negative control: the patched reader does not differ"
else
    rc=0
    (cd "$tmp/empty" && python3 -I "$tmp/variant/credread.py" "$c/scoped-pcr7" --expect-tpm-bound --systemd-version 257) > /dev/null 2>&1 || rc=$?
    [ "$rc" = 0 ] || bad "negative control: the mask-ignoring reader still refuses PCR 7"
fi

exit "$fail"
