#!/usr/bin/env bash
# Tests of scripts/tpm-record-check.sh on records of keys made on a swtpm: a key without policy passes, a duplicable key and an
# altered record give exit 1, an unknown id and bad usage give exit 2. A missing swtpm is a failure, never a skip.
# shellcheck disable=SC2015 # "A && B || bad" is meant: bad runs when either fails
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHK=$ROOT/scripts/tpm-record-check.sh
if [ "${IN_SWTPM:-}" != 1 ]; then exec "$ROOT/scripts/with-swtpm.sh" env IN_SWTPM=1 bash "$0"; fi

w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT
s=$w/state
mkdir -p "$s/1000"
cd "$w"
t() { "$@" > t.out 2>&1 || { cat t.out >&2; echo "test-tpm-record-check: '$1' failed" >&2; exit 1; }; tpm2_flushcontext -t > /dev/null 2>&1 || true; }
t tpm2_createprimary -C o -G ecc256:aes128cfb -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt' -c p.ctx
t tpm2_readpublic -c p.ctx -n p.name
t tpm2_create -C p.ctx -g sha256 -G ecc256 -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -u good.pub -r good.priv
t tpm2_startauthsession -S trial.ctx
t tpm2_policycommandcode -S trial.ctx -L pol.dat TPM2_CC_Duplicate
t tpm2_flushcontext trial.ctx
t tpm2_create -C p.ctx -g sha256 -G ecc256 -L pol.dat -a 'sensitivedataorigin|userwithauth|sign' -u dup.pub -r dup.priv
cp good.priv bad.priv
printf '\xff' | dd of=bad.priv bs=1 seek=$(($(stat -c %s bad.priv) - 1)) conv=notrunc 2> /dev/null
! cmp -s good.priv bad.priv || { echo "test-tpm-record-check: the altered private area equals the good one" >&2; exit 1; }
mkrec() { # ID PUB PRIV
    python3 -I - "$s/1000/$1" "$1" p.name "$2" "$3" << 'PY'
import sys
out, rid, namef, pubf, privf = sys.argv[1:6]
name, pub, priv = (open(f, "rb").read() for f in (namef, pubf, privf))
prot = len(name).to_bytes(2, "big") + name + pub + priv
data = b"CUSTODIO" + bytes([1, 1]) + (1000).to_bytes(4, "big") + bytes([len(rid)]) + rid.encode() + (4).to_bytes(4, "big") + b"cert" + len(prot).to_bytes(4, "big") + prot
open(out, "wb").write(data)
PY
}
mkrec k-good good.pub good.priv
mkrec k-dup dup.pub dup.priv
mkrec k-altered good.pub bad.priv

fail=0
bad() { cat run.out >&2; echo "test-tpm-record-check: $*" >&2; fail=1; }
run() { rc=0; "$CHK" "$@" > run.out 2>&1 || rc=$?; }
has() { grep -q -- "$1" run.out; }

run "$s" k-good
[ "$rc" = 0 ] && has 'authPolicy: empty' && has 'TPM_RC_POLICY_FAIL' || bad "a key without policy must pass (exit $rc)"
run "$s" k-dup
[ "$rc" = 1 ] && has 'authPolicy: NOT empty' && has '^tpm2_duplicate: succeeded' || bad "a duplicable key must give exit 1 (exit $rc)"
run "$s" k-altered
[ "$rc" = 1 ] && has 'tpm2_load failed' && ! has 'POLICY_FAIL' || bad "an altered record must be a load failure with exit 1 (exit $rc)"
run "$s" k-missing
[ "$rc" = 2 ] || bad "an unknown key id must give exit 2 (exit $rc)"
run --bogus "$s" k-good
[ "$rc" = 2 ] && has '^usage:' || bad "a wrong option must give usage and exit 2 (exit $rc)"
run "$s"
[ "$rc" = 2 ] && has '^usage:' || bad "a missing key id must give usage and exit 2 (exit $rc)"
[ "$fail" = 0 ] && echo "test-tpm-record-check: ok"
exit "$fail"
