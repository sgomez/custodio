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

exit "$fail"
