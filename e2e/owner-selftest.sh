#!/usr/bin/env bash
# The checks of the owner-* judgements (owner-lib.sh, owner-journal.py) on made-up evidence, good and bad. Container-free; the guest runs it first, like
# the other self-tests, because a judgement that never fails would make the owner cases worthless.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/owner-lib.sh
source "$here/owner-lib.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "owner-selftest: $*" >&2; fail=1; }
expect_ok() { local n=$1 out; shift; out=$("$@"); [ -z "$out" ] || bad "$n: problems on good evidence: $out"; }
expect_bad() { local n=$1 out; shift; out=$("$@"); [ -n "$out" ] || bad "$n: no problem on bad evidence"; }

# call_problems
good=$tmp/calls
for k in foreign control; do for c in $OWNER_CALLS; do echo "$k-$c $NO_SUCH_KEY"; done; done > "$good"
expect_ok calls call_problems "$good"
sed 's/^foreign-sign .*/foreign-sign ok/' "$good" > "$tmp/c1"; expect_bad calls-ok call_problems "$tmp/c1"
sed 's/^foreign-delete .*/foreign-delete error com.rfirma.Custodio1.Error.PolkitDenied/' "$good" > "$tmp/c2"; expect_bad calls-denied call_problems "$tmp/c2"
sed 's/^control-replace .*/control-replace error com.rfirma.Custodio1.Error.InvalidArgs/' "$good" > "$tmp/c3"; expect_bad calls-control call_problems "$tmp/c3"
grep -v '^foreign-replace ' "$good" > "$tmp/c4"; expect_bad calls-missing call_problems "$tmp/c4"
{ cat "$good"; echo "foreign-sign $NO_SUCH_KEY"; } > "$tmp/c5"; expect_bad calls-twice call_problems "$tmp/c5"
sed 's/^\(foreign\|control\)-sign .*/\1-sign error com.rfirma.Custodio1.Error.PolkitDenied/' "$good" > "$tmp/c7"; expect_bad calls-both-wrong call_problems "$tmp/c7"
: > "$tmp/c6"; expect_bad calls-empty call_problems "$tmp/c6"

# count_problems
expect_ok count-same count_problems x 3 3
expect_bad count-up count_problems x 3 4
expect_bad count-empty count_problems x '' ''
expect_bad count-text count_problems x a a

# list_problems
printf 'id: a\n  type: rsa2048\nid: b\n' > "$tmp/list"
expect_ok list list_problems "$tmp/list" +a +b -c
expect_bad list-missing list_problems "$tmp/list" +c
expect_bad list-foreign list_problems "$tmp/list" -a
printf 'You have no keys in the custodio service.\n' > "$tmp/none"
expect_bad list-none list_problems "$tmp/none" +a
expect_ok list-none-ok list_problems "$tmp/none" -a
printf '  id: a\nxid: a\nid: ab\n' > "$tmp/list2"
expect_bad list-substring list_problems "$tmp/list2" +a

# verify_problems
for k in 1 2; do
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/k$k.key" 2> /dev/null
    openssl req -new -x509 -key "$tmp/k$k.key" -subj "/CN=k$k" -days 2 -outform DER -out "$tmp/k$k.der"
done
printf 'data' > "$tmp/data"
openssl dgst -sha256 -sign "$tmp/k1.key" -out "$tmp/sig1" "$tmp/data"
expect_ok verify verify_problems "$tmp/sig1" "$tmp/data" "$tmp/k1.der"
expect_bad verify-other verify_problems "$tmp/sig1" "$tmp/data" "$tmp/k2.der"
expect_ok verify-fails verify_fails_problems "$tmp/sig1" "$tmp/data" "$tmp/k2.der"
expect_bad verify-fails-same verify_fails_problems "$tmp/sig1" "$tmp/data" "$tmp/k1.der"
printf 'x' > "$tmp/data2"
expect_bad verify-data verify_problems "$tmp/sig1" "$tmp/data2" "$tmp/k1.der"
expect_bad verify-nocert verify_problems "$tmp/sig1" "$tmp/data" "$tmp/data"

# owner-journal.py
j=$tmp/journal.json
entry() { printf '{"MESSAGE":"%s","_SYSTEMD_UNIT":"%s"}\n' "$1" "$2"; }
{
    entry "m-a0" x.service; entry import custodio.service; entry import custodio.service; entry "m-a1" x.service
    entry "m-b0" x.service; entry noise other.service; entry late custodio.service; entry "m-b1" x.service
    entry "m-c0" x.service; entry "m-c1" x.service
    printf '{"MESSAGE":[1,2,3],"_SYSTEMD_UNIT":"custodio.service"}\n'
} > "$j"
cnt() { python3 -I "$here/owner-journal.py" count --json "$j" --before "$1" --after "$2" --unit custodio.service; }
[ "$(cnt m-a0 m-a1)" = 2 ] || bad "journal: two entries between m-a0 and m-a1"
[ "$(cnt m-b0 m-b1)" = 1 ] || bad "journal: one entry of the unit between m-b0 and m-b1 (the other unit's does not count)"
[ "$(cnt m-c0 m-c1)" = 0 ] || bad "journal: none between m-c0 and m-c1"
if cnt m-a0 m-missing > /dev/null 2>&1; then bad "journal: a missing marker gave a count"; fi
if cnt m-a1 m-a0 > /dev/null 2>&1; then bad "journal: markers in the wrong order gave a count"; fi
{ cat "$j"; entry m-a0 x.service; } > "$tmp/dup.json"
if python3 -I "$here/owner-journal.py" count --json "$tmp/dup.json" --before m-a0 --after m-a1 --unit custodio.service > /dev/null 2>&1; then bad "journal: a marker found twice gave a count"; fi
python3 -I "$here/owner-journal.py" seen --json "$j" m-a0 m-c1 || bad "journal: seen fails on present markers"
if python3 -I "$here/owner-journal.py" seen --json "$j" m-a0 m-nope 2> /dev/null; then bad "journal: seen passes with a missing marker"; fi

exit "$fail"
