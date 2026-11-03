#!/usr/bin/env bash
# The checks of the ops-polkit-* judgements (ops-lib.sh) on made-up evidence, good and bad. Container-free; the guest runs it first, like the other self-tests.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/ops-lib.sh
source "$here/ops-lib.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "ops-selftest: $*" >&2; fail=1; }
expect_ok() { local n=$1 out; shift; out=$("$@"); [ -z "$out" ] || bad "$n: problems on good evidence: $out"; }
expect_bad() { local n=$1 out; shift; out=$("$@"); [ -n "$out" ] || bad "$n: no problem on bad evidence"; }

T=$'\t'
rec=$tmp/calls
{
    echo "imp${T}ok${T}approve $OPS_ACTION_IMPORT"
    echo "den${T}$OPS_DENIED${T}deny $OPS_ACTION_DELETE"
    echo "una${T}$OPS_UNAVAILABLE${T}"
    echo "twice${T}ok${T}approve $OPS_ACTION_REPLACE;approve $OPS_ACTION_REPLACE"
    echo "dup${T}ok${T}"
    echo "dup${T}ok${T}"
} > "$rec"
expect_ok call-ok ops_call_problems "$rec" imp ok "approve $OPS_ACTION_IMPORT"
expect_ok call-denied ops_call_problems "$rec" den "$OPS_DENIED" "deny $OPS_ACTION_DELETE"
expect_ok call-no-request ops_call_problems "$rec" una "$OPS_UNAVAILABLE" ""
expect_bad call-wrong-result ops_call_problems "$rec" den "$OPS_UNAVAILABLE" "deny $OPS_ACTION_DELETE"
expect_bad call-ok-vs-denied ops_call_problems "$rec" den ok "deny $OPS_ACTION_DELETE"
expect_bad call-wrong-action ops_call_problems "$rec" imp ok "approve $OPS_ACTION_REPLACE"
expect_bad call-wrong-mode ops_call_problems "$rec" imp ok "deny $OPS_ACTION_IMPORT"
expect_bad call-no-request-expected-one ops_call_problems "$rec" una "$OPS_UNAVAILABLE" "deny $OPS_ACTION_IMPORT"
expect_bad call-request-unexpected ops_call_problems "$rec" imp ok ""
expect_bad call-two-requests ops_call_problems "$rec" twice ok "approve $OPS_ACTION_REPLACE"
expect_ok call-two-requests-expected ops_call_problems "$rec" twice ok "approve $OPS_ACTION_REPLACE;approve $OPS_ACTION_REPLACE"
expect_ok call-any-result ops_call_problems "$rec" den '*' "deny $OPS_ACTION_DELETE"
expect_bad call-any-result-wrong-log ops_call_problems "$rec" den '*' ""
expect_bad call-missing ops_call_problems "$rec" nope ok ""
expect_bad call-duplicate-record ops_call_problems "$rec" dup ok ""
: > "$tmp/empty"
expect_bad call-empty-file ops_call_problems "$tmp/empty" imp ok ""

printf 'x\ny\n' > "$tmp/s1"; cp "$tmp/s1" "$tmp/s2"; printf 'x\nz\n' > "$tmp/s3"
expect_ok state-same ops_state_problems l "$tmp/s1" "$tmp/s2"
expect_bad state-changed ops_state_problems l "$tmp/s1" "$tmp/s3"
expect_bad state-empty ops_state_problems l "$tmp/empty" "$tmp/empty"
expect_bad state-missing ops_state_problems l "$tmp/none" "$tmp/s1"
expect_ok differ ops_differ_problems l "$tmp/s1" "$tmp/s3"
expect_bad differ-same ops_differ_problems l "$tmp/s1" "$tmp/s2"

printf 'id: a\n  type: rsa2048\nid: b\n' > "$tmp/list"
expect_ok listed ops_listed_problems "$tmp/list" +a +b -c
expect_bad listed-missing ops_listed_problems "$tmp/list" +c
expect_bad listed-present ops_listed_problems "$tmp/list" -a
printf 'id: ab\n' > "$tmp/list2"
expect_bad listed-substring ops_listed_problems "$tmp/list2" +a
exit "$fail"
