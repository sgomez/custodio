#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`), with WORK and MODULE set by tpmslots-run.sh (F143). Her test agent approves and keeps its state in $TS/agent; the number of requests it
# approved is written to $TS/requests-CMD when the session ends. One command per session:
#   tpmslots-user.sh import              imports $TS/rsa.p12 and $TS/ec.p12 as ts-rsa and ts-ec, reads the certificates the module serves (the public keys every signature is verified
#                                        against) and writes ListKeys to $TS/list-start.out
#   tpmslots-user.sh sign N              N signatures in a row with ts-rsa (RSA-PKCS and RSA-PKCS-PSS alternating) and N with ts-ec, the two runs as parallel jobs (TS_SERIES=1: one
#                                        after the other); every call is logged to $TS/calls-rsa.tsv / calls-ec.tsv AFTER it ran: "IDX MECH RC SIG INPUT"
#   tpmslots-user.sh imports M           M imports in a row of $TS/rsa.p12 as ts-imp-1..M, logged to $TS/imports.tsv ("IDX ID RC"), ListKeys to $TS/list-imports.out, then one
#                                        signature with ts-imp-M (calls-last.tsv)
#   tpmslots-user.sh post                one signature with ts-rsa and one with ts-ec (calls-post-rsa.tsv, calls-post-ec.tsv)
#   tpmslots-user.sh delete ID...        the deletes in this one session, then ListKeys to $TS/list-after.out
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
TS=$WORK/tpmslots
export E2E_DIR=$TS/agent
mkdir -p "$E2E_DIR" "$TS/out"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
cmd=${1:-}
done_session() { wc -l < "$E2E_DIR/requests" > "$TS/requests-$cmd" || true; kill "$agent" 2>/dev/null || true; }
trap done_session EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

# sign_call KEYID TAG IDX MECH: one signature, then its record (the exit status is the tool's, kept); prints nothing
sign_call() {
    local key=$1 tag=$2 idx=$3 mech=$4 rc=0 sig="out/$2-$3.sig" inp=in/msg.bin
    case $mech in
    pkcs) timeout 120 pkcs11-tool --module "$MODULE" --token-label "$key" --label "$key" --type privkey --sign --mechanism SHA256-RSA-PKCS \
        --input-file "$TS/$inp" --output-file "$TS/$sig" > "$TS/out/$tag-$idx.log" 2>&1 || rc=$? ;;
    ecdsa) timeout 120 pkcs11-tool --module "$MODULE" --token-label "$key" --label "$key" --type privkey --sign --mechanism ECDSA-SHA256 --signature-format openssl \
        --input-file "$TS/$inp" --output-file "$TS/$sig" > "$TS/out/$tag-$idx.log" 2>&1 || rc=$? ;;
    pss) inp=in/dgst.bin
        timeout 120 python3 -I /e2e/p11-pss.py "$MODULE" "$key" sha256 32 "$TS/$inp" "$TS/$sig" > "$TS/out/$tag-$idx.log" 2>&1 || rc=$? ;;
    *) fail "unknown mechanism $mech" ;;
    esac
    printf '%s\t%s\t%s\t%s\t%s\n' "$idx" "$mech" "$rc" "$sig" "$inp" >> "$TS/calls-$tag.tsv"
    return "$rc"
}
sign_run() { # KEYID TAG TYPE N: N calls in a row, stops at the first one that fails
    local key=$1 tag=$2 t=$3 n=$4 i mech
    : > "$TS/calls-$tag.tsv"
    for i in $(seq "$n"); do
        if [ "$t" = ec ]; then mech=ecdsa; elif [ $((i % 2)) = 1 ]; then mech=pkcs; else mech=pss; fi
        sign_call "$key" "$tag" "$i" "$mech" || return 1
    done
}
read_cert() { # KEYID: the public key of the certificate the module serves
    timeout 60 pkcs11-tool --module "$MODULE" --token-label "$1" --read-object --type cert --label "$1" --output-file "$TS/in/$1.crt.der" > "$TS/in/$1.log" 2>&1 \
        || { cat "$TS/in/$1.log" >&2; fail "the module did not serve the certificate of $1"; }
    openssl x509 -inform der -in "$TS/in/$1.crt.der" -pubkey -noout > "$TS/in/$1.pub.pem" || fail "no public key in the certificate of $1"
}

case $cmd in
import)
    for t in rsa ec; do
        timeout 60 python3 -I /e2e/import.py "$TS/$t.p12" "ts-$t" e2e-password > "$TS/import-$t.out" 2>&1 || { cat "$TS/import-$t.out" >&2; fail "import of ts-$t failed"; }
        read_cert "ts-$t"
    done
    timeout 60 python3 -I /e2e/owner-call.py list > "$TS/list-start.out" || fail "ListKeys gave no reply"
    ;;
sign)
    n=${2:?usage: sign N}
    if [ -n "${TS_SERIES:-}" ]; then
        sign_run ts-rsa rsa rsa "$n" || fail "the signing run with ts-rsa failed"
        sign_run ts-ec ec ec "$n" || fail "the signing run with ts-ec failed"
    else
        sign_run ts-rsa rsa rsa "$n" & p1=$!
        sign_run ts-ec ec ec "$n" & p2=$!
        r1=0 r2=0
        wait "$p1" || r1=$?
        wait "$p2" || r2=$?
        [ "$r1" = 0 ] || fail "the signing run with ts-rsa failed"
        [ "$r2" = 0 ] || fail "the signing run with ts-ec failed"
    fi
    ;;
imports)
    m=${2:?usage: imports M}
    : > "$TS/imports.tsv"
    for i in $(seq "$m"); do
        rc=0
        timeout 120 python3 -I /e2e/import.py "$TS/rsa.p12" "ts-imp-$i" e2e-password > "$TS/import-$i.out" 2>&1 || rc=$?
        printf '%s\tts-imp-%s\t%s\n' "$i" "$i" "$rc" >> "$TS/imports.tsv"
        [ "$rc" = 0 ] || { cat "$TS/import-$i.out" >&2; fail "import $i of $m failed"; }
    done
    timeout 60 python3 -I /e2e/owner-call.py list > "$TS/list-imports.out" || fail "ListKeys gave no reply"
    read_cert "ts-imp-$m"
    sign_run "ts-imp-$m" last rsa 1 || fail "the signature with the last imported key failed"
    ;;
post)
    sign_run ts-rsa post-rsa rsa 1 || fail "the signature with ts-rsa after the runs failed"
    sign_run ts-ec post-ec ec 1 || fail "the signature with ts-ec after the runs failed"
    ;;
delete)
    shift
    [ $# -gt 0 ] || fail "usage: delete ID..."
    pids=()
    for id in "$@"; do timeout 120 python3 -I /e2e/delete.py "$id" > "$TS/delete-$id.out" 2>&1 & pids+=($!); done
    for i in "${!pids[@]}"; do wait "${pids[$i]}" || { fail "a delete failed"; }; done
    timeout 60 python3 -I /e2e/owner-call.py list > "$TS/list-after.out" || fail "ListKeys after the deletes gave no reply"
    ;;
*) fail "usage: tpmslots-user.sh import | sign N | imports M | post | delete ID..." ;;
esac
echo "tpmslots-user: done"
