#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`) with WORK and MODULE set by sign-run.sh (F134). Her test agent approves and keeps its state in $SG/agent. She imports an RSA 2048
# and a P-256 key with the CLI, reads their certificates back through the module, signs with every mechanism (the signatures of a case at once, the cases one after another so that
# the agent's request count is exact per case), keeps every output for sign.py, lists the keys, and deletes both. Root judges all of it.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
SG=$WORK/sign
export E2E_DIR=$SG/agent
mkdir -p "$E2E_DIR" "$SG/out"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

for t in rsa ec; do
    timeout 60 python3 -I /e2e/import.py "$SG/$t.p12" "sg-$t" e2e-password > "$SG/import-$t.out" || { cat "$SG/import-$t.out" >&2; fail "import of sg-$t failed"; }
    # the certificate as the module serves it, then its public key
    timeout 60 pkcs11-tool --module "$MODULE" --token-label "sg-$t" --read-object --type cert --label "sg-$t" --output-file "$SG/in/$t.crt.der" > "$SG/cert-$t.log" 2>&1 \
        || { cat "$SG/cert-$t.log" >&2; fail "the module did not serve the certificate of sg-$t"; }
    openssl x509 -inform der -in "$SG/in/$t.crt.der" -pubkey -noout > "$SG/in/$t.pub.pem" || fail "no public key in the certificate of sg-$t"
done
timeout 60 python3 -I /e2e/owner-call.py list > "$SG/api.out" || fail "ListKeys gave no reply"

requests() { wc -l < "$E2E_DIR/requests"; }
# sign_job NAME KEY INPUT ARGS...: one pkcs11-tool process; its exit code, output and log are kept
sign_job() {
    local name=$1 key=$2 input=$3
    shift 3
    rc=0
    if [ "${1:-}" = p11-pss ]; then # RSA-PKCS-PSS with the salt length chosen: pkcs11-tool needs a public key object the module does not serve
        timeout 120 python3 -I /e2e/p11-pss.py "$MODULE" "sg-$key" "$2" "$3" "$SG/in/$input" "$SG/out/$name.sig" > "$SG/out/$name.log" 2>&1 || rc=$?
        echo "$rc" > "$SG/out/$name.rc"
        return 0
    fi
    timeout 120 pkcs11-tool --module "$MODULE" --token-label "sg-$key" --label "sg-$key" --type privkey --sign "$@" \
        --input-file "$SG/in/$input" --output-file "$SG/out/$name.sig" > "$SG/out/$name.log" 2>&1 || rc=$?
    echo "$rc" > "$SG/out/$name.rc"
}
python3 -I /e2e/sign.py groups > "$SG/groups"
python3 -I /e2e/sign.py jobs > "$SG/jobs"
while read -r group; do
    before=$(requests)
    pids=()
    while read -r name key input args; do
        # shellcheck disable=SC2086 # args are words
        sign_job "$name" "$key" "$input" $args &
        pids+=($!)
    done < <(python3 -I /e2e/sign.py jobs "$group")
    for p in "${pids[@]}"; do wait "$p"; done
    echo $(($(requests) - before)) > "$SG/count-$group"
done < "$SG/groups"
timeout 60 python3 -I /e2e/owner-call.py list > "$SG/api-mid.out" || fail "ListKeys gave no reply"
for t in rsa ec; do
    timeout 60 python3 -I /e2e/delete.py "sg-$t" > /dev/null || fail "delete of sg-$t failed"
done
timeout 60 python3 -I /e2e/owner-call.py list > "$SG/api-after.out" || fail "ListKeys after the deletes gave no reply"
echo "sign-user: done"
