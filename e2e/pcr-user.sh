#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`), with WORK and MODULE set by pcr-run.sh (F137). Her test agent approves and keeps its state in $PC/agent. One call per round:
#   pcr-user.sh import      imports $PC/rsa.p12 and $PC/ec.p12 as pr-rsa and pr-ec, then does the round `base`
#   pcr-user.sh sign TAG    round TAG: ListKeys to $PC/list-TAG.out, then a signature with every key of kind tpm it lists (the enumeration is of the list, not two chosen ids)
#   pcr-user.sh delete      deletes both keys and writes ListKeys to $PC/list-after.out
# The certificate of each key is read through the module once (round base) and is the public key every later signature is verified against.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
# F163: PCR_DIR (a VM run keeps its files across the power cycle), PCR_KIND (the kind of the keys it signs with: tpm, or encrypted-tpm in the lacking VM mode), PCR_NOSIGN=1 (import only)
PC=${PCR_DIR:-$WORK/pcr}
export E2E_DIR=$PC/agent
mkdir -p "$E2E_DIR" "$PC/out" "$PC/in"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

sign_round() { # TAG
    local tag=$1 id kt pids=() mech
    timeout 60 python3 -I /e2e/owner-call.py list > "$PC/list-$tag.out" || fail "ListKeys gave no reply (round $tag)"
    while IFS=$'\t' read -r id kt; do
        if [ ! -s "$PC/in/$id.pub.pem" ]; then
            timeout 60 pkcs11-tool --module "$MODULE" --token-label "$id" --read-object --type cert --label "$id" --output-file "$PC/in/$id.crt.der" > "$PC/in/$id.log" 2>&1 \
                || { cat "$PC/in/$id.log" >&2; fail "the module did not serve the certificate of $id"; }
            openssl x509 -inform der -in "$PC/in/$id.crt.der" -pubkey -noout > "$PC/in/$id.pub.pem" || fail "no public key in the certificate of $id"
        fi
        case $kt in
        rsa2048) mech=(--mechanism SHA256-RSA-PKCS) ;;
        ecdsa-p256) mech=(--mechanism ECDSA-SHA256 --signature-format openssl) ;;
        *) fail "the key $id has the type $kt, which these cases do not sign" ;;
        esac
        (
            rc=0
            timeout 120 pkcs11-tool --module "$MODULE" --token-label "$id" --label "$id" --type privkey --sign "${mech[@]}" \
                --input-file "$PC/in/msg.bin" --output-file "$PC/out/$tag-$id.sig" > "$PC/out/$tag-$id.log" 2>&1 || rc=$?
            echo "$rc" > "$PC/out/$tag-$id.rc"
        ) &
        pids+=($!)
    done < <(python3 -I /e2e/pcr.py enumerate "$PC/list-$tag.out" "${PCR_KIND:-tpm}")
    for p in "${pids[@]}"; do wait "$p"; done
}

case ${1:-} in
import)
    for t in rsa ec; do
        timeout 60 python3 -I /e2e/import.py "$PC/$t.p12" "pr-$t" e2e-password > "$PC/import-$t.out" 2>&1 || { cat "$PC/import-$t.out" >&2; fail "import of pr-$t failed"; }
    done
    [ -n "${PCR_NOSIGN:-}" ] || sign_round base
    ;;
sign) [ -n "${2:-}" ] || fail "usage: pcr-user.sh sign TAG"; sign_round "$2" ;;
delete)
    for t in rsa ec; do timeout 60 python3 -I /e2e/delete.py "pr-$t" > /dev/null || fail "delete of pr-$t failed"; done
    timeout 60 python3 -I /e2e/owner-call.py list > "$PC/list-after.out" || fail "ListKeys after the deletes gave no reply"
    ;;
*) fail "usage: pcr-user.sh import | sign TAG | delete" ;;
esac
echo "pcr-user: done"
