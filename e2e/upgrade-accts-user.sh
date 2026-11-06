#!/usr/bin/env bash
# Runs as an ordinary user (alice or bob) in a logind session of his or her own (`su -l`), with WORK and MODULE set by upgrade-accts.sh (F96). The
# test agent registers for the session it runs in, so the calls that ask polkit are made here, with this session's agent; its log is
# $ACC/agent-USER/requests. Everything observed goes to files in $ACC, which upgrade.sh judges with upgrade-accts-lib.sh.
#   upgrade-accts-user.sh seed          (bob) imports rsa1 and bobonly, then replaces the certificate of rsa1 (D-Bus, owner-call.py)
#   upgrade-accts-user.sh collect PHASE the list (custodio list) and the certificate of each listed id through the PKCS#11 module, into $ACC/PHASE
#   upgrade-accts-user.sh sign          one signature with each listed key, one request each; then a denied one (agent denies)
#   upgrade-accts-user.sh kinds PHASE   (F141) ListKeys (owner-call.py list) and `custodio list` into $ACC/kinds/PHASE/USER.api and USER.cli; no polkit call
#   upgrade-accts-user.sh cleanup       (bob) deletes his keys, so the state is as it was before the seed
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
user=$(id -un)
ACC=$WORK/upgrade-acct
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
mode=${1:-}

start_agent() {
    export E2E_DIR=$ACC/agent-$user
    mkdir -p "$E2E_DIR"
    : > "$E2E_DIR/requests"
    echo approve > "$E2E_DIR/mode"
    python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
    agent=$!
    trap 'kill $agent 2>/dev/null || true' EXIT
    for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
    grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "$user: the agent did not register"; }
}
requests() { wc -l < "$E2E_DIR/requests"; }
expect_requests() { [ "$(requests)" -eq "$1" ] || fail "$user: expected $1 requests in the agent's log, saw $(requests)"; }
read_cert() { # ID OUT: the certificate the module shows for the id
    pkcs11-tool --module "$MODULE" --token-label "$1" --label "$1" --type cert --read-object --output-file "$2" > "$ACC/$user-cert.log" 2>&1 \
        || { cat "$ACC/$user-cert.log" >&2; fail "$user: cannot read the certificate of $1"; }
}
listed_ids() { custodio list | sed -n 's/^id: //p'; }
p11sign() { # ID OUT: one signature through the module; the status of pkcs11-tool is returned
    local args=(--mechanism SHA256-RSA-PKCS)
    [ "$1" != ec1 ] || args=(--mechanism ECDSA-SHA256 --signature-format openssl)
    rm -f "$2"
    pkcs11-tool --module "$MODULE" --token-label "$1" --label "$1" --type privkey --sign "${args[@]}" \
        --input-file "$ACC/sign/data.bin" --output-file "$2" > "$ACC/$user-p11.log" 2>&1
}

case $mode in
seed)
    [ "$user" = bob ] || fail "seed is bob's"
    start_agent
    for id in rsa1 bobonly; do
        python3 -I /e2e/import.py "$ACC/bob-$id.p12" "$id" e2e-password > /dev/null || fail "bob: import of $id failed"
    done
    expect_requests 2
    got=$(python3 -I /e2e/owner-call.py replace rsa1 "$ACC/bob-new.der") || fail "bob: the replace call gave no D-Bus reply"
    [ "$got" = ok ] || fail "bob: ReplaceCertificate on the old package gave '$got'"
    expect_requests 3
    ;;
collect)
    phase=${2:?}
    custodio list > "$ACC/$phase/$user.list"
    for id in $(listed_ids); do read_cert "$id" "$ACC/$phase/$user-$id.der"; done
    ;;
kinds)
    phase=${2:?}
    timeout 60 python3 -I /e2e/owner-call.py list > "$ACC/kinds/$phase/$user.api" || fail "$user: ListKeys gave no reply"
    timeout 60 custodio list > "$ACC/kinds/$phase/$user.cli" || fail "$user: custodio list failed"
    ;;
sign)
    start_agent
    first=''
    for id in $(listed_ids); do
        [ -n "$first" ] || first=$id
        before=$(requests)
        p11sign "$id" "$ACC/sign/$user-$id.sig" || { cat "$ACC/$user-p11.log" >&2; fail "$user: the approved signature with $id failed"; }
        echo $(( $(requests) - before )) > "$ACC/sign/$user-$id.requests"
    done
    [ -n "$first" ] || fail "$user: no key to sign with"
    # nothing is cached from the signatures just made: a denied one fails and is still asked
    echo deny > "$E2E_DIR/mode"
    before=$(requests)
    st=0
    p11sign "$first" "$ACC/sign/$user-denied.sig" || st=$?
    bytes=0
    [ ! -e "$ACC/sign/$user-denied.sig" ] || bytes=$(stat -c %s "$ACC/sign/$user-denied.sig")
    echo "$st $(( $(requests) - before )) $bytes" > "$ACC/sign/$user-denied"
    ;;
cleanup)
    [ "$user" = bob ] || fail "cleanup is bob's"
    start_agent
    for id in $(listed_ids); do python3 -I /e2e/delete.py "$id" > /dev/null || fail "bob: delete of $id failed"; done
    expect_requests 2
    ;;
*) fail "usage: upgrade-accts-user.sh seed|collect PHASE|kinds PHASE|sign|cleanup" ;;
esac
echo "upgrade-accts-user $user: $mode done"
