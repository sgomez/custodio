#!/usr/bin/env bash
# Runs as an ordinary user in one logind session (`su -l`), with WORK and MODULE set by owner.sh (F91). The test agent registers for the session it
# runs in, so everything that asks polkit for this user is done here, with the agent of this session, whose log is $OWN/agent-USER/requests.
#   owner-user.sh a   alice: imports owner-a and owner-same (key A), says so ($OWN/a.imported), waits for $OWN/b.done with her agent denying (any
#                     request for bob's calls that reached it would be logged and refused), then checks that her keys are still there, signs
#                     with each (one request each), and deletes both.
#   owner-user.sh b   bob, ONE session and ONE agent for all of it: his list; the calls on alice's id owner-a and on the id nobody has
#                     (owner-nobody); proof that this agent is the one that registered and is alive (same pid), so a request for those calls
#                     would have been logged; then his own import of owner-same (key B), a signature with it, and the delete.
# The foreign calls are made by owner-call.py (sign, delete, replace: methods and signatures are in that file); they run with the agent set to
# "deny", so a call that wrongly reached polkit would fail as PolkitDenied and leave a request in the log, never delete alice's key.
# journal markers: `mark TAG` writes TAG as the MESSAGE of an entry; owner.sh finds the custodio.service entries between two of them.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
user=$(id -un)
OWN=$WORK/owner
export E2E_DIR=$OWN/agent-$user
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo deny > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"

python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill $agent 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }
echo "$agent" > "$E2E_DIR/agent.pid"

requests() { wc -l < "$E2E_DIR/requests"; }
expect_requests() { [ "$(requests)" -eq "$1" ] || fail "$user: expected $1 requests in the agent's log, saw $(requests)"; }
mark() { printf '%s\n' "$1" | systemd-cat -t custodio-e2e-owner; }
import_key() { python3 -I /e2e/import.py "$OWN/$2.p12" "$1" e2e-password > /dev/null || fail "$user: import of $1 failed"; }
p11sign() { # ID OUT: one signature with the PKCS#11 module, one request
    local before
    before=$(requests)
    rm -f "$2"
    pkcs11-tool --module "$MODULE" --token-label "$1" --label "$1" --type privkey --sign --mechanism SHA256-RSA-PKCS \
        --input-file "$OWN/data.bin" --output-file "$2" > "$OWN/$user-p11.log" 2>&1 || { cat "$OWN/$user-p11.log" >&2; fail "$user: signature with $1 failed"; }
    [ -s "$2" ] || fail "$user: no signature written for $1"
    [ "$(requests)" -eq $((before + 1)) ] || fail "$user: signing with $1 made $(( $(requests) - before )) requests, expected 1"
}
read_cert() { # ID OUT: the certificate the module shows for the id (what the service holds for this uid)
    pkcs11-tool --module "$MODULE" --token-label "$1" --label "$1" --type cert --read-object --output-file "$2" > "$OWN/$user-cert.log" 2>&1 \
        || { cat "$OWN/$user-cert.log" >&2; fail "$user: cannot read the certificate of $1"; }
}
delete_key() { python3 -I /e2e/delete.py "$1" > /dev/null || fail "$user: delete of $1 failed"; }

case ${1:-} in
a)
    echo approve > "$E2E_DIR/mode"
    mark "owner-a-import-before"
    import_key owner-a a
    import_key owner-same a
    mark "owner-a-import-after"
    expect_requests 2
    custodio list > "$OWN/list-a-1"
    requests > "$OWN/a.requests-1"
    touch "$OWN/a.imported"
    echo deny > "$E2E_DIR/mode"
    for _ in $(seq 600); do [ -e "$OWN/b.done" ] && break; sleep 0.5; done
    [ -e "$OWN/b.done" ] || fail "bob's session did not finish"
    requests > "$OWN/a.requests-2"
    custodio list > "$OWN/list-a-2"
    echo approve > "$E2E_DIR/mode"
    p11sign owner-a "$OWN/a-sign-own.sig"
    read_cert owner-a "$OWN/a-own.der"
    p11sign owner-same "$OWN/a-sign-same.sig"
    read_cert owner-same "$OWN/a-same.der"
    requests > "$OWN/a.requests-3"
    delete_key owner-a
    delete_key owner-same
    expect_requests 6
    ;;
b)
    custodio list > "$OWN/list-b-1"
    requests > "$OWN/b.requests-0"
    # the calls: first on alice's id, then on the id nobody has, each between two markers
    : > "$OWN/b.calls"
    for target in foreign:owner-a control:owner-nobody; do
        kind=${target%%:*}
        id=${target#*:}
        mark "owner-b-$kind-before"
        for c in sign delete replace; do
            case $c in replace) extra=("$OWN/b.der") ;; *) extra=() ;; esac
            result=$(python3 -I /e2e/owner-call.py "$c" "$id" "${extra[@]}") || fail "bob: owner-call $c $id did not give a D-Bus reply"
            echo "$kind-$c $result" >> "$OWN/b.calls"
        done
        mark "owner-b-$kind-after"
    done
    requests > "$OWN/b.requests-1"
    # the agent is still the one that registered (same pid, alive) and registered once: it is the one polkit would have asked
    kill -0 "$agent" 2>/dev/null || fail "bob's agent died during the calls"
    [ "$(cat "$E2E_DIR/agent.pid")" = "$agent" ] || fail "bob's agent pid changed"
    [ "$(grep -c registered "$E2E_DIR/agent.log")" -eq 1 ] || fail "bob's agent registered more than once"
    # the same agent logs a request at all: his own import and signature, one each
    echo approve > "$E2E_DIR/mode"
    import_key owner-same b
    expect_requests 1
    custodio list > "$OWN/list-b-2"
    p11sign owner-same "$OWN/b-sign.sig"
    read_cert owner-same "$OWN/b-same.der"
    expect_requests 2
    delete_key owner-same
    expect_requests 3
    ;;
*) fail "usage: owner-user.sh a|b" ;;
esac
echo "owner-user $user: done"
