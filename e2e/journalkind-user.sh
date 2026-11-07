#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`), with WORK set by journalkind-run.sh (F144). Her test agent approves (or denies, where said) and keeps its state in $JK/agent. One command per session:
#   journalkind-user.sh setup         imports $JK/rsa.p12 as jk-a and jk-b, then one signature with jk-a that is approved and one that is denied (the agent in deny mode): the entries no cause
#                                     query may return; writes the replies of the two signatures to $JK/sign-ok.out and $JK/sign-denied.out
#   journalkind-user.sh forge         writes entries as alice, with the fields of the service's entries, through journald's socket (key jk-forged-alice); the root side writes its own
#   journalkind-user.sh sign TAG ID...  one signature with each ID, in this order, approved; the replies to $JK/sign-TAG-ID.out
#   journalkind-user.sh delete ID...  the deletes in this one session
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
JK=$WORK/journalkind
export E2E_DIR=$JK/agent
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
cmd=${1:-}
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

sign_one() { # ID OUTFILE: one Sign call (tpmclear-sign.py prints "ok" or "error NAME: MESSAGE")
    timeout 120 python3 -I /e2e/tpmclear-sign.py "$1" rsa > "$2" 2>&1 || { cat "$2" >&2; fail "the Sign call for $1 gave no D-Bus reply"; }
}
forge() { python3 -I /e2e/jo-forge.py "$@"; }

case $cmd in
setup)
    for id in jk-a jk-b; do
        timeout 120 python3 -I /e2e/import.py "$JK/rsa.p12" "$id" e2e-password > "$JK/import-$id.out" 2>&1 || { cat "$JK/import-$id.out" >&2; fail "import of $id failed"; }
    done
    sign_one jk-a "$JK/sign-ok.out"
    echo deny > "$E2E_DIR/mode"
    sign_one jk-a "$JK/sign-denied.out"
    echo approve > "$E2E_DIR/mode"
    ;;
forge)
    k=$JK_KIND
    for kind in tpm encrypted-tpm encrypted-host; do
        forge MESSAGE_ID=4c7163ce45d0b9faf8e7c38d098bdb22 CUSTODIO_OPERATION=import CUSTODIO_OUTCOME=stored CUSTODIO_KEY_ID=jk-forged-alice "CUSTODIO_STORAGE_KIND=$kind" \
            PRIORITY=6 SYSLOG_IDENTIFIER=custodiod "MESSAGE=forged by alice"
    done
    for uid in $JK_UIDS; do
        forge MESSAGE_ID=8e1f5a6c0b3d4972a4c6d58f31b7e902 CUSTODIO_OPERATION=purge CUSTODIO_OUTCOME=purged CUSTODIO_KEY_ID=jk-forged-alice "CUSTODIO_OWNER_UID=$uid" \
            PRIORITY=4 SYSLOG_IDENTIFIER=custodiod "MESSAGE=forged by alice"
    done
    for cause in key_lost temporarily_unavailable; do
        forge MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401 CUSTODIO_OPERATION=sign CUSTODIO_OUTCOME=signing_failed CUSTODIO_KEY_ID=jk-forged-alice "CUSTODIO_STORAGE_KIND=$k" \
            "CUSTODIO_CAUSE=$cause" PRIORITY=3 SYSLOG_IDENTIFIER=custodiod "MESSAGE=forged by alice"
    done
    ;;
sign)
    tag=${2:?usage: sign TAG ID...}
    shift 2
    for id in "$@"; do sign_one "$id" "$JK/sign-$tag-$id.out"; done
    ;;
delete)
    shift
    [ $# -gt 0 ] || fail "usage: delete ID..."
    pids=()
    for id in "$@"; do timeout 120 python3 -I /e2e/delete.py "$id" > "$JK/delete-$id.out" 2>&1 & pids+=($!); done
    for p in "${pids[@]}"; do wait "$p" || fail "a delete failed"; done
    ;;
*) fail "usage: journalkind-user.sh setup | forge | sign TAG ID... | delete ID..." ;;
esac
echo "journalkind-user: done"
