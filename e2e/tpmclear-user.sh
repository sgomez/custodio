#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`), with WORK and MODULE set by tpmclear-run.sh (F140). Her test agent approves and keeps its state in $TC/agent; every request it approves is one
# line of $TC/agent/requests, i.e. one call of the service's Sign (polkit is asked for every signature, also for one that then fails). One call per action:
#   tpmclear-user.sh import OUTDIR T...   imports $TC/T.p12 as tc-T for each T (rsa, ec), reads the certificate the module serves (the public key every signature is verified against), writes ListKeys to OUTDIR/list.out
#   tpmclear-user.sh sign TAG T...        round TAG with tc-T for each T, all at once: a D-Bus Sign (tpmclear-sign.py: TAG-tc-T.dbus) and `pkcs11-tool --sign` (TAG-tc-T.{rc,log,sig}) in $TC/out;
#                                         the number of Sign calls the round made (requests approved) in $TC/out/TAG.count
#   tpmclear-user.sh list OUTDIR          ListKeys (list.out) and `custodio list` (cli.out)
#   tpmclear-user.sh delete OUTDIR ID...  the deletes at once (delete-ID.rc, delete-ID.out), then ListKeys (list.out)
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
TC=$WORK/tpmclear
export E2E_DIR=$TC/agent
mkdir -p "$E2E_DIR" "$TC/out" "$TC/in"
[ -f "$E2E_DIR/requests" ] || : > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }
requests() { wc -l < "$E2E_DIR/requests"; }
lists() { # OUTDIR
    mkdir -p "$1"
    timeout 60 python3 -I /e2e/owner-call.py list > "$1/list.out" || fail "ListKeys gave no reply"
}

action=${1:-}
shift || true
case $action in
import)
    out=$1
    shift
    mkdir -p "$out"
    for t in "$@"; do
        timeout 60 python3 -I /e2e/import.py "$TC/$t.p12" "tc-$t" e2e-password > "$out/import-$t.out" 2>&1 || { cat "$out/import-$t.out" >&2; fail "import of tc-$t failed"; }
        timeout 60 pkcs11-tool --module "$MODULE" --token-label "tc-$t" --read-object --type cert --label "tc-$t" --output-file "$TC/in/tc-$t.crt.der" > "$out/cert-$t.log" 2>&1 \
            || { cat "$out/cert-$t.log" >&2; fail "the module did not serve the certificate of tc-$t"; }
        openssl x509 -inform der -in "$TC/in/tc-$t.crt.der" -pubkey -noout > "$TC/in/tc-$t.pub.pem" || fail "no public key in the certificate of tc-$t"
    done
    lists "$out"
    ;;
sign)
    tag=$1
    shift
    before=$(requests)
    pids=()
    for t in "$@"; do
        id=tc-$t
        case $t in
        rsa) mech=(--mechanism SHA256-RSA-PKCS) ;;
        ec) mech=(--mechanism ECDSA-SHA256 --signature-format openssl) ;;
        *) fail "unknown key type $t" ;;
        esac
        timeout 90 python3 -I /e2e/tpmclear-sign.py "$id" "$t" > "$TC/out/$tag-$id.dbus" 2> "$TC/out/$tag-$id.dbus.err" & pids+=($!)
        (
            rc=0
            timeout 120 pkcs11-tool --module "$MODULE" --token-label "$id" --label "$id" --type privkey --sign "${mech[@]}" \
                --input-file "$TC/in/msg.bin" --output-file "$TC/out/$tag-$id.sig" > "$TC/out/$tag-$id.log" 2>&1 || rc=$?
            echo "$rc" > "$TC/out/$tag-$id.rc"
        ) &
        pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" || fail "a signing job of round $tag did not finish (see $TC/out/$tag-*.dbus.err)"; done
    echo $(($(requests) - before)) > "$TC/out/$tag.count"
    ;;
list)
    lists "$1"
    timeout 60 custodio list > "$1/cli.out" || fail "custodio list failed"
    ;;
delete)
    out=$1
    shift
    mkdir -p "$out"
    pids=()
    for id in "$@"; do
        ( rc=0; timeout 60 python3 -I /e2e/delete.py "$id" > "$out/delete-$id.out" 2>&1 || rc=$?; echo "$rc" > "$out/delete-$id.rc" ) & pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p"; done
    lists "$out"
    ;;
*) fail "usage: tpmclear-user.sh import OUTDIR T... | sign TAG T... | list OUTDIR | delete OUTDIR ID..." ;;
esac
echo "tpmclear-user: done"
