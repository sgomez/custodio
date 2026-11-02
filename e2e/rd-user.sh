#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`) with GROUP (replace or delete), WORK and MODULE set by rd-run.sh (F93). Her test agent approves. Everything she
# observes goes to files in $RD, which rd-run.sh judges. The state directory belongs to the service user, so a snapshot of it goes through root (`rootdo NAME`
# creates $RD/want-NAME and waits for $RD/have-NAME; root writes $RD/NAME.state). A snapshot NAME is $RD/NAME.user (custodio list and the sha256 of the
# certificate the module shows per key) and $RD/NAME.state. Calls are recorded in $RD/calls as in ops-user.sh: "LABEL<TAB>RESULT<TAB>LOGGED".
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${GROUP:?}" "${WORK:?}" "${MODULE:?}"
RD=$WORK/rd-$GROUP
export E2E_DIR=$RD/agent
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
CALLS=$RD/calls
: > "$CALLS"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

requests() { wc -l < "$E2E_DIR/requests"; }
rootdo() {
    touch "$RD/want-$1"
    for _ in $(seq 600); do [ -e "$RD/have-$1" ] && return 0; sleep 0.2; done
    fail "root did not do '$1'"
}
read_cert() { # ID OUT: the certificate the module shows for the id
    pkcs11-tool --module "$MODULE" --token-label "$1" --label "$1" --type cert --read-object --output-file "$2" > "$RD/read-cert.log" 2>&1 \
        || { cat "$RD/read-cert.log" >&2; fail "cannot read the certificate of $1"; }
    [ -s "$2" ] || fail "no certificate written for $1"
}
usnap() { # NAME
    local id
    {
        custodio list
        for id in $(custodio list | sed -n 's/^id: //p'); do
            printf 'cert %s %s\n' "$id" "$(pkcs11-tool --module "$MODULE" --token-label "$id" --label "$id" --type cert --read-object 2> /dev/null | sha256sum | cut -d' ' -f1)"
        done
    } > "$RD/$1.user"
    rootdo "snap-$1"
}
rec() { # LABEL then owner-call.py ARGS...
    local label=$1 before res st=0
    shift
    before=$(requests)
    res=$(timeout 60 python3 -I /e2e/owner-call.py "$@") || st=$?
    [ "$st" -ne 124 ] || fail "$label: the call did not return within 60 s"
    [ "$st" -eq 0 ] || fail "$label: owner-call.py gave no D-Bus reply (status $st)"
    printf '%s\t%s\t%s\n' "$label" "$res" "$(tail -n +$((before + 1)) "$E2E_DIR/requests" | paste -sd';' -)" >> "$CALLS"
}
rec_cli() { # LABEL then the CLI script and its ARGS (delete.py ID)
    local label=$1 before res st=0
    shift
    before=$(requests)
    timeout 60 python3 -I "$@" > "$RD/cli.out" 2>&1 || st=$?
    [ "$st" -ne 124 ] || fail "$label: the CLI did not return within 60 s"
    if [ "$st" -eq 0 ]; then res=ok; else res=cli-failed; fi
    printf '%s\t%s\t%s\n' "$label" "$res" "$(tail -n +$((before + 1)) "$E2E_DIR/requests" | paste -sd';' -)" >> "$CALLS"
}
import_key() { python3 -I /e2e/import.py "$RD/k.p12" "$1" e2e-password > /dev/null || fail "import of $1 failed"; }
delete_key() { python3 -I /e2e/delete.py "$1" > /dev/null || fail "delete of $1 failed"; }
p11sign() { # ID OUT: one signature with the module, one request
    local before
    before=$(requests)
    rm -f "$2"
    pkcs11-tool --module "$MODULE" --token-label "$1" --label "$1" --type privkey --sign --mechanism SHA256-RSA-PKCS \
        --input-file "$RD/data.bin" --output-file "$2" > "$RD/p11.log" 2>&1 || { cat "$RD/p11.log" >&2; fail "signature with $1 failed"; }
    [ -s "$2" ] || fail "no signature written for $1"
    [ "$(requests)" -eq $((before + 1)) ] || fail "signing with $1 made $(( $(requests) - before )) requests, expected 1"
}
slots() { pkcs11-tool --module "$MODULE" --list-token-slots > "$RD/$1" 2>&1 || true; } # judged on its content, not its status

case $GROUP in
replace)
    import_key rep-key
    read_cert rep-key "$RD/before.der"
    usnap r0
    rec replace-same replace rep-key "$RD/cert2.der"
    usnap r1
    custodio list > "$RD/list-after"
    read_cert rep-key "$RD/after.der"
    p11sign rep-key "$RD/sig"
    read_cert rep-key "$RD/module-after-sign.der"
    # the mismatch: a certificate of an unrelated key
    rec replace-mismatch replace rep-key "$RD/cert-other.der"
    usnap r2
    custodio list > "$RD/list-mismatch"
    read_cert rep-key "$RD/after-mismatch.der"
    p11sign rep-key "$RD/sig2"
    delete_key rep-key
    ;;
delete)
    usnap d0
    import_key del-keep
    usnap d1
    import_key del-key
    usnap d2
    slots slots-before
    rec sign-before sign del-key
    rec_cli delete-cli /e2e/delete.py del-key
    usnap d3
    slots slots-after
    rec sign-after sign del-key
    rec sign-keep sign del-keep
    import_key del-key
    usnap d4
    rec sign-reimport sign del-key
    delete_key del-key
    delete_key del-keep
    usnap d5
    ;;
*) fail "unknown group '$GROUP'" ;;
esac
echo "rd-user: done"
