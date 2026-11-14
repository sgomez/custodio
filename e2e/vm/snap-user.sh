#!/usr/bin/env bash
# Runs as an ordinary user in one logind session (`su -l`) with WORK set by e2e/vm/snap.sh (F179). The test agent of the session approves; its state is
# $WORK/snap/agent-USER (requests, subjects). Usage: snap-user.sh PHASE
#   import   imports the user's keys (sn-USER-rsa, sn-USER-ec) with the CLI; nothing else
#   place    the first `snap run --shell firefox` (the snap creates ~/snap/firefox), then the module copy and the client go to ~/snap/firefox/common/ by hand
#            (a byte copy of the installed module: the registration command and the refresh are F183)
#   sign     under `snap run --shell firefox`: the client lists the keys, reads the certificates and signs three times (rsa, ec, rsa); the pids are kept
#   bus      the bus call from the confinement and the identical call outside it (the same tool: snap-client.py call bus ListKeys)
#   unknown  from the confinement: ImportP12, DeleteKey, ReplaceCertificate as method calls on the socket
#   delete   deletes the user's keys
# The shell of the snap reads its commands from stdin; the client prints `pid<TAB>N` first, which is how the harness knows the pid of the process in the snap.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
phase=$1
user=$(id -un)
SN=$WORK/snap
H=$HOME/snap/firefox/common
MOD=$H/libcustodio_pkcs11.so
CL=$H/snap-client.py
export E2E_DIR=$SN/agent-$user
mkdir -p "$E2E_DIR"
[ -e "$E2E_DIR/requests" ] || : > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
python3 -I /e2e/agent.py >> "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

insnap() { # COMMAND...: one command in the confinement of the Firefox snap; its output and status
    printf '%s\n' "$*" | timeout 120 snap run --shell firefox
}
pid_of() { sed -n 's/^pid\t//p' "$1" | head -n 1; }
# outcome NAME CMD...: the client's output in $SN/NAME.out, its status in NAME.rc
inclient() { local n=$1 rc=0; shift; insnap "python3 -I $CL $*" > "$SN/$n.out" 2> "$SN/$n.err" || rc=$?; echo "$rc" > "$SN/$n.rc"; }

case $phase in
import)
    for t in rsa ec; do
        timeout 60 python3 -I /e2e/import.py "$SN/$t.p12" "sn-$user-$t" e2e-password > "$SN/import-$user-$t.out" || { cat "$SN/import-$user-$t.out" >&2; fail "import of sn-$user-$t failed"; }
    done
    ;;
place)
    rc=0
    # shellcheck disable=SC2016 # the snap's shell expands them
    insnap 'echo $SNAP_INSTANCE_NAME $HOME' > "$SN/first-run.out" 2>&1 || rc=$?
    [ "$rc" -eq 0 ] || { cat "$SN/first-run.out" >&2; fail "snap run --shell firefox failed as $user (exit $rc)"; }
    mkdir -p "$H"
    install -m 755 /usr/lib/custodio/libcustodio_pkcs11.so "$MOD"
    install -m 755 /e2e/vm/snap-client.py "$CL"
    cmp /usr/lib/custodio/libcustodio_pkcs11.so "$MOD" || fail "the module copy differs from the installed module"
    ;;
sign)
    # the keys of the user, only hers (the foreign key was imported by the other account earlier)
    inclient list list "$MOD"
    mkdir -p "$H/o"
    for k in rsa ec rsa2; do
        t=${k%2}
        printf 'message %s' "$k" | openssl dgst -sha256 -binary > "$H/o/digest-$k.bin"
        inclient "cert-$k" cert "$MOD" "sn-$user-$t" "$H/o/cert-$k.der"
        inclient "sign-$k" sign "$MOD" "sn-$user-$t" "$t" "$H/o/digest-$k.bin" "$H/o/sig-$k.bin"
        echo "$t" > "$SN/sign-$k.kind"
        pid_of "$SN/sign-$k.out" > "$SN/sign-$k.pid"
        cp "$H/o/cert-$k.der" "$SN/sign-$k.crt" 2> /dev/null || : > "$SN/sign-$k.crt"
        cp "$H/o/digest-$k.bin" "$SN/sign-$k.digest"
        cp "$H/o/sig-$k.bin" "$SN/sign-$k.sig" 2> /dev/null || : > "$SN/sign-$k.sig"
    done
    cp "$SN/list.out" "$SN/list.client"
    grep '^token' "$SN/list.client" > "$SN/list.out" || : > "$SN/list.out"
    ;;
bus)
    uid=$(id -u)
    inclient bus-raw call bus ListKeys "$uid"
    sed '/^pid/d' "$SN/bus-raw.out" > "$SN/bus-in.out"
    if [ ! -s "$SN/bus-in.out" ]; then echo "error no answer from the confinement: $(head -c 200 "$SN/bus-raw.err")" > "$SN/bus-in.out"; fi
    timeout 60 python3 -I "$CL" call bus ListKeys "$uid" | sed '/^pid/d' > "$SN/bus-out.out" || true
    ;;
unknown)
    for m in ImportP12 DeleteKey ReplaceCertificate; do
        inclient "um-raw-$m" call p2p "$m"
        sed '/^pid/d' "$SN/um-raw-$m.out" > "$SN/um-$m.out"
        if [ ! -s "$SN/um-$m.out" ]; then echo "error no answer: $(head -c 200 "$SN/um-raw-$m.err")" > "$SN/um-$m.out"; fi
    done
    ;;
delete)
    for t in rsa ec; do timeout 60 python3 -I /e2e/delete.py "sn-$user-$t" > /dev/null 2>&1 || true; done # best effort: also the cleanup of a failed run
    ;;
*) fail "unknown phase $phase" ;;
esac
echo "snap-user: $phase done"
