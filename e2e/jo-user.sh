#!/usr/bin/env bash
# Runs as alice in one logind session (`su -l`) with WORK and MODULE set by jo-run.sh (F94). Her test agent approves or denies per call (the plan is
# e2e/jo-ledger.txt). She writes a marker entry to the journal before the first call and after the last, makes every call so that the pid the bus will
# report is known (a wrapper that writes $$ and execs, or jo-cli.py, which writes the pid of the CLI child), and records "LABEL<TAB>PID<TAB>UID<TAB>RESULT"
# in $JO/observed. RESULT is one word: ok / denied / mismatch / wrong-password (owner-call.py), cli-ok / cli-denied / cli-failed (the CLI), p11-ok / p11-failed
# (pkcs11-tool). Root judges all of it (jo-run.sh); she judges nothing.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
JO=$WORK/jo
export E2E_DIR=$JO/agent
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
echo approve > "$E2E_DIR/mode"
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
OBSERVED=$JO/observed
: > "$OBSERVED"
: > "$JO/extra"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

mode() { echo "$1" > "$E2E_DIR/mode"; }
mark() { printf '%s\n' "$1" | systemd-cat -t custodio-e2e-jo || fail "cannot write the marker $1"; }
alice_uid=$(id -u)
pidof_call() { # LABEL: the pid file of the call, as a number
    local pid
    pid=$(tr -d '[:space:]' < "$JO/pid-$1" 2> /dev/null || true)
    [ -n "$pid" ] || fail "$1: no pid was recorded"
    echo "$pid"
}
observe() { printf '%s\t%s\t%s\t%s\n' "$1" "$(pidof_call "$1")" "$alice_uid" "$2" >> "$OBSERVED"; }
dbus() { # LABEL then the owner-call.py arguments: records ok / denied / mismatch / wrong-password
    local label=$1 out st=0 res
    shift
    # shellcheck disable=SC2016 # $$ and "$@" are for the inner shell: it writes its pid and execs, so the pid is the caller's
    out=$(timeout 60 bash -c 'echo $$ > "$1"; shift; exec "$@"' _ "$JO/pid-$label" python3 -I /e2e/owner-call.py "$@") || st=$?
    [ "$st" -ne 124 ] || fail "$label: the call did not return within 60 s"
    [ "$st" -eq 0 ] || fail "$label: owner-call.py gave no D-Bus reply (status $st)"
    case $out in
    ok) res=ok ;;
    *PolkitDenied) res=denied ;;
    *CertificateMismatch) res=mismatch ;;
    *WrongPasswordOrBadP12) res=wrong-password ;;
    *) res="error:${out// /_}" ;;
    esac
    observe "$label" "$res"
}
cli() { # LABEL then the jo-cli.py arguments after the pid file: records cli-ok / cli-denied / cli-failed
    local label=$1 out res st=0
    shift
    out=$(timeout 60 python3 -I /e2e/jo-cli.py "$JO/pid-$label" "$@") || st=$?
    [ "$st" -ne 124 ] || fail "$label: the CLI did not return within 60 s"
    if [ "$st" -eq 0 ]; then res=cli-ok; elif grep -qi 'not authorized' <<< "$out"; then res=cli-denied; else res=cli-failed; fi
    observe "$label" "$res"
}
p11sign() { # LABEL: one signature with pkcs11-tool over data.bin, the signature kept for the sweep
    local label=$1 st=0
    # shellcheck disable=SC2016 # as in dbus: the inner shell writes its pid and execs
    timeout 60 bash -c 'echo $$ > "$1"; shift; exec "$@"' _ "$JO/pid-$label" pkcs11-tool --module "$MODULE" --token-label jo-key --label jo-key --type privkey \
        --sign --mechanism SHA256-RSA-PKCS --input-file "$JO/data.bin" --output-file "$JO/sig-$label.bin" > "$JO/p11-$label.log" 2>&1 || st=$?
    [ "$st" -ne 124 ] || fail "$label: pkcs11-tool did not return within 60 s"
    if [ "$st" -eq 0 ]; then observe "$label" p11-ok; else observe "$label" p11-failed; fi
}
P12=$JO/k.p12

mark jo-ops-start
mode approve
cli import-cli-stored import "$P12" jo-key e2e-password
p11sign sign-p11-approved
dbus sign-dbus-approved sign jo-key "$JO/sig-sign-dbus-approved.bin"

mode deny
dbus import-denied-dbus import jo-den "$P12" e2e-password
cli import-denied-cli import "$P12" jo-den2 e2e-password
p11sign sign-p11-denied
dbus sign-dbus-denied sign jo-key "$JO/sig-sign-dbus-denied.bin"

mode approve
dbus import-wrong-password import jo-wp "$P12" not-the-password

mode deny
dbus replace-denied replace jo-key "$JO/cert2.der"
mode approve
dbus replace-replaced replace jo-key "$JO/cert2.der"
dbus replace-mismatch replace jo-key "$JO/cert-other.der"
p11sign sign-after-replace

mode deny
cli delete-denied delete jo-key
mode approve
p11sign sign-after-denied-delete
cli delete-deleted delete jo-key

# a call that fails before polkit leaves no entry: the key is gone, so this is NoSuchKey (recorded apart from the ledger; root judges it, and the
# window must hold no entry for it)
before=$(wc -l < "$E2E_DIR/requests")
python3 -I /e2e/owner-call.py sign jo-key > "$JO/extra" || true
[ "$(wc -l < "$E2E_DIR/requests")" -eq "$before" ] || fail "the sign on the deleted key reached the agent"
mark jo-ops-end
echo "jo-user: done"
