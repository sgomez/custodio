#!/usr/bin/env bash
# Runs as alice in one logind session of class user (`XDG_SESSION_CLASS=user su -l`, so that polkit finds her agent for a caller that is in a scope of her user
# manager and not in the session: the display session of the user) with WORK and MODULE set by appid-run.sh (F95). Usage: appid-user.sh prep|main|cap|end.
#   prep  starts a service of her user manager that keeps app.slice alive between the sessions (root creates children in it for the cap)
#   main, cap, end  make the calls of that phase of e2e/appid-ledger.txt with a test agent that approves or denies as the line says. Each call is made by
#                   appid-enter.py, started the way the KIND says; it records what alice saw in $AI/observed. Root judges all of it; alice judges nothing.
# The hostile names are never on a command line (systemd-run logs the command it starts): appid-enter.py reads them from $AI/names.tsv by label.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
phase=${1:?usage: appid-user.sh prep|main|cap|end}
AI=$WORK/appid
[ -n "${XDG_SESSION_ID:-}" ] || fail "no logind session (XDG_SESSION_ID is empty)"
[ "$(loginctl show-session "$XDG_SESSION_ID" -p Class --value)" = user ] || fail "the session is not of class user"

if [ "$phase" = prep ]; then
    systemd-run --user -q --collect --unit=appid-anchor sleep infinity || fail "cannot start the service that keeps app.slice alive"
    echo "appid-user: prep done"
    exit 0
fi

export E2E_DIR=$AI/agent-$phase
mkdir -p "$E2E_DIR"
: > "$E2E_DIR/requests"
: > "$E2E_DIR/subjects"
echo approve > "$E2E_DIR/mode"
python3 -I /e2e/agent.py > "$E2E_DIR/agent.log" 2>&1 &
agent=$!
trap 'kill "$agent" 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q registered "$E2E_DIR/agent.log" && break; sleep 0.1; done
grep -q registered "$E2E_DIR/agent.log" || { cat "$E2E_DIR/agent.log" >&2; fail "the agent did not register"; }

run() { timeout 120 "$@" < /dev/null; } # the calls must not read the ledger the loop reads
n=0
while read -r label ph kind cg op mode _outcome _state _id _result; do
    case $label in '' | '#'*) continue ;; esac
    [ "$ph" = "$phase" ] || continue
    echo "$mode" > "$E2E_DIR/mode"
    case $op in
    sign)
        cls=p11
        cmd=(pkcs11-tool --module "$MODULE" --token-label ai-key --label ai-key --type privkey --sign --mechanism SHA256-RSA-PKCS
            --input-file "$AI/data.bin" --output-file "$AI/sig-$label.bin") ;;
    import) cls=dbus; cmd=(python3 -I /e2e/owner-call.py import ai-key "$AI/k.p12" e2e-password) ;;
    replace_certificate) cls=dbus; cmd=(python3 -I /e2e/owner-call.py replace ai-key "$AI/cert2.der") ;;
    delete) cls=dbus; cmd=(python3 -I /e2e/owner-call.py delete ai-key) ;;
    *) fail "$label: unknown operation $op" ;;
    esac
    enter=(python3 -I /e2e/appid-enter.py "$AI" "$label" "$cls")
    [ "$cg" = - ] || enter+=(--cg "$cg")
    enter+=(-- "${cmd[@]}")
    n=$((n + 1))
    st=0
    case $kind in
    session) run "${enter[@]}" || st=$? ;;
    flatpak) # the unit name flatpak gives (the `-` of the id is \x2d), with an instance number of its own
        run systemd-run --user --scope -q --unit="app-flatpak-org.example.My_App\\x2dName-$((7000 + n))" "${enter[@]}" || st=$? ;;
    gnome) run systemd-run --user --scope -q --unit="app-gnome-gedit-$((7000 + n))" "${enter[@]}" || st=$? ;;
    cg) run systemd-run --user --scope -q "${enter[@]}" || st=$? ;;
    *) fail "$label: unknown kind $kind" ;;
    esac
    [ "$st" -ne 124 ] || fail "$label: the call did not return within 120 s"
    [ "$st" -eq 0 ] || fail "$label: the caller could not be run (status $st)"
done < /e2e/appid-ledger.txt
[ "$n" -gt 0 ] || fail "the phase $phase has no call in the ledger"
if [ "$phase" = end ]; then
    systemctl --user stop appid-anchor || fail "cannot stop the service that kept app.slice alive"
fi
echo "appid-user: $phase done ($n calls)"
