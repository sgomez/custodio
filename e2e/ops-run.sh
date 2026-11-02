#!/usr/bin/env bash
# Root side of the ops-polkit-* cases (F92, acceptance 3 and the polkit-ordering half of acceptance 4 of SPEC.md): alice, in a login session of her own with a test agent
# (ops-user.sh), imports, deletes and replaces the certificate of keys with the agent approving, denying, and polkit stopped. Needs WORK and MODULE.
#
# Placement: guest.sh runs this after the owner step and before upgrade.sh. Every key this step makes is deleted by alice at its end (checked here: the
# state directory is as before), and polkit is active again (checked here; guest.sh's trap restores it on any other path). Its calls add journal entries and
# agent lines after the journal step has counted, like the owner step.
# The user session cannot read the state directory nor stop polkit, so it asks this script through files (`rootdo` in ops-user.sh); this script serves the
# requests while the session runs.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/ops-lib.sh
source "$here/ops-lib.sh"
# shellcheck source=e2e/upgrade-lib.sh
source "$here/upgrade-lib.sh"
bash "$here/ops-selftest.sh" || fail "the ops self-test failed"

OPS=$WORK/ops
rm -rf "$OPS"
mkdir "$OPS"
chmod 1777 "$OPS"
# One key with two certificates (the replace uses the second), and its .p12 with the first.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OPS/k.key" 2> /dev/null
for n in 1 2; do
    case $n in 1) word=one ;; *) word=two ;; esac
    openssl req -new -x509 -key "$OPS/k.key" -subj "/CN=custodio e2e ops $word" -days 30 -out "$OPS/cert$n.pem"
    openssl x509 -in "$OPS/cert$n.pem" -outform DER -out "$OPS/cert$n.der"
done
openssl pkcs12 -export -inkey "$OPS/k.key" -in "$OPS/cert1.pem" -name ops -passout pass:e2e-password -out "$OPS/k1.p12"
rm -f "$OPS/k.key"
chmod 644 "$OPS"/*

snapshot_state > "$OPS/start.state" || fail "cannot snapshot the state directory"
restore_polkit() { systemctl unmask --runtime polkit && systemctl start polkit; }
polkit_stopped=''
cleanup() {
    [ -z "${upid:-}" ] || kill "$upid" 2> /dev/null || true
    if [ -n "$polkit_stopped" ]; then systemctl unmask --runtime polkit > /dev/null 2>&1 || true; systemctl start polkit > /dev/null 2>&1 || true; fi
}
trap cleanup EXIT
timeout 900 su -l alice -c "WORK=$WORK MODULE=$MODULE bash /e2e/ops-user.sh" > "$OPS/alice.out" 2>&1 &
upid=$!
serve() { # the requests of the session, until it ends
    local f name
    while kill -0 "$upid" 2> /dev/null; do
        for f in "$OPS"/want-*; do
            [ -e "$f" ] || continue
            name=${f##*/want-}
            [ ! -e "$OPS/have-$name" ] || continue
            case $name in
            snap-*)
                snapshot_state > "$OPS/${name#snap-}.state" || { echo "snapshot failed" >&2; return 1; }
                chmod 644 "$OPS/${name#snap-}.state"
                ;;
            polkit-stop)
                polkit_stopped=1
                systemctl stop polkit
                systemctl mask --runtime polkit > /dev/null 2>&1
                if systemctl is-active --quiet polkit; then echo "polkit still active" >&2; return 1; fi
                ;;
            polkit-start)
                restore_polkit || { echo "polkit could not be restored" >&2; return 1; }
                polkit_stopped=''
                systemctl is-active --quiet polkit || { echo "polkit is not active after the restore" >&2; return 1; }
                touch "$OPS/polkit-active-again"
                ;;
            *) echo "unknown request '$name'" >&2; return 1 ;;
            esac
            touch "$OPS/have-$name"
        done
        sleep 0.1
    done
}
serve || { cat "$OPS/alice.out" >&2; fail "serving alice's session failed"; }
wait "$upid" || { cat "$OPS/alice.out" >&2; fail "alice's session failed"; }
upid=''
[ ! -e "$OPS/want-polkit-stop" ] || [ -e "$OPS/polkit-active-again" ] || fail "polkit was not restored"
snapshot_state > "$OPS/end.state"
CALLS=$OPS/calls

problems=''
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p=$2
    p=$(printf '%s\n' "$p" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
call_p() { ops_call_problems "$CALLS" "$@"; }
snap_p() { # LABEL A B: the list/certificates part and the state directory part of two snapshots
    ops_state_problems "$1 (list and certificates)" "$OPS/$2.user" "$OPS/$3.user"
    ops_state_problems "$1 (state directory)" "$OPS/$2.state" "$OPS/$3.state"
}
once() { echo "approve $1"; }

# Acceptance 3: each of the three asks exactly once, under its own action, and succeeds (a light check of the outcome; the rest of it is F93's).
judge ops-polkit-import-asks-once "$(call_p import-once ok "$(once $OPS_ACTION_IMPORT)"; ops_listed_problems "$OPS/a1.user" +ops-imp +ops-base)"
judge ops-polkit-delete-asks-once "$(call_p delete-once ok "$(once $OPS_ACTION_DELETE)"; ops_listed_problems "$OPS/a2.user" -ops-imp +ops-base)"
judge ops-polkit-replace-asks-once "$(call_p replace-once ok "$(once $OPS_ACTION_REPLACE)"; ops_differ_problems "replace-once" "$OPS/b0.user" "$OPS/b1.user")"

# Acceptance 3: denied, the documented name (and a failing CLI), one request each, nothing changed.
d() { echo "deny $1"; }
judge ops-polkit-denied "$(call_p den-import "$OPS_DENIED" "$(d $OPS_ACTION_IMPORT)"
    call_p den-delete "$OPS_DENIED" "$(d $OPS_ACTION_DELETE)"
    call_p den-replace "$OPS_DENIED" "$(d $OPS_ACTION_REPLACE)"
    call_p den-cli-import cli-denied "$(d $OPS_ACTION_IMPORT)"
    call_p den-cli-delete cli-denied "$(d $OPS_ACTION_DELETE)"
    snap_p denied d0 d1)"

# Acceptance 3: polkit stopped, the documented name, no request, nothing changed, polkit back.
judge ops-polkit-unavailable "$(call_p un-import "$OPS_UNAVAILABLE" ''
    call_p un-delete "$OPS_UNAVAILABLE" ''
    call_p un-replace "$OPS_UNAVAILABLE" ''
    snap_p unavailable u0 u1
    [ -e "$OPS/polkit-active-again" ] || echo "polkit was not active again afterwards")"

# Acceptance 3: a second call asks again. Only the requests of the first call, and the outcome of the second, are judged here (denied is the case above).
judge ops-polkit-asks-again "$(for op in import:IMPORT replace:REPLACE delete:DELETE; do
        a=OPS_ACTION_${op#*:}
        call_p "again-${op%%:*}-1" '*' "$(d "${!a}")"
        call_p "again-${op%%:*}-2" ok "$(once "${!a}")"
    done)"

# Acceptance 4: the wrong password with polkit refusing is a refusal (the .p12 is not opened); approved, it is the wrong-password error; the same .p12 with
# the right password then imports (so it was the password).
judge ops-polkit-wrong-password-denied "$(call_p wp-denied "$OPS_DENIED" "$(d $OPS_ACTION_IMPORT)"
    snap_p wrong-password-denied w0 w1
    ops_listed_problems "$OPS/w1.user" -ops-wp
    call_p un-wp "$OPS_UNAVAILABLE" ''
    ops_listed_problems "$OPS/u1.user" -ops-un2)"
judge ops-polkit-wrong-password-approved "$(call_p wp-approved "$OPS_WRONG_PASSWORD" "$(once $OPS_ACTION_IMPORT)"
    snap_p wrong-password-approved w0 w2
    ops_listed_problems "$OPS/w2.user" -ops-wp
    call_p wp-correct ok "$(once $OPS_ACTION_IMPORT)"
    ops_listed_problems "$OPS/w3.user" +ops-wp)"

# Nothing is left behind: the state directory is as before the step.
if [ -n "$(ops_state_problems "end" "$OPS/start.state" "$OPS/end.state")" ]; then problems="$problems
end:
$(ops_state_problems "the state directory after the step" "$OPS/start.state" "$OPS/end.state")"; fi
[ -z "$problems" ] || fail "ops-polkit cases:$problems"
echo "ops-run: passed"
