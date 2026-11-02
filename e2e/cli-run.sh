#!/usr/bin/env bash
# Root side of the cli-* cases (F97, acceptance 11 of SPEC.md), with WORK and MODULE set. Alice, in a login session of her own with a test agent (cli-user.sh), lists
# and deletes keys with the shipped CLI on a pseudo-terminal; carol, a fresh account, has no keys (the "none" case) and, in a session with NO agent, imports and deletes
# through `pkttyagent` (cli-pty-user.sh) while PAM service polkit-1 checks her password. This script makes the fixtures, serves the snapshots of the state directory
# (they cannot read it), sets up and restores PAM and the account, and judges the evidence (cli-lib.sh).
# Placement: guest.sh runs the step after appid and before the upgrade. Every key is deleted by its owner; the state directory is compared with the one at the start, the
# PAM file with the original, and the account is removed, so the cases after it see the guest as before.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/cli-lib.sh
source "$here/cli-lib.sh"
# shellcheck source=e2e/upgrade-lib.sh
source "$here/upgrade-lib.sh"
bash "$here/cli-selftest.sh" || fail "the cli self-test failed"

CLI=$WORK/cli
PAM=/etc/pam.d/polkit-1
ACCOUNT_PW=carol-account-pw-4f1c
WRONG_PW=carol-wrong-pw-0b7e
upid=''
cleanup() {
    [ -z "$upid" ] || kill "$upid" 2> /dev/null || true
    if [ -f "$CLI/polkit-1.orig" ]; then cp -p "$CLI/polkit-1.orig" "$PAM"; fi
    if id carol > /dev/null 2>&1; then
        loginctl terminate-user carol > /dev/null 2>&1 || true
        userdel -r -f carol > /dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
! id carol > /dev/null 2>&1 || fail "the account carol exists before the step"
rm -rf "$CLI"
mkdir "$CLI"
chmod 1777 "$CLI"

# fixtures: two keys of different types, certificates with known subject and end of validity; the expected values are what OpenSSL says about them
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$CLI/rsa.key" 2> /dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$CLI/ec.key" 2> /dev/null
key_type() { # KEY: the type the service reports for it, from what OpenSSL says about the key
    local text
    text=$(openssl pkey -in "$1" -noout -text)
    case $text in
    *prime256v1*) printf 'ecdsa-p256' ;; # an EC key also says "Private-Key: (256 bit)", so it is looked for first
    "Private-Key: ("*" bit"*) printf 'rsa%s' "$(printf '%s' "$text" | sed -n '1s/^Private-Key: (\([0-9]*\) bit.*/\1/p')" ;;
    *) printf 'unknown' ;;
    esac
}
mkkey() { # NAME CN DAYS: NAME.pem, NAME.p12 and the expectations NAME.type NAME.subject NAME.end
    openssl req -new -x509 -key "$CLI/$1.key" -subj "/CN=$2" -days "$3" -out "$CLI/$1.pem"
    openssl pkcs12 -export -inkey "$CLI/$1.key" -in "$CLI/$1.pem" -name "$1" -passout pass:e2e-password -out "$CLI/$1.p12"
    key_type "$CLI/$1.key" > "$CLI/$1.type"
    openssl x509 -in "$CLI/$1.pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=//' > "$CLI/$1.subject"
    date -u -d "$(openssl x509 -in "$CLI/$1.pem" -noout -enddate | sed 's/^notAfter=//')" +%Y-%m-%dT%H:%M:%SZ > "$CLI/$1.end"
}
mkkey rsa f97-rsa 30
mkkey ec f97-ec 45
[ "$(cat "$CLI/rsa.type")" = rsa2048 ] && [ "$(cat "$CLI/ec.type")" = ecdsa-p256 ] || fail "key types of the fixtures: $(cat "$CLI/rsa.type") $(cat "$CLI/ec.type")"
rm -f "$CLI/rsa.key" "$CLI/ec.key"
printf '%s' "$ACCOUNT_PW" > "$CLI/account.pw"
printf '%s' "$WRONG_PW" > "$CLI/wrong.pw"
chmod 644 "$CLI"/*

useradd -m -s /bin/bash carol
cp -p "$PAM" "$CLI/polkit-1.orig"
snapshot_state > "$CLI/start.state" || fail "cannot snapshot the state directory"
journalctl --sync > /dev/null 2>&1 || true
since=$(date '+%Y-%m-%d %H:%M:%S')

serve() { # UPID: answers the requests of the session until it ends
    local f name
    while kill -0 "$1" 2> /dev/null; do
        for f in "$CLI"/want-*; do
            [ -e "$f" ] || continue
            name=${f##*/want-}
            [ ! -e "$CLI/have-$name" ] || continue
            case $name in
            snap-*) snapshot_state > "$CLI/${name#snap-}.state" || { echo "snapshot failed" >&2; return 1; }; chmod 644 "$CLI/${name#snap-}.state" ;;
            carol-list)
                st=0
                timeout 60 su -l carol -c "custodio list > $CLI/carol.list 2>&1" || st=$?
                echo "$st" > "$CLI/carol.exit"
                chmod 644 "$CLI/carol.list" "$CLI/carol.exit" ;;
            *) echo "unknown request '$name'" >&2; return 1 ;;
            esac
            touch "$CLI/have-$name"
        done
        sleep 0.1
    done
}
session() { # USER SCRIPT OUT: runs the script in a login session of the user, serving it
    timeout 900 su -l "$1" -c "WORK=$WORK MODULE=$MODULE bash /e2e/$2" > "$CLI/$3" 2>&1 &
    upid=$!
    serve "$upid" || { cat "$CLI/$3" >&2; fail "serving the session of $1 failed"; }
    wait "$upid" || { cat "$CLI/$3" >&2; fail "the session of $1 failed"; }
    upid=''
}
session alice cli-user.sh alice.out

# the pkttyagent cases: PAM checks the password of carol for the polkit-1 service, for the duration of the session only
printf 'auth required pam_unix.so\naccount required pam_unix.so\n' > "$PAM"
cp "$PAM" "$CLI/pam.during"
echo "carol:$ACCOUNT_PW" | chpasswd
session carol cli-pty-user.sh carol.out
cp -p "$CLI/polkit-1.orig" "$PAM"
same_file "$PAM" "$CLI/polkit-1.orig" || fail "the PAM file of polkit-1 could not be restored"
# the service keeps the (empty) directory of an account that had keys: it is carol's, and goes with her
carol_dir=$(readlink -f "$STATE_LINK")/$(id -u carol)
rmdir "$carol_dir" 2> /dev/null || true # fails if it holds anything, which the comparison below then shows
snapshot_state > "$CLI/end.state"
journalctl --sync > /dev/null 2>&1 || true
journalctl --no-pager --since "$since" > "$CLI/journal.txt" 2>&1 || true
chmod 644 "$CLI"/*

problems=''
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p=$2
    p=$(printf '%s\n' "$p" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
acall() { ops_call_problems "$CLI/calls" "$@"; }
pcall() { ops_call_problems "$CLI/pcalls" "$@"; }
same() { # LABEL A B: list/certificates part and state directory part equal
    ops_state_problems "$1 (list and certificates)" "$CLI/$2.user" "$CLI/$3.user"
    ops_state_problems "$1 (state directory)" "$CLI/$2.state" "$CLI/$3.state"
}
approve() { echo "approve $1"; }
judge cli-list-keys "$(cli_exit_problems "custodio list" "$(cat "$CLI/list.exit")"
    cli_list_block_problems "$CLI/list.out" cli-rsa "$(cat "$CLI/rsa.type")" "$(cat "$CLI/rsa.subject")" "$(cat "$CLI/rsa.end")"
    cli_list_block_problems "$CLI/list.out" cli-ec "$(cat "$CLI/ec.type")" "$(cat "$CLI/ec.subject")" "$(cat "$CLI/ec.end")"
    cli_list_only_problems "$CLI/list.out" cli-rsa cli-ec ec1 rsa1)"
judge cli-list-none "$(cli_none_problems "$CLI/carol.list" "$(cat "$CLI/carol.exit")"
    cli_has_keys_problems "$CLI/list.out")"
judge cli-delete-confirms "$(acall confirms ok "$(approve $CLI_ACTION_DELETE)"
    cli_events_problems "$CLI/confirms.events"
    cli_confirm_problems "$CLI/confirms.out" "$CLI/confirms.events"
    list_problems "$CLI/c3.user" +cli-ec +cli-rsa
    list_problems "$CLI/c4.user" -cli-ec +cli-rsa
    rd_token_problems "$CLI/c3.slots" +cli-ec +cli-rsa
    rd_token_problems "$CLI/c4.slots" -cli-ec +cli-rsa
    cli_state_key_problems "$CLI/c3.state" cli-ec present
    cli_state_key_problems "$CLI/c4.state" cli-ec absent
    cli_state_only_problems "$CLI/c3.state" "$CLI/c4.state" cli-ec)"
judge cli-delete-declined-confirmation "$(acall declined-confirmation cli-failed ''
    cli_events_problems "$CLI/declined-confirmation.events"
    cli_confirm_problems "$CLI/declined-confirmation.out" "$CLI/declined-confirmation.events"
    same "after declining the confirmation" c1 c2
    rd_token_problems "$CLI/c2.slots" +cli-ec +cli-rsa)"
judge cli-delete-declined-polkit "$(acall declined-polkit cli-failed "deny $CLI_ACTION_DELETE"
    cli_events_problems "$CLI/declined-polkit.events"
    same "after polkit refused" c2 c3
    rd_token_problems "$CLI/c3.slots" +cli-ec +cli-rsa)"
judge cli-no-agent-precondition "$(pcall pre-import "$OPS_DENIED" ''
    cli_no_test_agent_problems "$CLI/pre.procs"
    cli_no_leftover_problems "before the cases" "$CLI/pre.procs"
    same "the refused import over D-Bus" p0 p1
    list_problems "$CLI/p1.user" -cli-pre
    cli_pam_problems "$CLI/pam.during")"
judge cli-import-pkttyagent "$(pcall import-right ok ''
    cli_events_problems "$CLI/import-right.events"
    cli_agent_prompt_problems "$CLI/import-right.out" "$CLI/import-right.events" "$CLI_ACTION_IMPORT" carol
    cli_agent_outcome_problems "$CLI/import-right.out" complete
    list_problems "$CLI/p3.user" +cli-pty
    rd_token_problems "$CLI/p3.slots" +cli-pty
    cli_state_key_problems "$CLI/p3.state" cli-pty present
    cli_no_leftover_problems "after the import" "$CLI/import-right.procs")"
judge cli-import-pkttyagent-wrong-password "$(pcall import-wrong cli-failed ''
    cli_pam_problems "$CLI/pam.during"
    cli_agent_prompt_problems "$CLI/import-wrong.out" "$CLI/import-wrong.events" "$CLI_ACTION_IMPORT" carol
    cli_agent_outcome_problems "$CLI/import-wrong.out" failed
    same "after the wrong password" p1 p2
    list_problems "$CLI/p2.user" -cli-pty
    cli_no_leftover_problems "after the wrong password" "$CLI/import-wrong.procs")"
judge cli-delete-pkttyagent "$(pcall delete-right ok ''
    cli_events_problems "$CLI/delete-right.events"
    cli_confirm_problems "$CLI/delete-right.out" "$CLI/delete-right.events"
    cli_agent_prompt_problems "$CLI/delete-right.out" "$CLI/delete-right.events" "$CLI_ACTION_DELETE" carol
    cli_agent_outcome_problems "$CLI/delete-right.out" complete
    list_problems "$CLI/p3.user" +cli-pty
    list_problems "$CLI/p4.user" -cli-pty
    cli_no_token_problems "$CLI/p4.slots" cli-pty
    cli_state_key_problems "$CLI/p4.state" cli-pty absent
    cli_no_leftover_problems "after the delete" "$CLI/delete-right.procs")"
end=$(ops_state_problems "the state directory after the step" "$CLI/start.state" "$CLI/end.state"
    same_file "$PAM" "$CLI/polkit-1.orig" || echo "the PAM file of polkit-1 is not the original"
    cli_no_secret_problems "$CLI/journal.txt" e2e-password "$ACCOUNT_PW" "$WRONG_PW")
if [ -n "$end" ]; then problems="$problems
end:
$end"; fi
[ -z "$problems" ] || fail "cli cases:$problems"
echo "cli-run: passed"
