#!/usr/bin/env bash
# Root side of the owner-* cases (F91, acceptance 1 and 2 of SPEC.md): two real accounts, alice (A) and bob (B), each in a login session of
# their own with a test agent of their own (owner-user.sh). Needs WORK, MODULE, START (epoch seconds before the journal is queried).
#
# Placement: guest.sh runs this after journal-check.sh and before upgrade.sh. It leaves no key behind (each user deletes the keys of this step at its
# end, with the agent approving), so what the upgrade and lifecycle cases look at is as before. The journal step has counted its entries by then;
# the entries of this step (imports, deletes, signatures) come after them, and the cases that follow look at the state of the keys or at windows of
# their own, never at a count of all entries ("shows it" of upgrade-keys-listed and the lifecycle cases).
#
# The sessions: A's runs in the background through the whole step, so her agent is alive and logging while B calls; B's is one session for the
# foreign calls and for his own signature, so the agent that would have been asked is the agent that logs his own request.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}" "${START:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/owner-lib.sh
source "$here/owner-lib.sh"
bash "$here/owner-selftest.sh" || fail "the owner self-test failed"

OWN=$WORK/owner
rm -rf "$OWN"
mkdir "$OWN"
chmod 1777 "$OWN" # both users write here: their own files, and the agent state
id bob > /dev/null 2>&1 || useradd -m -s /bin/bash bob
# Keys: A has one, B has another (different keys and certificates), both under the password the other imports use.
for who in a b; do
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OWN/$who.key" 2> /dev/null
    openssl req -new -x509 -key "$OWN/$who.key" -subj "/CN=custodio e2e owner $who" -days 30 -out "$OWN/$who.crt"
    openssl pkcs12 -export -inkey "$OWN/$who.key" -in "$OWN/$who.crt" -name "owner-$who" -passout pass:e2e-password -out "$OWN/$who.p12"
    openssl x509 -in "$OWN/$who.crt" -outform DER -out "$OWN/$who.der"
done
head -c 1500 /dev/urandom > "$OWN/data.bin"
rm -f "$OWN"/*.key
chmod 644 "$OWN"/*

run_user() { # USER MODE: a login session of USER, with the environment su -l drops
    timeout 600 su -l "$1" -c "WORK=$WORK MODULE=$MODULE bash /e2e/owner-user.sh $2"
}
run_user alice a > "$OWN/alice.out" 2>&1 &
apid=$!
for _ in $(seq 300); do [ -e "$OWN/a.imported" ] && break; kill -0 "$apid" 2> /dev/null || break; sleep 0.5; done
[ -e "$OWN/a.imported" ] || { cat "$OWN/alice.out" >&2; fail "alice's session did not import"; }
run_user bob b || { touch "$OWN/b.done"; wait "$apid" || true; cat "$OWN/alice.out" >&2; fail "bob's session failed"; }
touch "$OWN/b.done"
wait "$apid" || { cat "$OWN/alice.out" >&2; fail "alice's session failed"; }

# The journal: all the markers must be visible before anything is counted, after a sync (an entry is submitted before the reply, but journald may lag).
markers="owner-a-import-before owner-a-import-after owner-b-foreign-before owner-b-foreign-after owner-b-control-before owner-b-control-after"
seen=''
for _ in $(seq 60); do
    journalctl --sync
    journalctl --since "@$START" -o json --no-pager > "$OWN/journal.json"
    # shellcheck disable=SC2086 # one tag per word
    if python3 -I "$here/owner-journal.py" seen --json "$OWN/journal.json" $markers 2> /dev/null; then seen=1; break; fi
    sleep 0.5
done
# shellcheck disable=SC2086 # one tag per word
[ -n "$seen" ] || { python3 -I "$here/owner-journal.py" seen --json "$OWN/journal.json" $markers; fail "the markers never reached the journal"; }
jcount() { python3 -I "$here/owner-journal.py" count --json "$OWN/journal.json" --before "owner-$1-before" --after "owner-$1-after" --unit custodio.service; }

problems=''
judge() { # CASE PROBLEMS...: the case is reported when it has no problem
    local case=$1 p=$2
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}

# Acceptance 1, list: A's list shows the id and B's does not; B had no key before his own import, and A's list is the same after B's calls.
p=$(list_problems "$OWN/list-a-1" +owner-a +owner-same; list_problems "$OWN/list-a-2" +owner-a +owner-same
    list_problems "$OWN/list-b-1" -owner-a -owner-same; list_problems "$OWN/list-b-2" -owner-a +owner-same)
grep -qx 'You have no keys in the custodio service.' "$OWN/list-b-1" || p="$p
list-b-1 is not the sentence for no keys"
judge owner-list-isolated "$p"

# Acceptance 1, the error: sign, delete and replace certificate on A's id give the same name as on an id nobody has, which is NoSuchKey.
judge owner-foreign-id-no-such-key "$(call_problems "$OWN/b.calls")"

# Acceptance 1, no polkit: B's agent and A's agent log nothing for those calls (B's was checked alive in the same session, and logged his own
# import and signature afterwards, see owner-user.sh), and the three calls on A's id and the control did not move B's log.
p=$(count_problems "bob's agent log over the calls" "$(cat "$OWN/b.requests-0")" "$(cat "$OWN/b.requests-1")"
    count_problems "alice's agent log over bob's session" "$(cat "$OWN/a.requests-1")" "$(cat "$OWN/a.requests-2")")
[ "$(wc -l < "$OWN/agent-bob/requests")" -eq 3 ] || p="$p
bob's agent log has $(wc -l < "$OWN/agent-bob/requests") lines, expected his import, signature and delete"
[ "$(wc -l < "$OWN/agent-alice/requests")" -eq 6 ] || p="$p
alice's agent log has $(wc -l < "$OWN/agent-alice/requests") lines, expected her 2 imports, 2 signatures, 2 deletes"
judge owner-foreign-id-no-polkit "$p"

# Acceptance 1, journal: the calls on A's id leave as many entries of custodio.service as the calls on the id nobody has, and that is none
# (docs/audit.md: a call that fails before polkit leaves no entry). A's import entries lie before the window and are counted by the same query,
# so the query is shown able to find entries, and the window by the control of the review (calls made as the owner).
p=$(count_problems "journal entries of the calls on alice's id vs the id nobody has" "$(jcount b-foreign)" "$(jcount b-control)")
[ "$(jcount b-foreign)" = 0 ] || p="$p
the calls on alice's id left $(jcount b-foreign) journal entries, expected 0"
[ "$(jcount a-import)" = 2 ] || p="$p
alice's two imports left $(jcount a-import) entries in the journal, expected 2 (the query cannot see entries)"
# her key was not touched: listed, signing (one request each, see owner-user.sh) and with its certificate
cmp -s "$OWN/a-own.der" "$OWN/a.der" || p="$p
alice's certificate for owner-a after bob's calls is not the one she imported"
judge owner-foreign-id-journal "$p"

# Acceptance 2: the same id under both uids; each signs with their own key, and the signature verifies against that uid's certificate only.
p=''
cmp -s "$OWN/a-same.der" "$OWN/a.der" || p="alice's certificate for owner-same is not hers"
cmp -s "$OWN/b-same.der" "$OWN/b.der" || p="$p
bob's certificate for owner-same is not his"
p="$p
$(verify_problems "$OWN/a-sign-same.sig" "$OWN/data.bin" "$OWN/a-same.der")
$(verify_problems "$OWN/b-sign.sig" "$OWN/data.bin" "$OWN/b-same.der")
$(verify_fails_problems "$OWN/a-sign-same.sig" "$OWN/data.bin" "$OWN/b-same.der")
$(verify_fails_problems "$OWN/b-sign.sig" "$OWN/data.bin" "$OWN/a-same.der")"
judge owner-same-id-own-key "$(printf '%s\n' "$p" | sed '/^$/d')"

[ -z "$problems" ] || fail "owner cases:$problems"
echo "owner-run: passed"
