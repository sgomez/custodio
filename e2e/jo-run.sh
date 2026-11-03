#!/usr/bin/env bash
# Root side of the journal-ops-* cases (F94, acceptance 7 of SPEC.md). Needs WORK and MODULE. Alice, in a login session of her own with a test agent
# (jo-user.sh), signs, imports, deletes and replaces a certificate through the shipped CLI, pkcs11-tool and a D-Bus client, with the agent approving or
# denying each call as e2e/jo-ledger.txt says, between two marker entries of the journal. This script makes the fixtures, then reads the journal of
# custodio.service between the markers and judges it with jo.py (and the sweep of journal.py).
# Placement: guest.sh runs it after the delete step and before the upgrade. Every key it imports it deletes, so the state directory and the agent
# request count of the earlier steps (TOTAL) after the step are those before it (judged here).
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/upgrade-lib.sh
source "$here/upgrade-lib.sh"
# shellcheck source=e2e/ops-lib.sh
source "$here/ops-lib.sh"
bash "$here/jo-selftest.sh" || fail "the jo self-test failed"

UNIT=custodio.service
JO=$WORK/jo
rm -rf "$JO"
mkdir "$JO"
chmod 1777 "$JO"
service_uid=$(id -u custodio)
alice_uid=$(id -u alice)
jo() { python3 -I "$here/jo.py" "$@"; }

# The first thing: can root write an entry with CUSTODIO_* fields, and does journalctl select it by them? It decides control (c) of the queries case. The
# entry is written before the window of alice's calls, so no window holds it.
t0=$(date +%s)
forge=impossible
python3 -I "$here/jo-forge.py" MESSAGE=jo-probe CUSTODIO_OPERATION=jo-probe SYSLOG_IDENTIFIER=custodio-e2e-forged || true
for _ in $(seq 20); do
    journalctl --sync
    if journalctl CUSTODIO_OPERATION=jo-probe --since "@$t0" -o json --no-pager | grep -q '"MESSAGE":"jo-probe"'; then forge=possible; break; fi
    sleep 0.5
done
echo "jo-run: root writing an entry with CUSTODIO_* fields, selected by them: $forge"

# Fixtures: a key with two certificates, a second key and its certificate, a .p12 of the first, the data of the D-Bus client (32 bytes), the passwords.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$JO/k.key" 2> /dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$JO/other.key" 2> /dev/null
mkcert() { openssl req -new -x509 -key "$1" -subj "/CN=$2" -days 30 -out "$3.pem" && openssl x509 -in "$3.pem" -outform DER -out "$3.der"; }
mkcert "$JO/k.key" f94-old "$JO/cert1"
mkcert "$JO/k.key" f94-new "$JO/cert2"
mkcert "$JO/other.key" f94-other "$JO/cert-other"
openssl pkcs12 -export -inkey "$JO/k.key" -in "$JO/cert1.pem" -name f94 -passout pass:e2e-password -out "$JO/k.p12"
rm -f "$JO/k.key" "$JO/other.key"
# over 1024 bytes, so that pkcs11-tool does not retry a denied one-shot C_Sign as a second signature (journal-cases.sh)
head -c 2000 /dev/urandom > "$JO/data.bin"
python3 -I -c 'import sys; sys.stdout.buffer.write(bytes(range(32)))' > "$JO/owner-data.bin"
printf %s e2e-password > "$JO/pw-right"
printf %s not-the-password > "$JO/pw-wrong"
chmod 644 "$JO"/*

agent_lines() { if [ -f "$WORK/agent/requests" ]; then wc -l < "$WORK/agent/requests"; else echo 0; fi; }
total_before=$(agent_lines)
snapshot_state > "$JO/start.state" || fail "cannot snapshot the state directory"
since=$(date +%s)
timeout 900 su -l alice -c "WORK=$WORK MODULE=$MODULE bash /e2e/jo-user.sh" > "$JO/alice.out" 2>&1 || { cat "$JO/alice.out" >&2; fail "alice's session failed"; }

get_window() { # SINCE START END PREFIX: waits until both markers are in the journal; writes PREFIX.all.json, PREFIX.window, PREFIX.cursors; prints the start cursor
    local since=$1 start=$2 end=$3 prefix=$4
    for _ in $(seq 60); do
        journalctl --sync
        journalctl --since "@$since" -o json --no-pager > "$prefix.all.json"
        if python3 -I "$here/owner-journal.py" seen --json "$prefix.all.json" "$start" "$end" 2> /dev/null; then break; fi
        sleep 0.5
    done
    jo window --json "$prefix.all.json" --start "$start" --end "$end" --window-out "$prefix.window" --cursors-out "$prefix.cursors"
}
run_queries() { # CURSOR DIR: every extracted query, the documented ones with only the placeholders replaced, plus the cursor after which the window starts
    local index args _rest
    mkdir -p "$2"
    while IFS=$'\t' read -r index args _rest; do
        # shellcheck disable=SC2086 # the arguments of a query are words
        journalctl --after-cursor="$1" $args -o json --no-pager > "$2/q-$index.json" || fail "query $index ($args) failed"
    done < "$JO/queries.tsv"
}
start_cursor=$(get_window "$since" jo-ops-start jo-ops-end "$JO/w") || fail "the markers of alice's calls are not in the journal once each"

problems=''
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p=$2
    p=$(printf '%s\n' "$p" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
# the ledger: the plan and what alice saw agree
jo merge --plan "$here/jo-ledger.txt" --observed "$JO/observed" --uid "$alice_uid" --out "$JO/ledger" || fail "alice's calls are not the calls of e2e/jo-ledger.txt"
ent() { jo entries --window "$JO/w.window" --ledger "$JO/ledger" --unit "$UNIT" --service-uid "$service_uid" "$@" 2>&1 || true; }
judge journal-ops-sign "$(ent --op sign)"
judge journal-ops-import "$(ent --op import)"
judge journal-ops-delete "$(ent --op delete)"
judge journal-ops-replace "$(ent --op replace_certificate)"
# exactly one entry per call and no more: every ledger line has its entry, no audit entry lacks a line, and the call on the deleted key left none
p=$(ent)
grep -q 'error com.rfirma.Custodio1.Error.NoSuchKey$' "$JO/extra" || p="$p
sign on the deleted key: '$(cat "$JO/extra")', expected NoSuchKey"
judge journal-ops-exactly-one "$p"

# no entry holds the .p12, the password, a certificate, the data or a signature, in any form
journalctl -u "$UNIT" --after-cursor="$start_cursor" -o export --no-pager > "$JO/service.export"
mkdir "$JO/secrets"
cp "$JO/k.p12" "$JO/cert1.der" "$JO/cert2.der" "$JO/cert-other.der" "$JO/data.bin" "$JO/owner-data.bin" "$JO/pw-right" "$JO/pw-wrong" "$JO"/sig-*.bin "$JO/secrets/"
p=$(python3 -I "$here/journal.py" sweep --export "$JO/service.export" --evidence "$JO/secrets" --password e2e-password 2>&1 >/dev/null || true)
[ "$(grep -ac '^CUSTODIO_OPERATION=' "$JO/service.export")" = "$(wc -l < "$JO/ledger")" ] || p="$p
the export holds $(grep -ac '^CUSTODIO_OPERATION=' "$JO/service.export") audit entries, the ledger has $(wc -l < "$JO/ledger"): the sweep did not look at the entries"
judge journal-ops-no-secrets "$p"

# every query docs/audit.md documents, with only its placeholders replaced and the window bound added
doc=/e2e-docs/audit.md # mounted by run.sh: the document of the repository, not a copy
[ -f "$doc" ] || doc=$here/../docs/audit.md
jo extract --doc "$doc" --uid "$alice_uid" --service-uid "$service_uid" --key jo-key --out "$JO/queries.tsv" || fail "docs/audit.md holds a query this step cannot judge"
run_queries "$start_cursor" "$JO/q"
p=$(jo queries --queries "$JO/queries.tsv" --results "$JO/q" --cursors "$JO/w.cursors" --ledger "$JO/ledger" --window "$JO/w.window" --unit "$UNIT" --service-uid "$service_uid" 2>&1 || true)
# control (c): a forged entry with the fields of a signing entry, written by root inside a window of its own: the documented queries do not return it, a query without
# _SYSTEMD_UNIT and _UID does
if [ "$forge" = possible ]; then
    t2=$(date +%s)
    printf '%s\n' jo-forged-start | systemd-cat -t custodio-e2e-jo
    python3 -I "$here/jo-forge.py" MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401 CUSTODIO_OPERATION=sign CUSTODIO_OUTCOME=signed CUSTODIO_KEY_ID=jo-key \
        "CUSTODIO_UID=$alice_uid" CUSTODIO_PID=1 PRIORITY=6 SYSLOG_IDENTIFIER=custodiod "MESSAGE=forged by the test: not from the service"
    printf '%s\n' jo-forged-end | systemd-cat -t custodio-e2e-jo
    c2=$(get_window "$t2" jo-forged-start jo-forged-end "$JO/f") || fail "the markers of the forged entry are not in the journal once each"
    : > "$JO/empty-ledger"
    run_queries "$c2" "$JO/fq"
    p="$p
$(jo queries --queries "$JO/queries.tsv" --results "$JO/fq" --cursors "$JO/f.cursors" --ledger "$JO/empty-ledger" --window "$JO/f.window" --unit "$UNIT" --service-uid "$service_uid" 2>&1 || true)"
    journalctl --after-cursor="$c2" CUSTODIO_OPERATION=sign -o json --no-pager > "$JO/fq-unfiltered.json"
    [ "$(jo count --json "$JO/fq-unfiltered.json" --cursors "$JO/f.cursors")" = 1 ] || p="$p
control (c): a query without _SYSTEMD_UNIT and _UID does not return the forged entry, so the exclusion proves nothing"
else
    echo "jo-run: control (c) dropped: root cannot write CUSTODIO_* fields here"
fi
judge journal-ops-queries "$p"

# TOTAL and the state directory after the step are those before it
snapshot_state > "$JO/end.state"
p=$(ops_state_problems "the state directory after the step" "$JO/start.state" "$JO/end.state")
[ "$(agent_lines)" = "$total_before" ] || p="$p
the request count of the earlier agent changed: $total_before before, $(agent_lines) after"
if [ -n "$p" ]; then problems="$problems
end:
$p"; fi
[ -z "$problems" ] || fail "journal-ops cases:$problems"
echo "jo-run: passed"
