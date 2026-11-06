#!/usr/bin/env bash
# Root side of the journal-kind-* cases (F144, acceptance 11 of SPEC.md: the queries of docs/audit.md work). Needs WORK, MODULE and E2E_TPM. The queries are the document's own
# (journalkind.py extract: only the service uid, the kind and the owner uid are replaced), run against the real journal after a cursor taken at the start; the entries the step caused
# are known to this script (written as the expectation files), and journalkind.py compares them with what each query returns.
# What the step does, in the order of the journal:
#   alice (journalkind-user.sh, polkit approved) imports jk-a and jk-b (kind tpm in swtpm and lacking, encrypted-host in none), signs once with jk-a approved and once denied;
#   entries with the fields of the service's are written by root and by alice (journald takes them from anyone): the documented queries name the unit and the service user, so none is returned;
#   old-format key files (no record magic) are placed in the state directory for alice and bob (owner = the service user, mode 0600, areas 0700) and the service is restarted: it purges them
#   at start-up and leaves one entry per key; the files are gone after;
#   key_lost: the record of jk-b is damaged (its last byte flipped; the original kept and put back) and alice signs with it; temporarily_unavailable: the TPM of the service is a path that
#   does not exist (swtpm, lacking; tf_point) or the credential service socket is stopped (none) and alice signs with jk-a; both injections are undone, and both keys sign again.
#   journal-kind-import   the kind query for each of the three kinds: the kind of the mode returns exactly jk-a and jk-b, the others nothing
#   journal-kind-purge    the purge query returns exactly one entry per placed key, outcome purged, no caller, and the files are gone
#   journal-kind-owner    the owner query for alice's uid and for bob's returns exactly their own, none of the other's
#   journal-kind-key-lost / -temporarily-unavailable   the cause query returns exactly the one failed signature, outcome signing_failed, the kind of the key; the approved and the denied
#                         signatures are in the window and not returned; the injection is undone and the key signs
# Every query must also return nothing from before the cursor and no forged entry (a forged entry of each writer is in the window, checked). Placement: guest.sh runs this after the tpmslots
# step and before the upgrade. The service stays active with the TPM of the run, the keys are deleted, the old files and bob's area are gone.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/journalkind-cases.sh
source "$here/journalkind-cases.sh"
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
# shellcheck source=e2e/tpm-lib.sh
source "$here/tpm-lib.sh"
# shellcheck source=e2e/tpmfail-lib.sh
source "$here/tpmfail-lib.sh"
mode=${E2E_TPM:-swtpm}
if [ "$mode" = none ]; then kind=encrypted-host; else kind=tpm; fi
for tool in journalctl openssl python3 busctl; do command -v "$tool" > /dev/null || fail "$tool is not installed"; done
JK=$WORK/journalkind
rm -rf "${JK:?}"
mkdir -p "$JK/in"
tk_make "$JK" journalkind
rm -f "${JK:?}"/*.crt
fx=$(fixture_problems "$JK/rsa.p12" rsa)
[ -z "$fx" ] || fail "the fixture is not what the cases need: $fx"
chmod a+r "$JK"/*.p12
chmod 1777 "$JK"
jk() { python3 -I "$here/journalkind.py" "$@"; }
t0=$SECONDS
lap() { echo "journalkind: $1 done at +$((SECONDS - t0)) s"; }
doc=/e2e-docs/audit.md
[ -f "$doc" ] || doc=$here/../docs/audit.md

service_uid=$(id -u custodio)
alice_uid=$(id -u alice)
id bob > /dev/null 2>&1 || useradd -m -s /bin/bash bob
bob_uid=$(id -u bob)
state=$(readlink -f /var/lib/custodio)
alice() { timeout 600 su -l alice -c "WORK=$WORK JK_KIND=$kind JK_UIDS='$alice_uid $bob_uid' bash /e2e/journalkind-user.sh $*" > "$JK/alice-$1.out" 2>&1 || { cat "$JK/alice-$1.out" >&2; fail "alice's session ($*) failed"; }; }
cursor() { journalctl --sync; journalctl -n1 -o json --no-pager | python3 -I -c 'import json,sys; print(json.loads(sys.stdin.readline())["__CURSOR"])'; }
SECRETS=(--secret e2e-password --secret KEY-SENTINEL --secret CERT-SENTINEL)

# the queries, as the document gives them
jk extract "$doc" "$service_uid" "$alice_uid" "$bob_uid" tpm encrypted-tpm encrypted-host > "$JK/queries.tsv" || fail "docs/audit.md lacks a query this step needs"

busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 org.freedesktop.DBus.Peer Ping > /dev/null 2>&1 || fail "the service does not answer a Ping"
c0=$(cursor)
journalctl _SYSTEMD_UNIT=custodio.service -o json --no-pager > "$JK/pre.json"
[ -s "$JK/pre.json" ] || fail "the journal holds no entry of the service before the cursor"

alice setup
lap setup
[ "$(cat "$JK/sign-ok.out")" = ok ] || fail "the approved signature gave: $(cat "$JK/sign-ok.out")"
grep -q '^error .*PolkitDenied' "$JK/sign-denied.out" || fail "the denied signature gave: $(cat "$JK/sign-denied.out")"

# forged entries, by root and by alice
forge_root() {
    local k u c
    for k in tpm encrypted-tpm encrypted-host; do
        python3 -I "$here/jo-forge.py" MESSAGE_ID=4c7163ce45d0b9faf8e7c38d098bdb22 CUSTODIO_OPERATION=import CUSTODIO_OUTCOME=stored CUSTODIO_KEY_ID=jk-forged-root "CUSTODIO_STORAGE_KIND=$k" \
            PRIORITY=6 SYSLOG_IDENTIFIER=custodiod "MESSAGE=forged by root"
    done
    for u in $alice_uid $bob_uid; do
        python3 -I "$here/jo-forge.py" MESSAGE_ID=8e1f5a6c0b3d4972a4c6d58f31b7e902 CUSTODIO_OPERATION=purge CUSTODIO_OUTCOME=purged CUSTODIO_KEY_ID=jk-forged-root "CUSTODIO_OWNER_UID=$u" \
            PRIORITY=4 SYSLOG_IDENTIFIER=custodiod "MESSAGE=forged by root"
    done
    for c in key_lost temporarily_unavailable; do
        python3 -I "$here/jo-forge.py" MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401 CUSTODIO_OPERATION=sign CUSTODIO_OUTCOME=signing_failed CUSTODIO_KEY_ID=jk-forged-root "CUSTODIO_STORAGE_KIND=$kind" \
            "CUSTODIO_CAUSE=$c" PRIORITY=3 SYSLOG_IDENTIFIER=custodiod "MESSAGE=forged by root"
    done
}
forge_root
alice forge
lap forge

# the purge: old-format files for alice and bob, then a restart; the service purges before it takes its bus name
owner_ids=$(stat -c '%u:%g' "${state:?}/$alice_uid")
old_files=''
place() { # UID ID CERT(yes|no)
    local area=$state/$1
    if [ ! -d "$area" ]; then
        mkdir "$area"
        chmod 0700 "$area"
        chown "$owner_ids" "$area"
    fi
    printf '\x30\x82\x01\x22KEY-SENTINEL-%s-d41f' "$2" > "$area/$2"
    old_files="$old_files $area/$2"
    if [ "$3" = yes ]; then
        printf '\x30\x82\x02\x10CERT-SENTINEL-%s-9b27' "$2" > "$area/$2-cert"
        old_files="$old_files $area/$2-cert"
    fi
    chmod 0600 "$area/$2"*
    chown "$owner_ids" "$area/$2"*
}
place "$alice_uid" jk-old-a1 yes
place "$alice_uid" jk-old-a2 no
place "$bob_uid" jk-old-b1 yes
place "$bob_uid" jk-old-b2 no
old=$(systemctl show -p MainPID --value custodio)
systemctl restart custodio
tf_wait_ready "$old"
lap purge
purge_left=''
for f in $old_files; do [ ! -e "$f" ] || purge_left="$purge_left $f"; done
rmdir "${state:?}/${bob_uid:?}" 2> /dev/null || true

# key_lost: a damaged record
rec=$state/$alice_uid/jk-b
[ -f "$rec" ] || fail "the record of jk-b is not at $rec"
cp -p "$rec" "$JK/jk-b.orig"
python3 -I - "$rec" << 'PY'
import sys
b = bytearray(open(sys.argv[1], "rb").read())
b[-1] ^= 0xFF
open(sys.argv[1], "wb").write(b)
PY
alice sign lost jk-b
cp -p "$JK/jk-b.orig" "$rec"
lap key-lost

# temporarily_unavailable: the TPM is a path that does not exist, or the credential service socket is stopped
if [ "$mode" = none ]; then tf_credentials_down; else tf_point "$TF_MISSING"; fi
alice sign temp jk-a
if [ "$mode" = none ]; then tf_credentials_up; else tf_point "$TPM_SOCK"; fi
alice sign after jk-a jk-b
lap temporarily-unavailable
alice delete jk-a jk-b
lap delete

# the queries, as jobs, over the window after the cursor
journalctl --sync
journalctl --after-cursor="$c0" -o json --no-pager > "$JK/window.json"
pids=()
while IFS=$'\t' read -r name args _; do
    # shellcheck disable=SC2086 # the arguments are words
    journalctl $args --after-cursor="$c0" -o json --no-pager > "$JK/q-${name//:/-}.json" 2> "$JK/q-${name//:/-}.err" &
    pids+=($!)
done < "$JK/queries.tsv"
for p in "${pids[@]}"; do wait "$p" || fail "a journalctl query failed"; done
for f in "$JK"/q-*.json; do echo "journalkind: $(basename "$f" .json): $(wc -l < "$f") entries"; done

x() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$@"; }
FORGED=(--forged jk-forged-root --forged jk-forged-alice)
mkdir -p "$JK/expect"
for k in tpm encrypted-tpm encrypted-host; do
    if [ "$k" = "$kind" ]; then { x jk-a import stored "$k" - -; x jk-b import stored "$k" - -; } > "$JK/expect/kind-$k"; else : > "$JK/expect/kind-$k"; fi
done
{ x jk-old-a1 purge purged - - "$alice_uid"; x jk-old-a2 purge purged - - "$alice_uid"; x jk-old-b1 purge purged - - "$bob_uid"; x jk-old-b2 purge purged - - "$bob_uid"; } > "$JK/expect/purge"
{ x jk-old-a1 purge purged - - "$alice_uid"; x jk-old-a2 purge purged - - "$alice_uid"; } > "$JK/expect/owner-$alice_uid"
{ x jk-old-b1 purge purged - - "$bob_uid"; x jk-old-b2 purge purged - - "$bob_uid"; } > "$JK/expect/owner-$bob_uid"
x jk-b sign signing_failed "$kind" key_lost - > "$JK/expect/key-lost"
x jk-a sign signing_failed "$kind" temporarily_unavailable - > "$JK/expect/temporarily-unavailable"
judge_q() { # NAME EXPECT-FILE [OPTIONS]: the problems of one query result against the expectation
    jk check "$JK/q-${1//:/-}.json" "$JK/pre.json" "$JK/window.json" "$service_uid" "$2" "${FORGED[@]}" "${@:3}" "${SECRETS[@]}" | sed "s/^/$1: /"
}
problems=''
judge() { # CASE PROBLEMS
    local p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$1"; else problems="$problems
$1:
$p"; fi
}
present=(--present jk-a:signed --present jk-a:denied)
judge journal-kind-import "$(for k in tpm encrypted-tpm encrypted-host; do judge_q "kind:$k" "$JK/expect/kind-$k"; done)"
judge journal-kind-purge "$(judge_q purge "$JK/expect/purge")
$([ -z "$purge_left" ] || echo "old-format files are still there:$purge_left")"
judge journal-kind-owner "$(judge_q "owner:$alice_uid" "$JK/expect/owner-$alice_uid"; judge_q "owner:$bob_uid" "$JK/expect/owner-$bob_uid")"
judge journal-kind-key-lost "$(judge_q key-lost "$JK/expect/key-lost" "${present[@]}")
$(grep -q '^error .*KeyLost' "$JK/sign-lost-jk-b.out" || echo "the damaged key did not give KeyLost: $(cat "$JK/sign-lost-jk-b.out" 2> /dev/null)")
$([ "$(cat "$JK/sign-after-jk-b.out")" = ok ] || echo "the restored key does not sign: $(cat "$JK/sign-after-jk-b.out" 2> /dev/null)")"
judge journal-kind-temporarily-unavailable "$(judge_q temporarily-unavailable "$JK/expect/temporarily-unavailable" "${present[@]}")
$(grep -q '^error .*TemporarilyUnavailable' "$JK/sign-temp-jk-a.out" || echo "the unavailable key did not give TemporarilyUnavailable: $(cat "$JK/sign-temp-jk-a.out" 2> /dev/null)")
$([ "$(cat "$JK/sign-after-jk-a.out")" = ok ] || echo "the key does not sign after the injection: $(cat "$JK/sign-after-jk-a.out" 2> /dev/null)")"
systemctl is-active --quiet custodio || problems="$problems
end:
custodio.service is not active after the step"
[ -z "$(printf '%s' "$problems" | tr -d '[:space:]')" ] || fail "journalkind cases:$problems"
echo "journalkind-run: passed"
