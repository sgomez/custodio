#!/usr/bin/env bash
# Root side of the appid-* cases (F95, acceptance 9 of SPEC.md). Needs WORK and MODULE. Alice, in sessions of her own with a test agent (appid-user.sh), calls
# sign, import, replace certificate and delete from processes in scopes of her user manager, named as flatpak names them (the shipped unit, the real journal,
# the app-id source F67 decided on: the caller's scope in user@<uid>.service/app.slice), and from hostile ones; this script makes the fixtures, brings the
# number of children of app.slice over the cap for a while, and judges the journal between two marker entries with appid.py (e2e/appid-ledger.txt is the plan).
# Placement: guest.sh runs it after journal-ops and before the upgrade. Every key it imports it deletes, and the scopes it makes it removes, so the state
# directory and the request count of the earlier agent (TOTAL) after the step are those before it (judged here).
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
bash "$here/appid-selftest.sh" || fail "the appid self-test failed"

UNIT=custodio.service
AI=$WORK/appid
rm -rf "$AI"
mkdir "$AI"
chmod 1777 "$AI"
service_uid=$(id -u custodio)
alice_uid=$(id -u alice)
alice_gid=$(id -g alice)
ai() { python3 -I "$here/appid.py" "$@"; }
jo() { python3 -I "$here/jo.py" "$@"; }

# What the judgements read from the repository: the cap of the reader and the bound of the lookup. run.sh mounts both files.
doc=/e2e-docs/audit.md
src=/e2e-src/app_id_source.rs
[ -f "$doc" ] || doc=$here/../docs/audit.md
[ -f "$src" ] || src=$here/../crates/custodiod/src/app_id_source.rs
cap=$(ai constant --file "$src" --name MAX_CHILDREN) || fail "cannot read MAX_CHILDREN of the reader"
echo "appid-run: the reader walks at most $cap children of app.slice; the lookup bound is $(ai deadline --doc "$doc") s"

# What the kernel allows alice in her app.slice, recorded (contract F95): children with 255 and 256 byte names, a symlink and a FIFO. Her session needs
# the user manager, so this runs after the first session below.
probe_tree() {
    local sl=$1 d long out
    d="$sl/appid-probe-tree"
    runuser -u alice -- mkdir "$d" || fail "alice cannot make a child of her app.slice"
    try() { runuser -u alice -- "$@" 2>&1 | sed 's/.*: //' || true; } # what the kernel says: the end of the message, or nothing when it worked
    out="symlink as cgroup.procs: $(try ln -s /etc/passwd "$d/cgroup.procs")"
    out="$out; fifo as cgroup.procs: $(try mkfifo "$d/cgroup.procs")"
    out="$out; removing cgroup.procs: $(try rm -f "$d/cgroup.procs")"
    out="$out; symlink child: $(try ln -s /etc "$sl/appid-probe-link")"
    out="$out; fifo child: $(try mkfifo "$sl/appid-probe-fifo")"
    long=$(python3 -I -c 'print("appid-probe-" + "x" * 244)')
    if runuser -u alice -- mkdir "$sl/$long" 2> /dev/null; then out="$out; mkdir of a 256-byte name: accepted"; else out="$out; mkdir of a 256-byte name: refused"; fi
    rmdir "$d" "$sl/$long" 2> /dev/null || true
    echo "appid-run: what alice can make in app.slice: $out"
}

lingered=no
[ ! -e /var/lib/systemd/linger/alice ] || lingered=yes
alice_session() { # PHASE: a session of class user (see appid-user.sh) with the phase's calls
    XDG_SESSION_CLASS=user timeout 900 su -l alice -c "WORK=$WORK MODULE=$MODULE bash /e2e/appid-user.sh $1" > "$AI/alice-$1.out" 2>&1 \
        || { cat "$AI/alice-$1.out" >&2; fail "alice's session ($1) failed"; }
}
sl=''
cleanup_all() {
    if [ -n "$sl" ] && [ -d "$sl" ]; then
        ai cap-teardown --slice "$sl" --names "$AI/names.tsv" 2> /dev/null || true
        ai cleanup --slice "$sl" --names "$AI/names.tsv" 2> /dev/null || true
    fi
    runuser -u alice -- env "XDG_RUNTIME_DIR=/run/user/$alice_uid" systemctl --user stop appid-anchor > /dev/null 2>&1 || true
    [ "$lingered" = yes ] || loginctl disable-linger alice > /dev/null 2>&1 || true
}
trap cleanup_all EXIT

# Fixtures: a key with two certificates (the second replaces the first), the data, the public key of the certificate, the scope names.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$AI/k.key" 2> /dev/null
openssl req -new -x509 -key "$AI/k.key" -subj "/CN=f95-old" -days 30 -out "$AI/cert1.pem"
openssl req -new -x509 -key "$AI/k.key" -subj "/CN=f95-new" -days 30 -outform DER -out "$AI/cert2.der"
openssl pkcs12 -export -inkey "$AI/k.key" -in "$AI/cert1.pem" -name f95 -passout pass:e2e-password -out "$AI/k.p12"
openssl x509 -in "$AI/cert1.pem" -pubkey -noout > "$AI/pub.pem"
rm -f "$AI/k.key"
head -c 2000 /dev/urandom > "$AI/data.bin" # over 1024 bytes, so that pkcs11-tool does not retry a denied one-shot C_Sign as a second signature
ai names --out "$AI/names.tsv" || fail "cannot make the scope names"
chmod 644 "$AI"/*

loginctl enable-linger alice # her user manager and app.slice stay between the sessions
alice_session prep
for _ in $(seq 50); do [ -d "/run/user/$alice_uid" ] && break; sleep 0.2; done
cg=$(systemctl show -p ControlGroup --value "$UNIT")
sl=$(ai slice --mount /sys/fs/cgroup --control-group "$cg" --uid "$alice_uid") || fail "cannot find the app.slice of alice's user manager"
[ -d "$sl" ] || fail "alice's app.slice is not at $sl: the tree of the reader is not where this step looks"
probe_tree "$sl"
[ -z "$(find "$sl" -mindepth 1 -maxdepth 1 \( -name 'appid-fill-*' -o -name '*CapCaller*' -o -name 'appid-probe*' \) | head -n 1)" ] || fail "children of an earlier run are in app.slice"

agent_lines() { if [ -f "$WORK/agent/requests" ]; then wc -l < "$WORK/agent/requests"; else echo 0; fi; }
total_before=$(agent_lines)
snapshot_state > "$AI/start.state" || fail "cannot snapshot the state directory"
since=$(date +%s)
mark() { printf '%s\n' "$1" | systemd-cat -t custodio-e2e-appid || fail "cannot write the marker $1"; }
mark appid-start

alice_session main
# The cap: root brings the children of app.slice over MAX_CHILDREN and picks two callers by their place in the walk; nothing is made or removed in app.slice
# between the check and the calls but the scope of the systemd-run that starts each caller (the margin of cap_problems). Gone again before the next phase.
ai cap-setup --slice "$sl" --cap "$cap" --uid "$alice_uid" --gid "$alice_gid" --names "$AI/names.tsv" || fail "cannot bring app.slice over the cap"
chmod 644 "$AI/names.tsv"
ai cap-check --slice "$sl" --cap "$cap" --names "$AI/names.tsv" || fail "the cap callers are not where the cases need them"
alice_session cap
ai cap-check --slice "$sl" --cap "$cap" --names "$AI/names.tsv" || fail "the cap callers were not where the cases need them after the calls"
ai cap-teardown --slice "$sl" --names "$AI/names.tsv" || fail "the children that brought app.slice over the cap are still there"
alice_session end
mark appid-end
ai cleanup --slice "$sl" --names "$AI/names.tsv" || fail "scopes of the step are still in app.slice"

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
start_cursor=$(get_window "$since" appid-start appid-end "$AI/w") || fail "the markers of alice's calls are not in the journal once each"
journalctl --since "@$since" -o export --no-pager > "$AI/all.export"

problems=''
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p=$2
    p=$(printf '%s\n' "$p" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
ai merge --plan "$here/appid-ledger.txt" --names "$AI/names.tsv" --observed "$AI/observed" --uid "$alice_uid" --out "$AI/ledger" \
    || fail "alice's calls are not the calls of e2e/appid-ledger.txt"
ent() { ai entries --case "$1" --window "$AI/w.window" --ledger "$AI/ledger" --unit "$UNIT" --service-uid "$service_uid" 2>&1 || true; }
for c in appid-flatpak appid-flatpak-max appid-cap appid-operations appid-none; do judge "$c" "$(ent "$c")"; done
# the hostile callers: the entries, and no text of their names anywhere in the journal (every field of every unit, no exclusion)
p=$(ent appid-hostile)
p="$p
$(ai sweep --export "$AI/all.export" --names "$AI/names.tsv" 2>&1 || true)"
judge appid-hostile "$p"
judge appid-outcome "$(ai outcome --window "$AI/w.window" --ledger "$AI/ledger" --unit "$UNIT" --service-uid "$service_uid" --dir "$AI" --pub "$AI/pub.pem" --data "$AI/data.bin" 2>&1 || true)"
judge appid-bound "$(ai bound --ledger "$AI/ledger" --doc "$doc" 2>&1 || true)"

# every query docs/audit.md documents, with only its placeholders replaced (the app-id one for each id the ledger has and for one no call used)
p=$(ai extract --doc "$doc" --uid "$alice_uid" --service-uid "$service_uid" --key ai-key --ledger "$AI/ledger" --out "$AI/queries.tsv" 2>&1 || true)
if [ -z "$p" ]; then
    mkdir "$AI/q"
    while IFS=$'\t' read -r index qargs _rest; do
        # shellcheck disable=SC2086 # the arguments of a query are words
        journalctl --after-cursor="$start_cursor" $qargs -o json --no-pager > "$AI/q/q-$index.json" || fail "query $index ($qargs) failed"
    done < "$AI/queries.tsv"
    p=$(ai queries --queries "$AI/queries.tsv" --results "$AI/q" --cursors "$AI/w.cursors" --ledger "$AI/ledger" --window "$AI/w.window" --unit "$UNIT" \
        --service-uid "$service_uid" 2>&1 || true)
fi
judge appid-queries "$p"

# the state directory and TOTAL after the step are those before it
snapshot_state > "$AI/end.state"
p=$(ops_state_problems "the state directory after the step" "$AI/start.state" "$AI/end.state")
[ "$(agent_lines)" = "$total_before" ] || p="$p
the request count of the earlier agent changed: $total_before before, $(agent_lines) after"
if [ -n "$p" ]; then problems="$problems
end:
$p"; fi
[ -z "$problems" ] || fail "appid cases:$problems"
echo "appid-run: passed"
