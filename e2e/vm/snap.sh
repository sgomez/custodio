#!/usr/bin/env bash
# Root side of the snap-* cases (F179, acceptances 17 and 18 of SPEC.md). Needs WORK, E2E_VM=1 and E2E_TPM; the VM full mode runs them, the lacking mode reports them
# skipped (the snap route does not depend on the TPM kind; SPEC puts the group in full). The Firefox snap was installed from stable by e2e/vm/run.sh (overlapping with
# the setup); this waits for the end of that install on a condition.
#   snap-record  snap-socket-dir  snap-list-keys  snap-sign-rsa  snap-sign-ec  snap-polkit-per-signature  snap-journal-label
#   snap-bus-denied  snap-refused-unconfined  snap-refused-root  snap-refused-other-snap  snap-unknown-methods
# The judges are e2e/vm/snap.py (snap-lib.sh); the evidence is collected here and by snap-user.sh (alice's session), in $WORK/snap.
# A label that is not snap.firefox.* in enforce mode, an unreachable socket and a bus call that goes through FAIL the run (acceptance 18); they are never skipped.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/../report.sh"
SNAP_CASES="snap-record snap-socket-dir snap-list-keys snap-sign-rsa snap-sign-ec snap-polkit-per-signature snap-journal-label snap-bus-denied snap-refused-unconfined snap-refused-root snap-refused-other-snap snap-unknown-methods"
mode=${E2E_TPM:-swtpm}
if [ -z "${E2E_VM:-}" ] || [ "$mode" != swtpm ]; then
    for c in $SNAP_CASES; do case_skip "$c" "E2E_TPM=$mode: the snap group runs in the full VM mode; the route does not depend on the TPM kind"; done
    exit 0
fi
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/../tpmkind-lib.sh"
# shellcheck source=e2e/vm/snap-lib.sh
source "$here/snap-lib.sh"
for tool in openssl python3 journalctl apparmor_parser aa-exec snap runuser; do command -v "$tool" > /dev/null || fail "$tool is not installed"; done

SN=$WORK/snap
rm -rf "${SN:?}"
mkdir -p "$SN"
chmod 1777 "$SN"
tk_make "$SN" snap
chmod 644 "$SN"/*.p12
id bob > /dev/null 2>&1 || useradd -m -s /bin/bash bob
snap_extra_cleanup() {
    # best effort: the keys of the group are deleted whatever happened (a failed run must not leave them for the groups after it)
    local u
    for u in alice bob; do
        timeout 120 su -l "$u" -c "WORK=$WORK bash /e2e/vm/snap-user.sh delete" > /dev/null 2>&1 || true
    done
}
snap_install_trap
user_phase() { # USER PHASE
    timeout 600 su -l "$1" -c "WORK=$WORK bash /e2e/vm/snap-user.sh $2" > "$SN/user-$1-$2.out" 2>&1 || { cat "$SN/user-$1-$2.out" >&2; fail "the $2 phase of $1 failed"; }
}
cursor() { journalctl --sync; journalctl -n1 --show-cursor 2> /dev/null | sed -n 's/^-- cursor: //p'; }
custodio_log() { journalctl --sync; journalctl --after-cursor="$1" _SYSTEMD_UNIT=custodio.service -o cat --no-pager; }
signs() { journalctl --sync; journalctl _SYSTEMD_UNIT=custodio.service CUSTODIO_OPERATION=sign -o cat --no-pager | wc -l; }

snap_wait_install 900 || fail "the Firefox snap is not installed"
echo "snap: installed: $(snap list firefox | tail -n 1)"
# the snap's own AppArmor profile must be loaded and in enforce mode (acceptance 18: a profile that is not enforcing fails the run)
aa-status 2> /dev/null | grep -q 'snap.firefox.firefox' || fail "the profile snap.firefox.firefox is not loaded: snapd's rules changed; a person must look"
id -u alice > "$SN/alice.uid"

# keys: another account's first, so that "only hers" is not vacuous
user_phase bob import
user_phase alice import
user_phase alice place
printf 'sn-alice-rsa\nsn-alice-ec\n' > "$SN/keys.alice"
printf 'sn-bob-rsa\nsn-bob-ec\n' > "$SN/keys.foreign"

# the group's own signatures, listing and certificates
: > "$SN/agent-alice/subjects" 2> /dev/null || true
c0=$(cursor)
user_phase alice sign
custodio_log "$c0" > /dev/null
journalctl --sync
journalctl --after-cursor="$c0" _SYSTEMD_UNIT=custodio.service CUSTODIO_OPERATION=sign -o json --no-pager > "$SN/journal.json"
cp "$SN/agent-alice/subjects" "$SN/subjects"
stat -c '%F|%U|%G|%a|%n' /run/snap.firefox > "$SN/dir.stat" 2>&1 || echo "missing|||| /run/snap.firefox" > "$SN/dir.stat"
stat -c '%F|%U|%G|%a|%n' /run/snap.firefox/custodio.sock > "$SN/sock.stat" 2>&1 || echo "missing||||/run/snap.firefox/custodio.sock" > "$SN/sock.stat"

# the record: versions, and the label as the service journals it
label=$(sed -n 's/.*"CUSTODIO_PEER_LABEL":"\([^"]*\)".*/\1/p' "$SN/journal.json" | head -n 1)
rev=$(snap list firefox | awk 'NR==2 {print $3}')
{
    echo "snap_revision=${rev:-unknown}"
    echo "snap_base=$(sed -n 's/^base: *//p' /snap/firefox/current/meta/snap.yaml | head -n 1)"
    echo "snapd_deb=$(dpkg-query -W -f='${Version}' snapd 2> /dev/null)"
    echo "snapd_snap=$(snap list snapd 2> /dev/null | awk 'NR==2 {print $2}')"
    echo "apparmor=$(apparmor_parser --version 2> /dev/null | sed -n '1s/.*version *//p')"
    echo "dbus_daemon=$(dbus-daemon --version 2> /dev/null | head -n 1 | awk '{print $NF}')"
    echo "peer_label=${label:-unknown}"
} > "$SN/record"
sed -i 's/=$/=unknown/' "$SN/record"
snap list firefox > "$SN/snap-list.out"
sha=$(python3 -I -c "import base64,hashlib,sys; print(base64.urlsafe_b64encode(hashlib.sha3_384(open(sys.argv[1],'rb').read()).digest()).decode().rstrip('='))" "/var/lib/snapd/snaps/firefox_$rev.snap")
snap known snap-revision "snap-sha3-384=$sha" > "$SN/snap-known.out" 2>&1 || true
while IFS= read -r line; do echo "E2E-SNAP-RECORD $line"; done < "$SN/record"

# the bus call from the confinement, and the same call outside; the denial is AppArmor's (its audit record)
c1=$(cursor)
user_phase alice bus
for _ in $(seq 20); do
    journalctl --sync
    { journalctl --after-cursor="$c1" -k --no-pager; journalctl --after-cursor="$c1" _TRANSPORT=audit --no-pager; } 2> /dev/null | grep 'apparmor="DENIED"' > "$SN/audit.log" || true
    [ -s "$SN/audit.log" ] && break
    sleep 0.5
done
[ -s "$SN/audit.log" ] || : > "$SN/audit.log"

# refused at the socket: alice outside the snap, then root outside the snap
refused() { # PREFIX COMMAND...: runs the command, keeps its output and status, the refusal lines of the service and the sign counts
    local pre=$1 cur rc=0
    shift
    cur=$(cursor)
    signs > "$SN/$pre.signs.before"
    "$@" > "$SN/$pre.out" 2> "$SN/$pre.err" || rc=$?
    echo "$rc" > "$SN/$pre.rc"
    sed -i '/^pid/d' "$SN/$pre.out"
    custodio_log "$cur" | grep 'peer refused' > "$SN/$pre.refusal.log" || : > "$SN/$pre.refusal.log"
    signs > "$SN/$pre.signs.after"
    grep '^token' "$SN/$pre.out" > "$SN/$pre.out.tokens" || true
    mv "$SN/$pre.out.tokens" "$SN/$pre.out"
}
MODC=/home/alice/snap/firefox/common/libcustodio_pkcs11.so
CLC=/home/alice/snap/firefox/common/snap-client.py
refused unconf runuser -u alice -- env SNAP_INSTANCE_NAME=firefox python3 -I "$CLC" list "$MODC"
refused root env SNAP_INSTANCE_NAME=firefox python3 -I "$CLC" list "$MODC"
# another snap's label: the test profile, loaded for this case only (the trap unloads it). Under alice, aa-exec gave a stacked label (the service said
# `peer label is stacked`), so root enters the profile; the child is root, which is why the judge requires the another-snap reason and not any refusal
snap_profile_load || fail "the test profile could not be loaded"
aa-exec -p snap.e2e-other.app -- cat /proc/self/attr/current > "$SN/other.label" 2>&1 || echo "no label: $(cat "$SN/other.label")" > "$SN/other.label"
aa-exec -p snap.e2e-other.app -- python3 -I -c "import socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/snap.firefox/custodio.sock'); print('connected')" > "$SN/other.connect" 2>&1 || true
sed -i 's/ *$//' "$SN/other.label"
if [ "$(tail -n 1 "$SN/other.connect")" = connected ]; then echo connected > "$SN/other.connect"; else head -c 200 "$SN/other.connect" > "$SN/other.connect.t"; mv "$SN/other.connect.t" "$SN/other.connect"; fi
refused other aa-exec -p snap.e2e-other.app -- env SNAP_INSTANCE_NAME=firefox python3 -I "$CLC" list "$MODC"
snap_profile_unload || fail "the test profile could not be unloaded"

# unknown methods: the key list, the state, the audit entries and the agent's requests are the same before and after
um_state() { { find /var/lib/custodio/ -printf '%y %p %m %s\n' | sort; } 2> /dev/null; }
um_entries() { # the audit entries of operations other than a listing
    journalctl --sync
    journalctl _SYSTEMD_UNIT=custodio.service -o json --no-pager | grep '"CUSTODIO_OPERATION"' | grep -vc '"CUSTODIO_OPERATION":"list' || true
}
um_keys() { runuser -u alice -- env SNAP_INSTANCE_NAME=firefox python3 -I "$CLC" list "$MODC" | grep '^token' || true; }
um_state > "$SN/um.state.before"; um_keys > "$SN/um.keys.before"
um_entries > "$SN/um.journal.before"
wc -l < "$SN/agent-alice/requests" > "$SN/um.agent.before"
user_phase alice unknown
um_state > "$SN/um.state.after"; um_keys > "$SN/um.keys.after"
um_entries > "$SN/um.journal.after"
wc -l < "$SN/agent-alice/requests" > "$SN/um.agent.after"

problems=''
for c in $SNAP_CASES; do
    p=$(snap_problems "$c" "$SN")
    if [ -z "$p" ]; then case_run "$c"; else problems="$problems
$c:
$p"; fi
done
if [ -n "$problems" ]; then
    { for f in sign-rsa.err sign-rsa.out unconf.err other.err agent-alice/agent.log; do echo "--- $f"; head -c 600 "$SN/$f" 2>&1; done
      echo "--- service journal"; journalctl -u custodio --no-pager -n 15 -o cat | cut -c1-200; echo "--- polkit"; journalctl -u polkit --no-pager -n 15 -o cat | cut -c1-200; } >&2
fi
[ -z "$problems" ] || fail "snap cases:$problems"
echo "snap: passed"
