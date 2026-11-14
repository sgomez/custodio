#!/usr/bin/env bash
# F179: container-free checks of the snap-* cases (e2e/vm/snap.py, snap-lib.sh, snap-client.py): every judge over fixtures of the guest's evidence with a negative
# control for each fact (the evidence of a VM run is what they judge), the unload of the test profile with a stub apparmor_parser (a failing judge, a signal, a clean
# end), the D-Bus words of the client against a fake peer, and the report of the cases in the mode that skips them. NOT checked here: a real guest.
# shellcheck disable=SC2015,SC2016 # A && B || bad is the check; single quotes hold text for the stubs
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-vm-snap: $*" >&2; fail=1; }
E=$ROOT/e2e
# shellcheck source=e2e/vm/snap-lib.sh
source "$E/vm/snap-lib.sh"
CASES="snap-record snap-socket-dir snap-list-keys snap-sign-rsa snap-sign-ec snap-polkit-per-signature snap-journal-label snap-bus-denied snap-refused-unconfined snap-refused-root snap-refused-other-snap snap-unknown-methods"
LABEL='snap.firefox.firefox (enforce)'

# ---- fixtures: a complete good evidence directory
g=$tmp/good
mkdir -p "$g"
cd "$g"
for k in rsa ec; do
    if [ $k = rsa ]; then openssl req -x509 -newkey rsa:2048 -nodes -keyout $k.key -subj /CN=t -days 2 -outform der -out sign-$k.crt 2> /dev/null
    else openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $k.key -subj /CN=t -days 2 -outform der -out sign-$k.crt 2> /dev/null; fi
    echo $k > sign-$k.kind
    printf 'message %s' $k | openssl dgst -sha256 -binary > sign-$k.digest
done
openssl pkeyutl -sign -inkey rsa.key -in sign-rsa.digest -out sign-rsa.sig -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha256 -pkeyopt rsa_mgf1_md:sha256 -pkeyopt rsa_pss_saltlen:32
openssl pkeyutl -sign -inkey ec.key -in sign-ec.digest -out ec.der -pkeyopt digest:sha256
python3 -I - << 'PY'
# DER r||s -> raw 64 bytes
d = open("ec.der", "rb").read()
i = 2
def take(i):
    n = d[i + 1]; v = d[i + 2:i + 2 + n]; return v.lstrip(b"\0").rjust(32, b"\0"), i + 2 + n
r, i = take(i); s, i = take(i)
open("sign-ec.sig", "wb").write(r + s)
PY
cp sign-rsa.crt sign-rsa2.crt; cp sign-rsa.kind sign-rsa2.kind; cp sign-rsa.digest sign-rsa2.digest
openssl pkeyutl -sign -inkey rsa.key -in sign-rsa2.digest -out sign-rsa2.sig -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha256 -pkeyopt rsa_mgf1_md:sha256 -pkeyopt rsa_pss_saltlen:32
rm -f rsa.key ec.key ec.der
n=0
for s in rsa ec rsa2; do n=$((n + 1)); echo $((4000 + n)) > sign-$s.pid; echo 0 > sign-$s.rc; done
cat > record << EOF2
snap_revision=9181
snap_base=core26
snapd_deb=2.77.1+ubuntu26.04.2
snapd_snap=2.78
apparmor=5.0.2
dbus_daemon=1.16.2
peer_label=$LABEL
EOF2
cat > snap-list.out << 'EOF2'
Name     Version  Rev   Tracking       Publisher  Notes
firefox  160.0-1  9181  latest/stable  mozilla**  -
EOF2
printf 'type: snap-revision\nauthority-id: canonical\nsnap-revision: 9181\ndeveloper-id: mozilla\n' > snap-known.out
echo 'directory|root|root|755|/run/snap.firefox' > dir.stat
echo 'socket|root|root|666|/run/snap.firefox/custodio.sock' > sock.stat
printf 'token\tsn-rsa\ntoken\tsn-ec\n' > list.out; echo 0 > list.rc
printf 'sn-rsa\nsn-ec\n' > keys.alice; printf 'bob-key\n' > keys.foreign
echo 1000 > alice.uid
printf 'com.rfirma.custodio.sign 4001 1000\ncom.rfirma.custodio.sign 4002 1000\ncom.rfirma.custodio.sign 4003 1000\n' > subjects
: > journal.json
for p in 4001 4002 4003; do
    printf '{"CUSTODIO_OPERATION":"sign","CUSTODIO_TRANSPORT":"socket","CUSTODIO_PEER_LABEL":"%s","CUSTODIO_PID":"%s"}\n' "$LABEL" "$p" >> journal.json
done
echo "error org.freedesktop.DBus.Error.AccessDenied: An AppArmor policy prevents this sender from sending this message" > bus-in.out
echo ok > bus-out.out
echo 'audit: type=1400 apparmor="DENIED" operation="dbus_method_call" profile="snap.firefox.firefox" name="com.rfirma.Custodio1"' > audit.log
for pre in unconf root other; do
    : > $pre.out; echo 1 > $pre.rc; echo 3 > $pre.signs.before; echo 3 > $pre.signs.after
done
echo "custodiod: peer refused: the peer's label is refused: peer is unconfined" > unconf.refusal.log
cp unconf.refusal.log root.refusal.log
echo "custodiod: peer refused: the peer's label is refused: peer is another snap" > other.refusal.log
echo 'snap.e2e-other.app (enforce)' > other.label; echo connected > other.connect
for m in ImportP12 DeleteKey ReplaceCertificate; do echo "error org.freedesktop.DBus.Error.UnknownMethod: no such method $m" > um-$m.out; done
for n in keys state journal agent; do echo "same-$n" > um.$n.before; echo "same-$n" > um.$n.after; done
cd "$ROOT"

judge_all() { local c; for c in $CASES; do snap_problems "$c" "$1"; done; }
p=$(judge_all "$g"); [ -z "$p" ] || bad "good evidence rejected: $p"
# ctl NAME CASE SHELL-TEXT: a copy of the good evidence changed by SHELL-TEXT (run in the copy), which the judge of CASE must reject; MSG (optional, env) must be in the answer
ctl() {
    local n=$1 c=$2 d=$tmp/c-$1 out
    cp -r "$g" "$d"
    (cd "$d" && bash -c "$3")
    out=$(snap_problems "$c" "$d")
    [ -n "$out" ] || { bad "control $n: the case $c accepts bad evidence"; return; }
    [ -z "${MSG:-}" ] || grep -qF -- "$MSG" <<< "$out" || bad "control $n: the answer lacks '$MSG': $out"
}
# record and the signed install
ctl rec-dangerous snap-record "sed -i 's/ -\$/ dangerous/' snap-list.out"
ctl rec-channel snap-record "sed -i 's|latest/stable|latest/beta|' snap-list.out"
ctl rec-tracking-none snap-record "sed -i 's|latest/stable|-|' snap-list.out"
ctl rec-publisher snap-record "sed -i 's|mozilla|evil|' snap-list.out"
ctl rec-no-assertion snap-record ': > snap-known.out'
ctl rec-assertion-other-rev snap-record "sed -i 's/snap-revision: 9181/snap-revision: 1/' snap-known.out"
for f in snap_revision snap_base snapd_deb snapd_snap apparmor dbus_daemon peer_label; do
    ctl "rec-no-$f" snap-record "sed -i '/^$f=/d' record"
    ctl "rec-unknown-$f" snap-record "sed -i 's/^$f=.*/$f=unknown/' record"
done
MSG='a person must look' ctl rec-label snap-record "sed -i 's/(enforce)/(complain)/' record"
# the socket directory
ctl dir-775 snap-socket-dir "echo 'directory|root|root|775|/run/snap.firefox' > dir.stat"
ctl dir-alice snap-socket-dir "echo 'directory|alice|root|755|/run/snap.firefox' > dir.stat"
ctl sock-file snap-socket-dir "echo 'regular file|root|root|644|/run/snap.firefox/custodio.sock' > sock.stat"
ctl sock-missing snap-socket-dir 'rm sock.stat'
ctl sock-name snap-socket-dir "echo 'socket|root|root|666|/run/snap.firefox/other.sock' > sock.stat"
# the keys
ctl keys-empty snap-list-keys ': > list.out'
ctl keys-missing snap-list-keys "sed -i '/sn-ec/d' list.out"
ctl keys-foreign snap-list-keys "printf 'token\tbob-key\n' >> list.out"
ctl keys-no-foreign snap-list-keys ': > keys.foreign'
MSG=custodio.sock ctl keys-unreachable snap-list-keys "echo 1 > list.rc; : > list.out"
# the signatures
ctl sig-flipped snap-sign-rsa "python3 -I -c \"d=bytearray(open('sign-rsa.sig','rb').read()); d[5]^=1; open('sign-rsa.sig','wb').write(d)\""
ctl sig-other-data snap-sign-rsa "printf other | openssl dgst -sha256 -binary > sign-rsa.digest"
ctl sig-ec-flipped snap-sign-ec "python3 -I -c \"d=bytearray(open('sign-ec.sig','rb').read()); d[5]^=1; open('sign-ec.sig','wb').write(d)\""
ctl sig-ec-other-data snap-sign-ec "printf other | openssl dgst -sha256 -binary > sign-ec.digest"
ctl sig-ec-swapped-cert snap-sign-ec 'cp sign-rsa.crt sign-ec.crt'
MSG='socket' ctl sig-rc snap-sign-rsa 'echo 1 > sign-rsa.rc'
# polkit
ctl pk-one-request snap-polkit-per-signature "sed -i '3d' subjects"
ctl pk-service-pid snap-polkit-per-signature "sed -i 's/4003/777/' subjects"
ctl pk-uid snap-polkit-per-signature "sed -i '1s/1000/0/' subjects"
ctl pk-journal-pid snap-polkit-per-signature "sed -i 's/4003/778/' journal.json"
# journal
for pair in 'unconfined:unconfined' 'complain:snap.firefox.firefox (complain)' 'other:snap.other.app (enforce)'; do
    ctl "jl-${pair%%:*}" snap-journal-label "sed -i 's/\"CUSTODIO_PEER_LABEL\":\"[^\"]*\"/\"CUSTODIO_PEER_LABEL\":\"${pair#*:}\"/' journal.json"
done
ctl jl-bus snap-journal-label "sed -i 's/\"socket\"/\"bus\"/' journal.json"
ctl jl-nolabel snap-journal-label "sed -i 's/\"CUSTODIO_PEER_LABEL\":\"[^\"]*\",//' journal.json"
# the bus
MSG='person must look' ctl bus-succeeded snap-bus-denied 'echo ok > bus-in.out'
ctl bus-no-audit snap-bus-denied ': > audit.log'
ctl bus-outside-fails snap-bus-denied "echo 'error org.freedesktop.DBus.Error.AccessDenied' > bus-out.out"
ctl bus-other-error snap-bus-denied "echo 'error org.freedesktop.DBus.Error.NoReply' > bus-in.out"
# refusals
for pre in unconf root other; do
    c=snap-refused-$([ $pre = unconf ] && echo unconfined || { [ $pre = root ] && echo root || echo other-snap; })
    ctl "$pre-listed" "$c" "printf 'token\tsn-rsa\n' > $pre.out"
    ctl "$pre-no-refusal" "$c" ": > $pre.refusal.log"
    ctl "$pre-new-sign" "$c" "echo 4 > $pre.signs.after"
    ctl "$pre-no-control" "$c" 'echo 1 > list.rc'
done
ctl other-wrong-reason snap-refused-other-snap "echo 'custodiod: peer refused: the peers label is refused: peer is unconfined' > other.refusal.log"
ctl other-vacuous snap-refused-other-snap "echo 'unconfined' > other.label"
ctl other-no-connect snap-refused-other-snap "echo 'denied' > other.connect"
# unknown methods
ctl um-success snap-unknown-methods "echo ok > um-ImportP12.out"
ctl um-polkit snap-unknown-methods "echo 'error org.freedesktop.DBus.Error.AccessDenied: polkit' > um-DeleteKey.out"
ctl um-state snap-unknown-methods 'echo changed > um.state.after'
ctl um-keys snap-unknown-methods 'echo changed > um.keys.after'
ctl um-entry snap-unknown-methods 'echo changed > um.journal.after'
ctl um-agent snap-unknown-methods 'echo changed > um.agent.after'
ctl um-empty-state snap-unknown-methods ': > um.state.before; : > um.state.after'
# a missing evidence file is a problem for every case
for c in $CASES; do
    rm -rf "$tmp/empty"; mkdir "$tmp/empty"
    [ -n "$(snap_problems "$c" "$tmp/empty")" ] || bad "$c accepts an empty evidence directory"
done
[ -n "$(snap_problems snap-nonexistent "$g")" ] || bad "an unknown case is accepted"
# replacing the judge by `true` is caught
mkdir -p "$tmp/fake"; printf 'import sys\nsys.exit(0)\n' > "$tmp/fake/snap.py"
[ -z "$(SN_E2E=$tmp/fake snap_problems snap-bus-denied "$tmp/c-bus-succeeded")" ] || bad "the stub judge is not silent (the control is broken)"
out=$(python3 -I "$E/vm/snap.py" snap-bus-denied "$tmp/c-bus-succeeded"); [ -n "$out" ] || bad "the real judge accepts the bus call that succeeded"

# ---- the test profile is always unloaded
printf '#!/bin/sh\necho "$@" >> "$PARSER_LOG"\n' > "$tmp/parser"
chmod +x "$tmp/parser"
prof() { # prof NAME BODY: runs BODY in a shell that sourced the lib with the stub parser; prints the parser log
    local log=$tmp/plog-$1
    : > "$log"
    PARSER_LOG=$log SN_PARSER=$tmp/parser SN_PROFILE=/p/x bash -c "source $E/vm/snap-lib.sh; snap_install_trap; $2" > /dev/null 2>&1 || true
    cat "$log"
}
r=$(prof ok 'snap_profile_load; true'); [ "$r" = $'-r /p/x\n-R /p/x' ] || bad "a clean end does not unload: '$r'"
r=$(prof failing 'snap_profile_load; false'); grep -q -- '-R /p/x' <<< "$r" || bad "a failing run does not unload: '$r'"
r=$(prof signal 'snap_profile_load; kill -TERM $$; sleep 5'); grep -q -- '-R /p/x' <<< "$r" || bad "a signal does not unload: '$r'"
r=$(prof never 'true'); [ -z "$r" ] || bad "the profile was touched without a load: '$r'"
: > "$tmp/x"
PARSER_LOG=$tmp/x SN_PARSER=$tmp/parser SN_PROFILE=/p/x bash -c "source $E/vm/snap-lib.sh; snap_profile_load; true" > /dev/null 2>&1
! grep -q -- '-R' "$tmp/x" || bad "the control without the trap unloads"
grep -q 'profile snap.e2e-other.app' "$E/vm/snap-other.profile" || bad "the test profile is not named snap.e2e-other.app"

# ---- the D-Bus words of the client against a fake peer
python3 -I "$E/vm/snap-dbus-selftest.py" "$E/vm" || bad "the D-Bus client self-test failed"

# ---- the report of the cases in lacking
(
    export WORK=$tmp/w E2E_SELECT_FILE=$tmp/sel E2E_VM=1 E2E_TPM=lacking
    mkdir -p "$WORK"
    # shellcheck disable=SC2086 # one id per word
    printf '%s\n' $CASES > "$tmp/sel"
    out=$(bash "$E/vm/snap.sh" 2>&1) || exit 1
    n=$(grep -c '^E2E-CASE skipped snap-' <<< "$out")
    [ "$n" = 12 ] || { echo "lacking reports $n skipped cases, not 12: $out" >&2; exit 1; }
) || bad "snap.sh in the lacking mode does not skip the twelve cases"
[ "$fail" -eq 0 ] || exit 1
echo "test-e2e-vm-snap: ok"
