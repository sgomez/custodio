#!/usr/bin/env bash
# F179: container-free checks of the snap-* cases (e2e/vm/snap.py, snap-lib.sh): the judge of every case accepts a fixture of the guest's evidence and rejects one
# broken fact, the real `custodio setup browsers enable` acts on the profile the place phase makes, and the mode that skips the cases reports them. NOT checked here: a real guest.
# shellcheck disable=SC2015,SC2016 # A && B || bad is the check; single quotes hold text for the copies
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
echo 0 > register.rc
printf 'ok    Firefox (snap)  module copy: placed\nok    Firefox (snap)  s.default: registered\n      Restart the browsers to see the change.\n' > register.out
echo 5d41402abc4b2a76b9719d911017c592 > module.sha; cp module.sha copy.sha
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
# one control per case
ctl rec-dangerous snap-record "sed -i 's/ -\$/ dangerous/' snap-list.out"
MSG='snap profile was registered' ctl reg-no-profile snap-record "sed -i '/s.default/d' register.out"
MSG='not ok' ctl reg-failed snap-record "printf 'FAIL  Firefox         a.default: a browser has it open\n' >> register.out"
ctl dir-775 snap-socket-dir "echo 'directory|root|root|775|/run/snap.firefox' > dir.stat"
ctl keys-foreign snap-list-keys "printf 'token\tbob-key\n' >> list.out"
ctl sig-flipped snap-sign-rsa "python3 -I -c \"d=bytearray(open('sign-rsa.sig','rb').read()); d[5]^=1; open('sign-rsa.sig','wb').write(d)\""
ctl sig-ec-flipped snap-sign-ec "python3 -I -c \"d=bytearray(open('sign-ec.sig','rb').read()); d[5]^=1; open('sign-ec.sig','wb').write(d)\""
ctl pk-one-request snap-polkit-per-signature "sed -i '3d' subjects"
ctl jl-unconfined snap-journal-label "sed -i 's/\"CUSTODIO_PEER_LABEL\":\"[^\"]*\"/\"CUSTODIO_PEER_LABEL\":\"unconfined\"/' journal.json"
MSG='person must look' ctl bus-succeeded snap-bus-denied 'echo ok > bus-in.out'
ctl unconf-listed snap-refused-unconfined "printf 'token\tsn-rsa\n' > unconf.out"
ctl root-new-sign snap-refused-root 'echo 4 > root.signs.after'
ctl other-wrong-reason snap-refused-other-snap "echo 'custodiod: peer refused: the peers label is refused: peer is unconfined' > other.refusal.log"
ctl um-success snap-unknown-methods "echo ok > um-ImportP12.out"

# ---- the profile the guest's place phase makes, then the real command registers it (F179's harness, F183's command)
bin=$ROOT/target/debug/custodio-cli
cargo build --quiet --locked -p custodio-cli || bad "the command could not be built"
stub=$(find /usr/lib /usr/lib64 -name libsoftokn3.so -print -quit 2> /dev/null) || true # a loadable shared object: modutil refuses anything else
[ -n "$stub" ] || bad "no shared object for the stub module"
mkdir -p "$tmp/mod"
cp "$stub" "$tmp/mod/libcustodio_pkcs11.so"
reg() { # HOME: the real command on it, as the place phase runs it, with the module of this run
    HOME=$1 "$bin" setup browsers enable --module "$tmp/mod/libcustodio_pkcs11.so"
}
mkdir -p "$tmp/home"
snap_make_profile "$tmp/home/snap/firefox/common/.mozilla/firefox" || bad "snap_make_profile failed on a temporary home"
out=$(reg "$tmp/home") || bad "custodio setup browsers enable failed on the home the function made: $out"
grep -qE '^ok +Firefox \(snap\)  +s\.default: ' <<< "$out" || bad "the command did not report the snap profile registered: $out"
cmp -s "$tmp/mod/libcustodio_pkcs11.so" "$tmp/home/snap/firefox/common/libcustodio_pkcs11.so" || bad "the copy is not the module"
modutil -dbdir "sql:$tmp/home/snap/firefox/common/.mozilla/firefox/s.default" -list < /dev/null | grep -q 'common/libcustodio_pkcs11.so' || bad "the profile does not list the copy"
# the judge accepts that report and the copy's hash as the place phase records them
cp -r "$g" "$tmp/c-real"
printf '%s\n' "$out" > "$tmp/c-real/register.out"
p=$(snap_problems snap-record "$tmp/c-real"); [ -z "$p" ] || bad "the judge rejects the report of the real command: $p"
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
