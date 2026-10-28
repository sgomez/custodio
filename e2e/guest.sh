#!/usr/bin/env bash
# Runs as root inside the systemd container: installs the package, starts the real service, imports
# a key, and runs user.sh in a logind session of an ordinary user (the polkit agent needs one).
set -euo pipefail
MODULE=/usr/lib/custodio/libcustodio_pkcs11.so
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }

# The checks of the journal checker come first; a broken checker would make the later checks worthless.
bash /e2e/journal-selftest.sh || fail "the journal self-test failed"
start=$(date +%s) # journal checks only look at entries since here
dpkg -i /pkg/custodio.deb >/dev/null
systemctl daemon-reload
systemctl reload dbus # restart would drop logind and polkit off the bus
systemctl start polkit
# The service is started by D-Bus activation on the first call, as for a user; start it now so a
# failing unit (hardening too strict) shows up here with its log.
systemctl start custodio || { journalctl -u custodio --no-pager | tail -n 30 >&2; fail "custodio.service did not start"; }
systemctl is-active --quiet custodio || fail "custodio.service is not active"
[ "$(systemctl show -p User --value custodio)" = custodio ] || fail "the service does not run as user custodio"

id alice >/dev/null 2>&1 || useradd -m -s /bin/bash alice
work=$(mktemp -d /tmp/e2e.XXXXXX)
chmod 755 "$work"
chown alice "$work" # user.sh writes the agent state and signatures here
for kind in rsa ec; do
    case $kind in
        rsa) genopt=(-algorithm RSA -pkeyopt rsa_keygen_bits:2048) ;;
        ec) genopt=(-algorithm EC -pkeyopt ec_paramgen_curve:P-256) ;;
    esac
    openssl genpkey "${genopt[@]}" -out "$work/$kind.key" 2>/dev/null
    openssl req -new -x509 -key "$work/$kind.key" -subj "/CN=custodio e2e $kind" -days 30 -out "$work/$kind.crt"
    openssl pkcs12 -export -inkey "$work/$kind.key" -in "$work/$kind.crt" -name "${kind}1" \
        -passout pass:e2e-password -out "$work/${kind}1.p12"
done
# A CSR for NSS to sign with the custodied RSA key (the CSR's own key is a throwaway).
openssl req -new -newkey rsa:2048 -nodes -keyout "$work/csr.key" -subj "/CN=e2e subject" -out "$work/csr.pem" 2>/dev/null
openssl req -in "$work/csr.pem" -outform DER -out "$work/csr.der"
head -c 32 /dev/urandom > "$work/data.bin"
for kind in rsa ec; do openssl x509 -in "$work/$kind.crt" -pubkey -noout > "$work/$kind.pub"; done
chmod 644 "$work"/*

# Import as the user, on a pseudo-terminal (the password is only read from /dev/tty).
for k in rsa1 ec1; do
    su -l alice -c "python3 -I /e2e/import.py $work/$k.p12 $k e2e-password" >/dev/null \
        || fail "import of $k failed"
done
rm -f "$work"/*.key "$work"/*.p12

# User side, in a login session: `su -l` goes through PAM, so pam_systemd opens a logind session.
su -l alice -c "WORK=$work MODULE=$MODULE bash /e2e/user.sh" || fail "user.sh failed"

# Polkit unavailable: stopped and masked, so that D-Bus activation cannot start it either. The trap only
# restores it if the explicit restore below was not reached.
restore_polkit() { systemctl unmask --runtime polkit && systemctl start polkit; }
trap 'restore_polkit >/dev/null 2>&1 || true' EXIT
total=$(wc -l < "$work/agent/requests") # requests of the agent so far: one per signature up to here
systemctl stop polkit
systemctl mask --runtime polkit >/dev/null 2>&1
if systemctl is-active --quiet polkit; then fail "polkit still active"; fi
timeout 60 su -l alice -c "WORK=$work MODULE=$MODULE bash /e2e/unavailable.sh" || fail "unavailable.sh failed"
restore_polkit || fail "polkit could not be restored"
systemctl is-active --quiet polkit || fail "polkit is not active after the restore"
WORK=$work START=$start TOTAL=$total bash /e2e/journal-check.sh || fail "journal-check.sh failed"

# The service must still be healthy and must not have logged a secret.
systemctl is-active --quiet custodio || fail "custodio.service died during the tests"
if journalctl -u custodio --no-pager | grep -q "e2e-password"; then fail "the password reached the journal"; fi
echo "e2e: all checks passed"
