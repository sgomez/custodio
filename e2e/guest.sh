#!/usr/bin/env bash
# Runs as root inside the systemd container, the same on every target: installs the package with the target's own step
# (/e2e-target/install.sh), starts the real service, imports a key, and runs user.sh in a logind session of an ordinary user
# (the polkit agent needs one). Prints the record of the run (the target's probe.sh) and one E2E-CASE line per case (report.sh).
# Usage: guest.sh TARGET [oldpath]. With "oldpath" (F61, on a fresh container) it installs the old-path fixture (/pkg-oldpath, the current package with the daemon at /usr/lib/custodio);
# it reports the upgrade-oldpath-* cases only. A target with a no-oldpath marker (Arch has no old path) skips them in the main run.
# With E2E_SELECT (F63, `just e2e-cases`: case ids separated by spaces) only those cases are reported, by report.sh, and a step that no selected case
# needs is not run (select.sh); the setup (install, service, user, import) always is.
set -euo pipefail
mode=${2:-main}
case $mode in main | old | oldpath) ;; *) echo "e2e: FAIL: unknown mode '$mode'" >&2; exit 1 ;; esac
MODULE=/usr/lib/custodio/libcustodio_pkcs11.so
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
# shellcheck source=e2e/select.sh
source /e2e/select.sh
if [ -n "${E2E_SELECT:-}" ]; then
    # shellcheck disable=SC2086 # one id per word; globbing is off, an id has no character the shell would expand
    (set -f; printf '%s\n' $E2E_SELECT) > "$E2E_SELECT_FILE"
else
    rm -f "$E2E_SELECT_FILE"
fi

# A refusal-only target (F50) installs nothing: it runs the refusal case only, with no service, key, user session, upgrade or lifecycle step.
if [ -f /e2e-target/refusal-only ]; then
    [ "$mode" = main ] || fail "a refusal-only target has no old-package or old-path run"
    pkg=$(find /pkg -type f | head -n 1)
    [ -n "$pkg" ] || fail "no package is mounted in /pkg"
    if phase_runs refusal; then
        bash /e2e/refusal-selftest.sh || fail "the refusal self-test failed"
        bash /e2e/refusal.sh "$pkg" || fail "refusal.sh failed"
    fi
    probe=$(bash /e2e-target/probe.sh) || fail "the probe of the bus daemon and polkit failed"
    while IFS= read -r line; do echo "E2E-RECORD $line"; done <<< "$probe"
    echo "e2e: all checks passed (refusal)"
    exit 0
fi

# The checks of the journal checker come first; a broken checker would make the later checks worthless.
bash /e2e/journal-selftest.sh || fail "the journal self-test failed"
start=$(date +%s) # journal checks only look at entries since here
case $mode in oldpath) from_dir=/pkg-oldpath ;; *) from_dir=/pkg ;; esac
pkg=$(find "$from_dir" -type f | head -n 1)
[ -n "$pkg" ] || fail "no package is mounted in $from_dir"
pkg_next=$(find /pkg-next -type f | head -n 1)
[ -n "$pkg_next" ] || fail "no package N+1 is mounted in /pkg-next"
bash /e2e-target/install.sh "$pkg" || fail "the package could not be installed"
echo "e2e: installed $(basename "$pkg") from the mounted file"
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

# Import as the user. Import asks polkit, so import-user.sh starts the test agent and approves in the same login session.
su -l alice -c "WORK=$work bash /e2e/import-user.sh" || fail "import-user.sh failed"
rm -f "$work"/*.key "$work"/*.p12

if [ "$mode" = oldpath ]; then
    WORK=$work MODULE=$MODULE bash /e2e/upgrade.sh "$pkg" "$pkg_next" upgrade-oldpath || fail "upgrade.sh failed (from the old-path package)"
    systemctl is-active --quiet custodio || fail "custodio.service is not active after the upgrade from the old-path package"
    echo "e2e: all checks passed (upgrade from the old-path package)"
    exit 0
fi

# User side, in a login session: `su -l` goes through PAM, so pam_systemd opens a logind session. With a selection, the steps that no selected case
# needs are left out (select.sh); user.sh also leaves the agent state that the unavailable and journal steps read.
if phase_runs user; then
    su -l alice -c "WORK=$work MODULE=$MODULE bash /e2e/user.sh" || fail "user.sh failed"
fi

# Polkit unavailable: stopped and masked, so that D-Bus activation cannot start it either. The trap only
# restores it if the explicit restore below was not reached.
restore_polkit() { systemctl unmask --runtime polkit && systemctl start polkit; }
if phase_runs unavailable; then
    trap 'restore_polkit >/dev/null 2>&1 || true' EXIT
    total=$(wc -l < "$work/agent/requests") # requests of the agent so far: one per signature up to here
    systemctl stop polkit
    systemctl mask --runtime polkit >/dev/null 2>&1
    if systemctl is-active --quiet polkit; then fail "polkit still active"; fi
    timeout 60 su -l alice -c "WORK=$work MODULE=$MODULE bash /e2e/unavailable.sh" || fail "unavailable.sh failed"
    restore_polkit || fail "polkit could not be restored"
    systemctl is-active --quiet polkit || fail "polkit is not active after the restore"
fi
if phase_runs journal; then
    WORK=$work START=$start TOTAL=$total bash /e2e/journal-check.sh || fail "journal-check.sh failed"
fi

# The ownership cases (F91): two ordinary accounts, each with a session and an agent of its own. After the journal step, whose counts they would
# change (they sign, import and delete), and before the upgrade, whose cases and the lifecycle's look at the state of the keys or at windows of
# their own: the step deletes every key it imports. Needs nothing from the steps above but the setup.
if phase_runs owner; then
    WORK=$work MODULE=$MODULE START=$start bash /e2e/owner-run.sh || fail "owner-run.sh failed"
fi

# The polkit cases of import, delete and replace certificate (F92): alice, her own session and agent, polkit answering, refusing and stopped. After owner,
# and before the upgrade, for the same reasons; polkit is stopped for a while and restored (the trap below covers every path); every key it makes it deletes.
if phase_runs ops-polkit; then
    trap 'restore_polkit >/dev/null 2>&1 || true' EXIT
    WORK=$work MODULE=$MODULE bash /e2e/ops-run.sh || fail "ops-run.sh failed"
fi

# The replace-certificate and delete cases (F93): alice, her own session and agent approving, the CLI, the service and the PKCS#11 module. Each group makes keys of its
# own and deletes them, so the state after is the one before; after ops-polkit and before the upgrade, for the same reasons.
if phase_runs replace; then
    WORK=$work MODULE=$MODULE bash /e2e/rd-run.sh replace || fail "rd-run.sh replace failed"
fi
if phase_runs delete; then
    WORK=$work MODULE=$MODULE bash /e2e/rd-run.sh delete || fail "rd-run.sh delete failed"
fi

# The journal cases of every operation (F94): alice signs, imports, deletes and replaces with known outcomes, root reads the journal of the service between two
# marker entries. After delete and before the upgrade, for the same reasons; every key is deleted at the end, so the state and the counts are as before.
if phase_runs journal-ops; then
    WORK=$work MODULE=$MODULE bash /e2e/jo-run.sh || fail "jo-run.sh failed"
fi

# The app-id cases (F95): alice calls from processes in scopes of her user manager (named as flatpak names them, and hostile ones) and root judges the entries
# of the journal and that nothing of the hostile names is in it. After journal-ops and before the upgrade, for the same reasons; it makes children of her
# app.slice and removes them, imports a key and deletes it, so the state and the counts are as before.
if phase_runs appid; then
    WORK=$work MODULE=$MODULE bash /e2e/appid-run.sh || fail "appid-run.sh failed"
fi

# The upgrade case comes last of the cases, so that it does not disturb the audit counts above: it installs N+1 over N.
# The lifecycle cases start from the state it leaves, so they need it too.
if phase_runs upgrade; then
    WORK=$work MODULE=$MODULE bash /e2e/upgrade.sh "$pkg" "$pkg_next" || fail "upgrade.sh failed"
fi

# A target without an old path (Arch) skips the cases of the upgrade from it, with the reason its marker holds.
if [ -f /e2e-target/no-oldpath ]; then
    # shellcheck source=e2e/report.sh
    source /e2e/report.sh
    reason=$(head -n 1 /e2e-target/no-oldpath)
    for c in version-greater service-new-binary state-unchanged keys-listed signs-with-polkit no-manual-step; do case_skip "upgrade-oldpath-$c" "$reason"; done
fi

# The removal, purge and reinstall cases come after the upgrade: they remove N+1 and install it again, from the state the upgrade left.
if phase_runs lifecycle; then
    WORK=$work MODULE=$MODULE bash /e2e/lifecycle.sh "$pkg_next" || fail "lifecycle.sh failed"
fi

# The service must still be healthy and must not have logged a secret.
systemctl is-active --quiet custodio || fail "custodio.service died during the tests"
if journalctl -u custodio --no-pager | grep -q "e2e-password"; then fail "the password reached the journal"; fi
probe=$(bash /e2e-target/probe.sh) || fail "the probe of the bus daemon and polkit failed"
while IFS= read -r line; do echo "E2E-RECORD $line"; done <<< "$probe"
echo "e2e: all checks passed"
