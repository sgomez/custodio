#!/usr/bin/env bash
# Root side of the vm-fingerprint-* cases (F200, acceptances 18 and 19 of SPEC.md). Needs WORK, E2E_VM=1 and E2E_TPM; the VM full mode runs them, the lacking mode reports
# them skipped (SPEC puts the group in full). libfprint's virtual sensor, fprintd, libpam-fprintd and the polkit agent are the real ones (docs/findings/acceptance-6-fingerprint.md).
#   vm-fingerprint-stage  vm-fingerprint-polkit-finger  vm-fingerprint-polkit-unenrolled  vm-fingerprint-polkit-timeout  vm-fingerprint-sudo  vm-fingerprint-negative
#   vm-fingerprint-disabled  vm-fingerprint-sign  vm-fingerprint-fallback-module  vm-fingerprint-fallback-daemon  vm-fingerprint-fallback-reader  vm-fingerprint-fallback-finger
# The judge is e2e/vm/fingerprint.py; the evidence is written here in $WORK/fingerprint (formats at the top of the judge). A staging that fails FAILS the run: no skip path (acceptance 19).
# The group works on its own account (fpuser, with a password), never the harness's: /etc/pam.d/polkit-1 (the harness's pam_permit) and the harness's passwordless sudo rule are set
# aside and put back by an exit trap, and `end.state` says both are back. The fallback cases break one thing each (module moved, daemon masked, drop-in removed, finger deleted),
# the exit trap undoes each too, and CASE.restored says fprintd is up again before the next case.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/../report.sh"
FP_CASES="vm-fingerprint-stage vm-fingerprint-polkit-finger vm-fingerprint-polkit-unenrolled vm-fingerprint-polkit-timeout vm-fingerprint-sudo vm-fingerprint-negative vm-fingerprint-disabled vm-fingerprint-sign vm-fingerprint-fallback-module vm-fingerprint-fallback-daemon vm-fingerprint-fallback-reader vm-fingerprint-fallback-finger"
mode=${E2E_TPM:-swtpm}
if [ -z "${E2E_VM:-}" ] || [ "$mode" != swtpm ]; then
    for c in $FP_CASES; do case_skip "$c" "E2E_TPM=$mode: the fingerprint group runs in the full VM mode (SPEC, end-to-end scope)"; done
    exit 0
fi
for tool in python3 busctl journalctl custodio setpriv useradd chpasswd; do command -v "$tool" > /dev/null || fail "$tool is not installed"; done

FP=$WORK/fingerprint
rm -rf "${FP:?}"
mkdir -p "$FP"
PAMF=/etc/pam.d/polkit-1
ASIDE=/etc/pam.d/polkit-1.e2e-harness
RULE=/etc/polkit-1/rules.d/49-e2e-fingerprint.rules
DROPIN_DIR=/etc/systemd/system/fprintd.service.d
SUDO_ASIDE=/var/lib/e2e-sudo-aside
FPPW='fp-Right-pw-1'
USER_FP=fpuser
SUDO_FILES=''
KEY=fp-key
MODULE=${MODULE:-/usr/lib/custodio/libcustodio_pkcs11.so}
MODSAVE=/var/lib/e2e-pam_fprintd.so
MODPATH=''

restore() { # the files set aside are back, whatever happened
    local f
    rm -f "$RULE"
    # idempotent: the file at $PAMF is the override only while the harness's file is set aside
    [ ! -f "$ASIDE" ] || mv -f "$ASIDE" "$PAMF"
    for f in $SUDO_FILES; do [ ! -f "$SUDO_ASIDE/$(basename "$f")" ] || mv -f "$SUDO_ASIDE/$(basename "$f")" "$f"; done
    SUDO_FILES=''
    [ -z "$MODPATH" ] || [ ! -f "$MODSAVE" ] || mv -f "$MODSAVE" "$MODPATH"
    systemctl unmask fprintd.service > /dev/null 2>&1 || true
    rm -rf "$DROPIN_DIR"
    systemctl daemon-reload || true
    systemctl stop fprintd.service || true
    userdel -r "$USER_FP" > /dev/null 2>&1 || true
}
# shellcheck disable=SC2329 # run by the EXIT trap
on_exit() {
    local rc=$?
    trap - EXIT
    restore || true
    exit "$rc"
}
trap on_exit EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP

# wait_for SECONDS COMMAND...: a condition, polled, bounded
wait_for() { local s=$1; shift; export -f has_device stages_at_least; export FP USER_FP; timeout "$s" bash -c 'until "$@" > /dev/null 2>&1; do sleep 0.1; done' wait_for "$@"; }
# shellcheck disable=SC2329 # run by wait_for, through sh
has_device() { fprintd-list "$USER_FP" 2>&1 | grep -q 'Device at'; }
touch_id() { python3 -I -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect('/run/fpvirt/sock'); s.sendall(('SCAN '+sys.argv[1]+'\n').encode()); s.shutdown(socket.SHUT_WR)" "$1"; }
ver() { dpkg-query -W -f='${Version}' "$1" 2> /dev/null || echo unknown; }
# shellcheck disable=SC2329 # run by wait_for, through sh
stages_at_least() { [ "$(grep -c 'enroll-' "$FP/enroll.out")" -ge "$1" ]; }

# ---- staging: packages from the signed archive (guest only, never a dependency of the package), the virtual sensor, an enrolled finger
apt-get install -y --no-install-recommends fprintd libpam-fprintd pkexec > "$FP/apt.log" 2>&1 || { tail -n 8 "$FP/apt.log" >&2; fail "fprintd and libpam-fprintd do not install from the archive"; }
command -v pkexec > /dev/null || fail "pkexec is not installed after the apt install"
libpkg=$(dpkg-query -W -f='${Package}\n' 'libfprint-2-2*' 2> /dev/null | head -n 1 || true)
libfprint=$(ver "${libpkg:-libfprint-2-2}")
lib=$(dpkg -L "${libpkg:-libfprint-2-2}" 2> /dev/null | grep -m1 'libfprint-2\.so\.2\.' || true)
virt=no
if [ -n "$lib" ] && grep -q FP_VIRTUAL_DEVICE "$lib"; then virt=yes; fi
# the pam-auth-update profile of fprintd must not be on for sudo's stack: only polkit-1 gets the finger, from the override
if grep -q pam_fprintd /etc/pam.d/common-auth; then pam-auth-update --disable fprintd > /dev/null 2>&1 || true; fi
if grep -q pam_fprintd /etc/pam.d/common-auth; then fail "pam_fprintd is still in /etc/pam.d/common-auth: sudo would show the finger"; fi
write_dropin() {
    mkdir -p "$DROPIN_DIR"
    cat > "$DROPIN_DIR/virt.conf" << 'EOF2'
[Service]
Environment=FP_VIRTUAL_DEVICE=/run/fpvirt/sock
RuntimeDirectory=fpvirt
ExecStart=
ExecStart=/usr/libexec/fprintd --no-timeout
EOF2
    systemctl daemon-reload
    systemctl restart fprintd.service
}
write_dropin
id "$USER_FP" > /dev/null 2>&1 || useradd -m -s /bin/bash -G sudo "$USER_FP"
echo "$USER_FP:$FPPW" | chpasswd
# the polkit admin identity is the test user alone (otherwise the agent asks which of the admins to be)
mkdir -p "$(dirname "$RULE")"
printf 'polkit.addAdminRule(function(action, subject) { return ["unix-user:%s"]; });\n' "$USER_FP" > "$RULE"
wait_for 20 has_device || { journalctl -u fprintd --no-pager -n 10 -o cat >&2; fprintd-list "$USER_FP" >&2 2>&1 || true; ls -l /run/fpvirt >&2 2>&1 || true; systemctl cat fprintd.service 2>&1 | tail -n 12 >&2; fail "fprintd lists no device with the virtual sensor"; }
sock=no
enroll_finger() { # five scans of the same id, each when the previous stage was reported
    : > "$FP/enroll.out"
    fprintd-enroll -f right-index-finger "$USER_FP" > "$FP/enroll.out" 2>&1 &
    local enroll=$! i
    for i in 1 2 3 4 5; do
        wait_for 10 stages_at_least "$((i - 1))" || true
        if wait_for 10 test -S /run/fpvirt/sock; then sock=yes; fi # the socket exists only while the device is open (the enrolment holds it)
        touch_id enrolled-finger || true
    done
    wait "$enroll" || true
}
enroll_finger
enrolled=no
if fprintd-list "$USER_FP" 2>&1 | grep -q 'right-index-finger'; then enrolled=yes; fi

# the key the sign case uses: imported now, while the harness's pam_permit file lets the test agent approve the import (the finger is for the signature, not the import)
mkdir -p "$FP/user"
chmod 1777 "$FP" "$FP/user"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$FP/user/k.key" 2> /dev/null
openssl req -new -x509 -key "$FP/user/k.key" -subj "/CN=custodio e2e fingerprint" -days 30 -out "$FP/user/k.crt"
openssl pkcs12 -export -inkey "$FP/user/k.key" -in "$FP/user/k.crt" -name "$KEY" -passout pass:e2e-password -out "$FP/user/k.p12"
rm -f "$FP/user/k.key"
chmod 644 "$FP/user/k.p12"
timeout 300 su -l "$USER_FP" -c "WORK=$WORK MODULE=$MODULE bash $here/fingerprint-user.sh $FP/user $KEY $FP/user/k.p12" > "$FP/user/alice.out" 2>&1 || { cat "$FP/user/alice.out" >&2; fail "the test user could not import the key"; }
rm -f "$FP/user/k.p12" # no key material stays in the evidence

# the harness's pam_permit file is a foreign file for `enable`: set aside, the real layout used
mv -f "$PAMF" "$ASIDE"
override=no
if custodio setup fingerprint enable > "$FP/enable.out" 2>&1 && [ -f "$PAMF" ] && grep -q pam_fprintd "$PAMF"; then override=yes; fi
{
    echo "staging=$([ "$virt$sock$enrolled$override" = yesyesyesyes ] && echo ok || echo failed)"
    echo "virtual_driver=$virt"
    echo "socket=$sock"
    echo "device=yes"
    echo "enrolled=$enrolled"
    echo "override=$override"
    echo "polkit=$(ver polkitd)"
    echo "fprintd=$(ver fprintd)"
    echo "libfprint=$libfprint"
    echo "libpam-fprintd=$(ver libpam-fprintd)"
} > "$FP/record"
sed -i 's/=$/=unknown/' "$FP/record"
while IFS= read -r line; do echo "E2E-FINGERPRINT-RECORD $line"; done < <(grep -E '^(polkit|fprintd|libfprint|libpam-fprintd)=' "$FP/record")
problems=$(python3 -I "$here/fingerprint.py" stage "$FP") || true
if [ -n "$problems" ]; then printf '%s\n' "$problems" >&2; fail "the virtual sensor could not be staged (a failed staging fails the group; acceptance 19)"; fi

# ---- the authentications, on a pseudo-terminal as the test user
MON=''
monitor_start() { busctl --system monitor net.reactivated.Fprint > "$1" 2>&1 & MON=$!; }
monitor_stop() { kill "$MON" 2> /dev/null || true; wait "$MON" 2> /dev/null || true; }
auth() { # CASE PLAN KILL_AFTER CMD...: the driver runs the command as the test user; events in $FP/CASE.events
    local case=$1 plan=$2 kill=$3
    shift 3
    monitor_start "$FP/$case.monitor"
    python3 -I "$here/fingerprint-pty.py" "$FP/$case.events" "$plan" "$kill" "$FP/$case.monitor" -- su -lP -s /bin/bash "$USER_FP" -c "$(printf '%q ' "$@")" || true
    monitor_stop
    pkill -KILL -u "$USER_FP" || true # nothing of the case stays alive to approve later
}
CHECK=/tmp/fp-check.sh
install -m 755 "$here/fingerprint-check.sh" "$CHECK"
marker() { echo "/tmp/fp-approved-$1"; }
approve() { rm -f "$(marker "$1")"; auth "$1" "$2" "$3" "$CHECK" "$(marker "$1")"; }

approve polkit-finger '{"prompt-finger":["touch:enrolled-finger"]}' 0
approve polkit-unenrolled "{\"prompt-finger\":[\"touch:not-enrolled\",\"touch:not-enrolled\",\"touch:not-enrolled\"],\"prompt-password\":[\"type:$FPPW\"]}" 0
approve polkit-timeout "{\"prompt-password\":[\"type:$FPPW\"]}" 0
approve negative '{}' 35
if [ -e "$(marker negative)" ]; then echo present > "$FP/negative.action"; else echo absent > "$FP/negative.action"; fi

# sudo: the harness's passwordless rule is out of the way for this case only (restore() puts it back on any exit)
mkdir -p "$SUDO_ASIDE"
SUDO_FILES=$(grep -l NOPASSWD /etc/sudoers.d/* 2> /dev/null | tr '\n' ' ' || true)
for f in $SUDO_FILES; do mv -f "$f" "$SUDO_ASIDE/$(basename "$f")"; done
auth sudo "{\"prompt-password\":[\"type:wrong-pw\",\"type:$FPPW\"]}" 0 sh -c 'sudo -k; sudo -p "[sudo] password: " /usr/bin/id -u'
cp "$FP/sudo.events.out" "$FP/sudo.text"
for f in $SUDO_FILES; do mv -f "$SUDO_ASIDE/$(basename "$f")" "$f"; done
SUDO_FILES=''

# sign: the enrolled finger is the only authentication of a signature by the module (the pkttyagent is registered for the signing process)
SIGNSH=/tmp/fp-sign.sh
install -m 755 "$here/fingerprint-sign.sh" "$SIGNSH"
printf 'the bytes the finger approved\n' > "$FP/sign.data"
chmod 644 "$FP/sign.data"
rm -f "$FP/user/sign.sig"
journalctl --sync
cur=$(journalctl -n1 --show-cursor | sed -n 's/^-- cursor: //p')
auth sign '{"prompt-finger":["touch:enrolled-finger"]}' 0 "$SIGNSH" "$MODULE" "$KEY" "$FP/sign.data" "$FP/user/sign.sig"
journalctl --sync
journalctl --after-cursor="$cur" _SYSTEMD_UNIT=custodio.service CUSTODIO_OPERATION=sign -o json --no-pager > "$FP/sign.journal"
cp "$FP/user/sign.sig" "$FP/sign.sig" 2> /dev/null || : > "$FP/sign.sig"
cp "$FP/user/pub.pem" "$FP/sign.pub"
echo "$KEY" > "$FP/sign.key"
id -u "$USER_FP" > "$FP/sign.uid"

# the fallbacks: one thing broken, the password asked at once and accepted, then everything restored and shown up again
fprintd_back() { # CASE: fprintd is up again, with its device and the finger, before the next case
    local c=$1 unit=inactive dev=missing
    systemctl unmask fprintd.service > /dev/null 2>&1 || true
    systemctl start fprintd.service > /dev/null 2>&1 || true
    wait_for 20 has_device && dev=listed
    if [ "$(systemctl is-active fprintd.service)" = active ]; then unit=active; fi
    fprintd-list "$USER_FP" 2>&1 | grep -q right-index-finger || fail "$c: the enrolled finger is not back"
    echo "unit=$unit device=$dev" > "$FP/$c.restored"
}
fallback() { # NAME: the password prompt first, the right password approves
    approve "fallback-$1" "{\"prompt-password\":[\"type:$FPPW\"]}" 0
}
MODPATH=$(find /usr/lib -name pam_fprintd.so | head -n 1)
[ -n "$MODPATH" ] || fail "pam_fprintd.so is not found"
mv -f "$MODPATH" "$MODSAVE"
fallback module
mv -f "$MODSAVE" "$MODPATH"
fprintd_back fallback-module
systemctl stop fprintd.service
systemctl mask fprintd.service > /dev/null
fallback daemon
fprintd_back fallback-daemon
rm -rf "$DROPIN_DIR"
systemctl daemon-reload
systemctl restart fprintd.service
fallback reader
write_dropin
fprintd_back fallback-reader
fprintd-delete "$USER_FP" > /dev/null 2>&1 || fail "the enrolled finger could not be deleted"
fallback finger
enroll_finger
fprintd_back fallback-finger

# disabled: the override is gone, polkit shows the password only and consumes no scan
custodio setup fingerprint disable > "$FP/disable.out" 2>&1 || fail "custodio setup fingerprint disable failed: $(head -c 300 "$FP/disable.out")"
if [ -e "$PAMF" ] && grep -q pam_fprintd "$PAMF"; then echo fprintd > "$FP/disabled.pam"; else echo absent > "$FP/disabled.pam"; fi
approve disabled "{\"prompt-password\":[\"type:$FPPW\"]}" 0

# the files set aside are back: checked after restore, which the exit trap runs again
restore
restore # what the exit trap will do again: it must leave the files where they are
state=''
if [ -f "$PAMF" ] && grep -q pam_permit "$PAMF"; then state='polkit-1=back '; fi
if grep -q NOPASSWD /etc/sudoers.d/* 2> /dev/null; then state="${state}sudo-rule=back"; fi
echo "$state" > "$FP/end.state"

problems=''
for c in $FP_CASES; do
    n=${c#vm-fingerprint-}
    p=$(python3 -I "$here/fingerprint.py" "$n" "$FP" 2>&1) || p="the judge failed for $n"
    if [ -z "$p" ]; then case_run "$c"; else problems="$problems
$c:
$p"; fi
done
p=$(python3 -I "$here/fingerprint.py" end "$FP" 2>&1)
if [ -n "$p" ]; then problems="$problems
end:
$p"; fi
if [ -n "$problems" ]; then
    { for f in "$FP"/*.events.out; do echo "--- $f"; tail -c 700 "$f"; done; journalctl -u polkit --no-pager -n 12 -o cat | cut -c1-200; journalctl -u fprintd --no-pager -n 10 -o cat | cut -c1-200; } >&2
    fail "fingerprint cases:$problems"
fi
