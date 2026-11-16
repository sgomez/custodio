#!/usr/bin/env bash
# F200: container-free checks of the vm-fingerprint-* cases (e2e/vm/fingerprint.py): the judge of every case accepts a fixture of the guest's evidence and rejects one
# broken fact per rule, naming it; the judge's case ids are the ones of e2e/vm/cases.list. NOT checked here: a real guest (the run proves the guest scripts).
# shellcheck disable=SC2015,SC2016 # A && B || bad is the check; single quotes hold text for the copies
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-vm-fingerprint: $*" >&2; fail=1; }
J=$ROOT/e2e/vm/fingerprint.py
CASES="stage polkit-finger polkit-unenrolled polkit-timeout sudo negative disabled sign fallback-module fallback-daemon fallback-reader fallback-finger"
judge() { python3 -I "$J" "$1" "$2" 2>&1 || echo "the judge failed for $1"; }

# the judge knows the cases of the list, no more and no fewer
listed=$(sed -n 's/^vm-fingerprint-//p' "$ROOT/e2e/vm/cases.list" | tr '\n' ' ')
# shellcheck disable=SC2086 # the cases are a word list
[ "$listed" = "$(printf "%s " $CASES)" ] || bad "the cases of e2e/vm/cases.list ($listed) differ from the judge's ($CASES)"

# ---- the good evidence
g=$tmp/good
mkdir -p "$g"
cd "$g"
cat > record << 'EOF2'
staging=ok
virtual_driver=yes
socket=yes
device=yes
enrolled=yes
override=yes
polkit=127-2ubuntu1
fprintd=1.94.5-4
libfprint=1:1.95.1+tod1-0ubuntu2
libpam-fprintd=1.94.5-4
EOF2
printf '0 start\n0.4 prompt-finger\n0.9 scan right-index-finger\n1.1 matched\n1.3 approved\n' > polkit-finger.events
printf '0 start\n0.4 prompt-finger\n0.9 scan unenrolled\n1.1 nomatch\n1.3 prompt-password\n1.6 typed-right\n1.9 approved\n' > polkit-unenrolled.events
printf '0 start\n0.4 prompt-finger\n10.6 prompt-password\n10.9 typed-right\n11.2 approved\n' > polkit-timeout.events
printf '0 start\n0.3 prompt-password\n0.6 typed-wrong\n0.9 refused\n1.2 prompt-password\n1.5 typed-right\n1.8 approved\n' > sudo.events
printf '[sudo] password for fpuser: \nSorry, try again.\n[sudo] password for fpuser: \n' > sudo.text
printf '0 start\n0.4 prompt-finger\n0.8 prompt-password\n15.5 killed\n' > negative.events
echo absent > negative.action
printf '0 start\n0.3 prompt-password\n0.6 typed-right\n0.9 approved\n' > disabled.events
echo absent > disabled.pam; echo 0 > disabled.scans
printf '0 start\n0.4 prompt-finger\n0.9 scan right-index-finger\n1.1 matched\n1.5 approved\n' > sign.events
openssl ecparam -name prime256v1 -genkey -noout -out k.pem 2> /dev/null
openssl ec -in k.pem -pubout -out sign.pub 2> /dev/null
printf 'to be signed' > sign.data
openssl dgst -sha256 -sign k.pem -out sign.sig sign.data
rm -f k.pem
echo fp-sign > sign.key; echo 1001 > sign.uid
printf '{"MESSAGE":"signature made","CUSTODIO_OPERATION":"sign","CUSTODIO_KEY":"fp-sign","CUSTODIO_UID":"1001"}\n' > sign.journal
for c in module daemon reader finger; do
    printf '0 start\n0.3 prompt-password\n0.6 typed-right\n0.9 approved\n' > fallback-$c.events
    echo 'unit=active device=listed' > fallback-$c.restored
done
echo 'polkit-1=back sudo-rule=back' > end.state
cd "$ROOT"

for c in $CASES end; do
    p=$(judge "$c" "$g"); [ -z "$p" ] || bad "good evidence rejected for $c: $p"
done
p=$(judge vm-fingerprint-sign "$g"); [ -z "$p" ] || bad "the judge does not take the full id: $p"

# ctl NAME CASE SHELL-TEXT: a copy of the good evidence changed by SHELL-TEXT (run in the copy), which the judge of CASE must reject; MSG (env) is in the answer
ctl() {
    local n=$1 c=$2 d=$tmp/c-$1 out
    cp -r "$g" "$d"
    (cd "$d" && bash -c "$3")
    out=$(judge "$c" "$d")
    [ -n "$out" ] || { bad "control $n: the case $c accepts bad evidence"; return; }
    [ -z "${MSG:-}" ] || grep -qF -- "$MSG" <<< "$out" || bad "control $n: the answer lacks '$MSG': $out"
}
# a missing evidence file, for every case
for c in $CASES end; do
    d=$tmp/c-missing-$c
    cp -r "$g" "$d"
    rm -f "$d/$c.events" "$d/record" "$d/end.state"
    [ -n "$(judge "$c" "$d")" ] || bad "control: $c accepts evidence with its file missing"
done
# stage
MSG='skipped' ctl stage-skipped stage 'sed -i "s/^staging=ok/staging=skipped/" record'
MSG='virtual_driver' ctl stage-nodriver stage 'sed -i "s/^virtual_driver=yes/virtual_driver=no/" record'
MSG='enrolled' ctl stage-noenrol stage 'sed -i "/^enrolled/d" record'
MSG='override' ctl stage-nooverride stage 'sed -i "s/^override=yes/override=no/" record'
for v in polkit fprintd libfprint libpam-fprintd; do MSG="version of $v" ctl "ver-$v" stage "sed -i 's/^$v=.*/$v=unknown/' record"; done
# polkit-finger
MSG="'typed-right'" ctl finger-typed polkit-finger "printf '1.2 typed-right\n' >> polkit-finger.events"
MSG="'prompt-finger'" ctl finger-noprompt polkit-finger 'sed -i "/prompt-finger/d" polkit-finger.events'
MSG="'scan'" ctl finger-noscan polkit-finger 'sed -i "/ scan/d" polkit-finger.events'
MSG="'matched'" ctl finger-nomatch polkit-finger 'sed -i "/matched/d" polkit-finger.events'
ctl finger-password polkit-finger 'sed -i "s/^0.4 prompt-finger/0.4 prompt-password/" polkit-finger.events'
ctl finger-nostart polkit-finger 'sed -i "1d" polkit-finger.events'
# polkit-unenrolled
MSG="'typed-wrong'" ctl unenr-wrong-typed polkit-unenrolled 'sed -i "s/typed-right/typed-wrong/" polkit-unenrolled.events'
MSG="'nomatch'" ctl unenr-nofail polkit-unenrolled 'sed -i "/nomatch/d" polkit-unenrolled.events'
MSG="'matched'" ctl unenr-matched polkit-unenrolled 'printf "1.2 matched\n" >> polkit-unenrolled.events'
ctl unenr-nopassword polkit-unenrolled 'sed -i "/prompt-password/d;/typed/d;/refused/d" polkit-unenrolled.events'
ctl unenr-not-approved polkit-unenrolled 'sed -i "/approved/d" polkit-unenrolled.events'
# polkit-timeout: before 10 s, never, after the margin, a scan sent
MSG='before the 10 s timeout' ctl to-early polkit-timeout 'sed -i "s/^10.6 prompt-password/9.5 prompt-password/" polkit-timeout.events'
MSG='before the 10 s timeout' ctl to-immediate polkit-timeout 'sed -i "s/^10.6 prompt-password/0.5 prompt-password/" polkit-timeout.events'
MSG='after 15 s' ctl to-late polkit-timeout 'sed -i "s/^10.6 prompt-password/60.4 prompt-password/" polkit-timeout.events'
ctl to-never polkit-timeout 'sed -i "/prompt-password/d;/typed/d;/refused/d;/approved/d" polkit-timeout.events'
MSG="'scan'" ctl to-scan polkit-timeout 'sed -i "s/^0.4 prompt-finger/0.4 prompt-finger\n0.5 scan x/" polkit-timeout.events'
# sudo
MSG="'prompt-finger'" ctl sudo-fingerprompt sudo 'sed -i "s/^0.3 prompt-password/0.2 prompt-finger\n0.3 prompt-password/" sudo.events'
MSG='fingerprint prompt' ctl sudo-text sudo 'echo "Place your finger on the reader" >> sudo.text'
MSG="'prompt-password'" ctl sudo-nopassword sudo 'printf "0 start\n0.5 approved\n" > sudo.events'
MSG="'typed-wrong'" ctl sudo-rule-left sudo 'printf "0 start\n0.3 prompt-password\n0.6 typed-right\n0.9 approved\n" > sudo.events'
MSG="'refused'" ctl sudo-wrong-accepted sudo 'sed -i "/refused/d" sudo.events'
# negative
MSG="'approved'" ctl neg-approved negative 'printf "15.7 approved\n" >> negative.events'
MSG='was performed' ctl neg-action negative 'echo present > negative.action'
MSG='before the 15 s' ctl neg-fastkill negative 'sed -i "s/^15.5 killed/3 killed/" negative.events'
MSG="'killed'" ctl neg-notkilled negative 'sed -i "/killed/d" negative.events'
MSG="'typed-right'" ctl neg-password negative 'printf "5 typed-right\n" >> negative.events'
# disabled
MSG="'prompt-finger'" ctl dis-finger disabled 'sed -i "s/^0.3 prompt-password/0.2 prompt-finger\n0.3 prompt-password/" disabled.events'
MSG='still names' ctl dis-pam disabled 'echo fprintd > disabled.pam'
MSG='scan was consumed' ctl dis-scans disabled 'echo 1 > disabled.scans'
# sign
MSG='does not verify' ctl sign-flipped sign "python3 -I -c \"d=bytearray(open('sign.sig','rb').read()); d[10]^=1; open('sign.sig','wb').write(d)\""
MSG='does not verify' ctl sign-otherdata sign 'printf "other" > sign.data'
MSG='0 sign entries' ctl sign-nojournal sign ': > sign.journal'
MSG='3 sign entries' ctl sign-extra sign 'cat sign.journal sign.journal sign.journal > j; mv j sign.journal'
MSG='not' ctl sign-wrongkey sign 'echo other > sign.key'
MSG='not' ctl sign-wronguid sign 'echo 0 > sign.uid'
MSG="'typed-right'" ctl sign-password sign 'printf "1.2 typed-right\n" >> sign.events'
MSG="'prompt-finger'" ctl sign-nofinger sign 'sed -i "/prompt-finger/d" sign.events'
# fallbacks
for c in module daemon reader finger; do
    MSG="'prompt-finger'" ctl "fb-$c-finger" "fallback-$c" "sed -i 's/^0.3 prompt-password/0.2 prompt-finger\n0.3 prompt-password/' fallback-$c.events"
    MSG='timeout was waited' ctl "fb-$c-waited" "fallback-$c" "sed -i 's/^0.3 prompt-password/10.4 prompt-password/' fallback-$c.events"
    MSG='not shown up again' ctl "fb-$c-notrestored" "fallback-$c" "echo 'unit=inactive device=none' > fallback-$c.restored"
    ctl "fb-$c-notapproved" "fallback-$c" "sed -i '/approved/d' fallback-$c.events"
done
# end: the files set aside
MSG='polkit-1=back' ctl end-polkit end 'echo "sudo-rule=back" > end.state'
MSG='sudo-rule=back' ctl end-sudo end 'echo "polkit-1=back" > end.state'
# an unknown case is not accepted
[ -n "$(judge vm-fingerprint-bogus "$g")" ] || bad "an unknown case is accepted"
[ "$fail" -eq 0 ] && echo "test-e2e-vm-fingerprint: ok"
exit $fail
