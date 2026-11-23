#!/usr/bin/env bash
# Root side of the doctor-* cases (F204, acceptance 17 of SPEC.md, doctor part). Runs the installed `custodio doctor` as a regular account (doctor-user.sh, `su -l`) on the real /etc of the target and
# judges what it prints (e2e/doctor.py reads the observations in $WORK/doctor). Staged, and put back by the exit trap: the override (`custodio setup fingerprint enable`), the file its include names (renamed in its
# own directory), the journal (a directory made, or a drop-in with Storage=volatile; journald restarted), custodio.service stopped. The image's pam_permit /etc/pam.d/polkit-1 (the test agent's) is
# renamed to /etc/pam.d.doctor-aside, as fingerprint-run.sh does. Exit 0 cannot happen in a container (the state directory is on overlay, check 6 is `not ok`); F203's doctor_acceptance covers it.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
OBS=$WORK/doctor
rm -rf "$OBS"
mkdir -p "$OBS"
chmod 1777 "$OBS"
PAMD=/etc/pam.d
ASIDE=/etc/pam.d.doctor-aside
OVERRIDE=$PAMD/polkit-1
DROPIN_DIR=/etc/systemd/journald.conf.d
DROPIN=$DROPIN_DIR/50-persistent.conf
TUSER=docuser
command -v custodio > /dev/null || fail "custodio is not installed"
obs() { cat > "$OBS/$1"; }
manifest() { # PATH...: path type mode owner mtime hash, one line each; an absent path says so. NO_DIR_MTIME=1: no mtime for a directory (staging an entry changes its parent's; the listing shows entries)
    local p f h t
    for p in "$@"; do
        if [ ! -e "$p" ] && [ ! -L "$p" ]; then echo "$p absent"; continue; fi
        find "$p" -print0 | sort -z | while IFS= read -r -d '' f; do
            h=-
            if [ -f "$f" ] && [ ! -L "$f" ]; then h=$(sha256sum < "$f" | cut -c1-64); fi
            t=%Y
            if [ -n "${NO_DIR_MTIME:-}" ] && [ -d "$f" ]; then t=-; fi
            echo "$f $(stat -c "%F %a %U:%G $t" -- "$f" | tr ' ' '_') $h"
        done
    done
}
INCLUDE=/nonexistent
# /etc without exactly the staged paths: the override, the file it moved aside, the include and its aside name, the drop-in and its directory
etc_manifest() { NO_DIR_MTIME=1 manifest /etc | grep -vE "^($OVERRIDE|$ASIDE|$INCLUDE|$INCLUDE\.doctor-aside|$DROPIN|$DROPIN_DIR) " || true; }
HOME_DIR=''
journal_staged=''
made_dir=''
made_dir_var=''
cleaned=''
cleanup() {
    [ -z "$cleaned" ] || return 0
    cleaned=1
    set +e
    systemctl unmask --runtime custodio.service > /dev/null 2>&1
    systemctl start custodio.service > /dev/null 2>&1
    [ ! -e "$INCLUDE.doctor-aside" ] || mv -f "$INCLUDE.doctor-aside" "$INCLUDE"
    if [ -e "$OVERRIDE" ] && [ -e "$ASIDE" ]; then custodio setup fingerprint disable > /dev/null 2>&1; [ ! -e "$OVERRIDE" ] || rm -f "$OVERRIDE"; fi
    [ ! -e "$ASIDE" ] || { rm -f "$OVERRIDE"; mv -f "$ASIDE" "$OVERRIDE"; }
    if [ -n "$journal_staged" ]; then
        rm -f "$DROPIN"
        [ -z "$made_dir" ] || rmdir "$DROPIN_DIR" 2> /dev/null
        [ -z "$made_dir_var" ] || rmdir /var/log/journal 2> /dev/null
        systemctl restart systemd-journald > /dev/null 2>&1
    fi
    userdel -r "$TUSER" > /dev/null 2>&1
}
trap cleanup EXIT

[ -f "$OVERRIDE" ] || fail "the image has no $OVERRIDE (the test agent's file)"
mv "$OVERRIDE" "$ASIDE"
useradd -m -s /bin/bash "$TUSER"
HOME_DIR=$(getent passwd "$TUSER" | cut -d: -f6)
! id -nG "$TUSER" | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin|root' || fail "the account has sudo rights"

runs=''
udoc() { # NAME: a run as the account, with /etc/pam.d manifested around it
    manifest $PAMD | obs "$1.pam.before"
    timeout 60 su -l "$TUSER" -c "OBS=$OBS bash $here/doctor-user.sh $1" || true
    [ -f "$OBS/$1.rc" ] || fail "doctor-user.sh left no result for $1"
    manifest $PAMD | obs "$1.pam.after"
    runs="$runs $1"
}

# what the journal is, observed independently of doctor
storage=$(systemd-analyze cat-config systemd/journald.conf 2> /dev/null | sed -n 's/^Storage=//p' | tail -n 1)
storage=${storage:-auto}
if [ -d /var/log/journal ]; then echo 1; else echo 0; fi | obs journal.dir
echo "$storage" | obs journal.storage
NO_DIR_MTIME=1 manifest "$HOME_DIR" | obs home.before
etc_manifest | obs etc.before

udoc base
busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 StateStorage | sed 's/^s "\(.*\)"$/\1/' | obs storage.state
busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 StateStorageReason | sed 's/^s "\(.*\)"$/\1/' | obs storage.reason

# the journal flipped: a volatile drop-in when /var/log/journal exists, the directory made when it does not; journald restarted, and again to restore
if [ -d /var/log/journal ]; then
    [ -z "$(find "$DROPIN_DIR" -name '*.conf' 2> /dev/null)" ] || fail "cannot stage the journal flip: journald.conf.d holds files"
    [ -d "$DROPIN_DIR" ] || { mkdir -p "$DROPIN_DIR"; made_dir=1; }
    printf '[Journal]\nStorage=volatile\n' > "$DROPIN"
    echo 1 | obs jflip.dir
else
    mkdir -p /var/log/journal
    made_dir_var=1
    echo 1 | obs jflip.dir
fi
journal_staged=1
systemctl restart systemd-journald
# the effective Storage= is re-read after the restart, as the base run does
storage_now=$(systemd-analyze cat-config systemd/journald.conf 2> /dev/null | sed -n 's/^Storage=//p' | tail -n 1)
echo "${storage_now:-auto}" | obs jflip.storage
udoc jflip
rm -f "$DROPIN"
if [ -n "$made_dir" ]; then rmdir "$DROPIN_DIR"; made_dir=''; fi
if [ -n "$made_dir_var" ]; then rmdir /var/log/journal; made_dir_var=''; fi
systemctl restart systemd-journald
journal_staged=''

# never prompts: no terminal, no agent, a time limit; the journal is read from a cursor taken after the restart
polkit_count() { journalctl --no-pager -q -o cat --since "$1" 2> /dev/null | grep -ci 'polkit.*\(authoriz\|check\)\|Registered Authentication Agent' || true; }
sig_count() { journalctl --no-pager -q -o export -u custodio.service --since "$1" 2> /dev/null | grep -c 'MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401' || true; }
journalctl --sync > /dev/null 2>&1 || true
since=$(date '+%Y-%m-%d %H:%M:%S')
polkit_count "$since" | obs never.pk.before
sig_count "$since" | obs never.sig.before
udoc never_run
cp "$OBS/never_run.rc" "$OBS/never.rc"
journalctl --sync > /dev/null 2>&1 || true
polkit_count "$since" | obs never.pk.after
sig_count "$since" | obs never.sig.after
id -nG "$TUSER" | obs never.groups

# the override on, its include broken, the override off
fp_ok() { custodio setup fingerprint "$@" > /dev/null 2>&1 || fail "custodio setup fingerprint $* failed"; }
fp_ok enable
echo 1 | obs override.present
INCLUDE=$(sed -n 's/^auth[[:space:]]\+include[[:space:]]\+//p' "$OVERRIDE" | head -n 1)
[ -n "$INCLUDE" ] || fail "no include line in the override"
echo "$INCLUDE" | obs broken.include
if [ -e "$INCLUDE" ]; then echo 1; else echo 0; fi | obs on.include.exists
udoc on
mv "$INCLUDE" "$INCLUDE.doctor-aside"
udoc broken
mv "$INCLUDE.doctor-aside" "$INCLUDE"
fp_ok disable
udoc off

# an unreadable ~/.mozilla (a file)
echo 'not a directory' > "$HOME_DIR/.mozilla"
chown "$TUSER": "$HOME_DIR/.mozilla"
udoc nofox
rm -f "$HOME_DIR/.mozilla"

# the service stopped
systemctl mask --runtime custodio.service > /dev/null 2>&1 # the bus would start it again for the call
systemctl stop custodio.service
udoc nosvc
systemctl unmask --runtime custodio.service
systemctl start custodio.service
for _ in $(seq 50); do busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 org.freedesktop.DBus.Peer Ping > /dev/null 2>&1 && break; sleep 0.2; done

echo "$runs" | tr ' ' '\n' | grep -v '^$' | obs runs
NO_DIR_MTIME=1 manifest "$HOME_DIR" | obs home.after
etc_manifest | obs etc.after

# root is refused
etc_manifest | obs root.etc.before
rc=0; custodio doctor < /dev/null > "$OBS/root.out" 2> "$OBS/root.err" || rc=$?
echo "$rc" | obs root.rc
etc_manifest | obs root.etc.after

cleanup
problems=''
for c in six-checks no-reader override-active broken-include no-firefox-profile journal state-storage exit-status never-prompts root-refused changes-nothing; do
    out=$(python3 -I "$here/doctor.py" "$c" "$OBS") || problems="$problems
doctor-$c: $out"
    [ -n "$out" ] || case_run "doctor-$c"
done
if [ -n "$problems" ]; then # what the judge saw, for the run record
    cat "$OBS/base.out" "$OBS/nosvc.out" "$OBS/nofox.out" >&2
    diff "$OBS/etc.before" "$OBS/etc.after" | head -n 10 >&2 || true
    diff "$OBS/home.before" "$OBS/home.after" | head -n 10 >&2 || true
    fail "doctor cases:$problems"
fi
echo "doctor-run: passed"
