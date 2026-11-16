#!/usr/bin/env bash
# Root side of the fingerprint-* cases (F199, acceptance 17 of SPEC.md). Runs the installed `custodio fingerprint` on the real /etc and /usr of the target. It does not touch the daemon,
# keys or the TPM. The image's pam_permit /etc/pam.d/polkit-1 (the test agent's) is renamed to /etc/pam.d.fp-aside (same file system: mode, owner and label stay) and put back at the end and
# from the exit trap. The files the cases move aside (vendor file, module) are renamed in their own directory and put back the same way. Observations go to $WORK/fp as <case>.<name>
# and e2e/fingerprint.py judges each case; every notes line of the judge ("SELinux not enforcing here") is shown in the run record.
# Order: refusals (no override), enable, the file and its label, the PAM client, enable again, disable (byte for byte), then the family cases (pam-auth-update, authselect) with
# the override enabled once more; those two change files of /etc/pam.d and are put back by their own tool, so they come after the byte-for-byte case.
# PAM client: e2e/fingerprint-pam.py (ctypes on libpam) reads /proc/self/maps after pam_authenticate: pam_fprintd.so is mapped only if the stack of polkit-1 went through the override.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
OBS=$WORK/fp
rm -rf "$OBS"
mkdir -p "$OBS"
PAMD=/etc/pam.d
ASIDE=/etc/pam.d.fp-aside
VENDOR=/usr/lib/pam.d/polkit-1
VENDOR_ASIDE=/usr/lib/pam.d/.fp-aside-polkit-1
TUSER=fpuser
TPASS='fp-Test-Pass-1'
module=$(find /usr/lib /usr/lib64 /lib /lib64 -name pam_fprintd.so 2> /dev/null | head -n 1)
[ -n "$module" ] || fail "pam_fprintd.so is not installed in the image"
MODULE_ASIDE=$module.fp-aside
command -v custodio > /dev/null || fail "custodio is not installed"
owes() { grep -qxF -- "$1" "${E2E_TARGET_DIR:-/e2e-target}/cases.list" 2> /dev/null; } # a case of this family only (the common ones are in e2e/cases.list)

manifest() { # PATH...: one line per path: path type mode owner label hash [mtime]; an absent path says so
    local p f
    for p in "$@"; do
        if [ ! -e "$p" ] && [ ! -L "$p" ]; then echo "$p absent"; continue; fi
        find "$p" -print0 | sort -z | while IFS= read -r -d '' f; do
            printf '%s %s' "$f" "$(stat -c '%F %a %U:%G %C' -- "$f" | tr ' ' '_')"
            if [ -f "$f" ] && [ ! -L "$f" ]; then printf ' %s' "$(sha256sum < "$f" | cut -c1-64)"; else printf ' -'; fi
            if [ -n "${FP_MTIME:-}" ]; then printf ' %s' "$(stat -c %Y -- "$f")"; fi
            echo
        done
    done
}
obs() { cat > "$OBS/$1.$2"; } # CASE NAME, content on stdin
fp() { # CASE: run `custodio fingerprint ARGS`, its exit code and output into CASE.rc and CASE.out
    local case=$1 rc=0
    shift
    custodio fingerprint "$@" > "$OBS/$case.out" 2>&1 || rc=$?
    echo "$rc" > "$OBS/$case.rc"
}
client() { python3 -I "$here/fingerprint-pam.py" polkit-1 "$TUSER" "$1"; }

cleaned=''
cleanup() {
    [ -z "$cleaned" ] || return 0
    cleaned=1
    set +e
    if [ -e $PAMD/polkit-1 ] && [ -e "$ASIDE" ]; then
        custodio fingerprint disable > /dev/null 2>&1
        [ ! -e $PAMD/polkit-1 ] || rm -f $PAMD/polkit-1
    fi
    [ ! -e "$VENDOR_ASIDE" ] || mv -f "$VENDOR_ASIDE" "$VENDOR"
    [ ! -e "$MODULE_ASIDE" ] || mv -f "$MODULE_ASIDE" "$module"
    [ ! -e "$ASIDE" ] || { [ ! -e $PAMD/polkit-1 ] || rm -f $PAMD/polkit-1; mv -f "$ASIDE" $PAMD/polkit-1; }
    userdel -r "$TUSER" > /dev/null 2>&1
}
trap cleanup EXIT

# setup: the test agent's file aside, a user with a password
manifest $PAMD/polkit-1 | obs disable-restores agent-before
[ -f $PAMD/polkit-1 ] || fail "the image has no /etc/pam.d/polkit-1 (the test agent's file)"
mv "$PAMD/polkit-1" "$ASIDE"
[ -f "$VENDOR" ] || fail "the vendor file $VENDOR is not installed"
useradd -m "$TUSER"
echo "$TUSER:$TPASS" | chpasswd
manifest $PAMD | obs disable-restores before

# the refusals: nothing changes, the message names the cause
# no vendor file
manifest $PAMD "$VENDOR" | obs refuse-no-vendor before
mv "$VENDOR" "$VENDOR_ASIDE"
fp refuse-no-vendor enable
mv "$VENDOR_ASIDE" "$VENDOR"
manifest $PAMD "$VENDOR" | obs refuse-no-vendor after
# no module
mv "$module" "$MODULE_ASIDE"
manifest $PAMD "$module" | obs refuse-no-module before
fp refuse-no-module enable
manifest $PAMD "$module" | obs refuse-no-module after
mv "$MODULE_ASIDE" "$module"
# a foreign file: the image's own
mv "$ASIDE" $PAMD/polkit-1
manifest $PAMD | obs refuse-foreign before
fp refuse-foreign enable
manifest $PAMD | obs refuse-foreign after
mv $PAMD/polkit-1 "$ASIDE"

# enable: the file, its label, the PAM client
fp enable-file enable
cat $PAMD/polkit-1 > "$OBS/enable-file.content"
stat -c '%a %U:%G %F' $PAMD/polkit-1 | obs enable-file stat
if owes fingerprint-selinux-label; then
    cp "$OBS/enable-file.rc" "$OBS/selinux-label.rc" # the label of the file the first enable wrote
    { cat /sys/fs/selinux/enforce 2> /dev/null || echo 0; } | tr -d '\0' | obs selinux-label enforcing
    stat -c %C $PAMD/polkit-1 | obs selinux-label label
    { matchpathcon -n $PAMD/polkit-1 2> /dev/null || true; } | obs selinux-label default
    { restorecon -n -v $PAMD/polkit-1 2>&1 || true; } | obs selinux-label restorecon
fi
client "$TPASS" | obs pam-password right
client 'not-the-password' | obs pam-password wrong
# enable again: nothing changes, mtime included
FP_MTIME=1 manifest $PAMD | obs enable-twice before
fp enable-twice enable
FP_MTIME=1 manifest $PAMD | obs enable-twice after
# disable: byte for byte
fp disable-restores disable
manifest $PAMD | obs disable-restores after
client "$TPASS" | obs pam-password disabled

# the family cases, with the override enabled again
if owes fingerprint-pam-auth-update; then
    custodio fingerprint enable > /dev/null 2>&1 || fail "enable (before pam-auth-update) failed"
    ov() { { stat -c '%a %U:%G' $PAMD/polkit-1; sha256sum < $PAMD/polkit-1; } | obs pam-auth-update "$1"; }
    ca() { sha256sum < $PAMD/common-auth | obs pam-auth-update "$1"; }
    ov override-before; ca common-before
    rc=0; DEBIAN_FRONTEND=noninteractive pam-auth-update --enable fprintd > "$OBS/pam-auth-update.enable.out" 2>&1 || rc=$?
    echo "$rc" | obs pam-auth-update rc-enable
    ov override-enabled; ca common-enabled
    rc=0; DEBIAN_FRONTEND=noninteractive pam-auth-update --disable fprintd > "$OBS/pam-auth-update.disable.out" 2>&1 || rc=$?
    echo "$rc" | obs pam-auth-update rc-disable
    ov override-disabled; ca common-disabled
fi
if owes fingerprint-authselect; then
    [ -f $PAMD/polkit-1 ] || custodio fingerprint enable > /dev/null 2>&1 || fail "enable (before authselect) failed"
    ov() { { stat -c '%a %U:%G' $PAMD/polkit-1; sha256sum < $PAMD/polkit-1; } | obs authselect "$1"; }
    ov override-before
    sa() { sha256sum < $PAMD/system-auth | obs authselect "$1"; }
    sa system-original
    cp -a $PAMD/system-auth "$WORK/system-auth.orig"
    echo '# edited by the e2e case' >> $PAMD/system-auth
    sa system-modified
    rc=0; authselect apply-changes > "$OBS/authselect.out" 2>&1 || rc=$?
    echo "$rc" | obs authselect rc
    sa system-after
    ov override-after
    cmp -s $PAMD/system-auth "$WORK/system-auth.orig" || { cp -a "$WORK/system-auth.orig" $PAMD/system-auth; }
fi
cleanup
manifest $PAMD/polkit-1 | obs disable-restores agent-after

problems=''
for c in enable-file pam-password enable-twice refuse-foreign refuse-no-vendor refuse-no-module disable-restores pam-auth-update selinux-label authselect; do
    case $c in pam-auth-update | selinux-label | authselect) owes "fingerprint-$c" || continue ;; esac
    echo "fingerprint: judging $c"
    out=$(python3 -I "$here/fingerprint.py" "$c" "$OBS" 2> "$OBS/$c.notes") || problems="$problems
$out"
    sed 's/^/fingerprint: /' "$OBS/$c.notes"
    [ -n "$out" ] || case_run "fingerprint-$c"
done
[ -z "$problems" ] || fail "fingerprint cases:$problems"
echo "fingerprint-run: passed"
