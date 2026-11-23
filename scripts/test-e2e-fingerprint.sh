#!/usr/bin/env bash
# F199: container-free check of e2e/fingerprint.py, the judge of the fingerprint-* cases: one accepted set of observations per case and, for each rule, a set that breaks only
# that rule and must be rejected with the rule's words. NOT checked here: the real runs (`just e2e-cases <target> 'fingerprint-*'`).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-fingerprint: $*" >&2; fail=1; }
EXPECTED=$(python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); import fingerprint; sys.stdout.write(fingerprint.EXPECTED + "x")' "$ROOT/e2e")
EXPECTED=${EXPECTED%x}
M=$'/etc/pam.d/common-auth file 644 root:root - aaaa\n/etc/pam.d/other file 644 root:root - bbbb'

# w DIR CASE NAME CONTENT
w() { printf '%s' "$4" > "$1/$2.$3"; }
good() { # DIR: the accepted observations of every case
    local d=$1 c
    mkdir -p "$d"
    w "$d" enable-file rc 0; w "$d" enable-file content "$EXPECTED"; w "$d" enable-file stat '644 root:root regular file'
    w "$d" pam-password right 'rc=0 fprintd=1'; w "$d" pam-password wrong 'rc=7 fprintd=1'; w "$d" pam-password disabled 'rc=0 fprintd=0'
    w "$d" enable-twice rc 0; w "$d" enable-twice before "$M"; w "$d" enable-twice after "$M"
    for c in refuse-foreign refuse-no-vendor refuse-no-module; do
        w "$d" $c rc 1; w "$d" $c before "$M"; w "$d" $c after "$M"
    done
    w "$d" refuse-foreign out 'custodio setup fingerprint: /etc/pam.d/polkit-1 is not Custodio'"'"'s'
    w "$d" refuse-no-vendor out 'custodio setup fingerprint: /usr/lib/pam.d/polkit-1 is missing'
    w "$d" refuse-no-module out 'custodio setup fingerprint: pam_fprintd.so is not installed'
    w "$d" disable-restores rc 0; w "$d" disable-restores before "$M"; w "$d" disable-restores after "$M"
    w "$d" disable-restores agent-before '/etc/pam.d/polkit-1 file 644 root:root - cccc'; w "$d" disable-restores agent-after '/etc/pam.d/polkit-1 file 644 root:root - cccc'
    w "$d" pam-auth-update rc-enable 0; w "$d" pam-auth-update rc-disable 0
    for n in override-before override-enabled override-disabled; do w "$d" pam-auth-update $n 'dddd 644 root:root'; done
    w "$d" pam-auth-update common-before one; w "$d" pam-auth-update common-enabled two; w "$d" pam-auth-update common-disabled one
    w "$d" selinux-label rc 0; w "$d" selinux-label enforcing 1; w "$d" selinux-label label 'system_u:object_r:etc_t:s0'
    w "$d" selinux-label default 'system_u:object_r:etc_t:s0'; w "$d" selinux-label restorecon ''
    w "$d" authselect rc 0; w "$d" authselect override-before 'dddd 644'; w "$d" authselect override-after 'dddd 644'
    w "$d" authselect system-original orig; w "$d" authselect system-modified edited; w "$d" authselect system-after orig
}
J() { python3 -I "$ROOT/e2e/fingerprint.py" "$@"; }
CASES="enable-file pam-password enable-twice refuse-foreign refuse-no-vendor refuse-no-module disable-restores pam-auth-update selinux-label authselect"
good "$tmp/ok"
for c in $CASES; do J "$c" "$tmp/ok" 2> /dev/null > "$tmp/out" || bad "accepted set of $c rejected: $(cat "$tmp/out")"; done

# ctl NAME CASE RULE-WORDS FILE CONTENT: a copy of the accepted set with one file changed; the judge must reject it naming the rule
ctl() {
    local name=$1 c=$2 words=$3 d=$tmp/ctl-$1 out rc=0
    rm -rf "$d"; cp -r "$tmp/ok" "$d"
    printf '%s' "$5" > "$d/$c.$4"
    out=$(J "$c" "$d" 2> /dev/null) || rc=$?
    [ "$rc" = 1 ] || bad "$name: not rejected (exit $rc)"
    grep -qF -- "$words" <<< "$out" || bad "$name: rejected without the words '$words': $out"
}
ctl content enable-file 'not exactly' content "${EXPECTED}extra
"
ctl mode enable-file 'mode, owner' stat '600 root:root regular file'
ctl owner enable-file 'mode, owner' stat '644 alice:alice regular file'
ctl enable-rc enable-file 'did not exit 0' rc 1
ctl accepts-wrong pam-password 'wrong password was accepted' wrong 'rc=0 fprintd=1'
ctl right-refused pam-password 'right password was refused' right 'rc=7 fprintd=1'
ctl override-ignored pam-password 'did not go through the override' right 'rc=0 fprintd=0'
ctl still-loaded pam-password 'still loaded' disabled 'rc=0 fprintd=1'
ctl twice-changed enable-twice 'manifests differ' after "$M"$'\n/etc/pam.d/polkit-1 file 644 root:root - eeee'
ctl twice-rc enable-twice 'did not exit 0' rc 1
ctl twice-empty enable-twice 'empty' before ''
for c in refuse-foreign refuse-no-vendor refuse-no-module; do
    ctl "$c-left-file" $c 'manifests differ' after "$M"$'\n/etc/pam.d/polkit-1 file 644 root:root - eeee'
    ctl "$c-accepted" $c 'did not refuse' rc 0
    ctl "$c-no-cause" $c 'does not name the cause' out 'custodio setup fingerprint: something'
done
ctl disable-extra disable-restores 'byte for byte' after "$M"$'\n/etc/pam.d/polkit-1 file 644 root:root - eeee'
ctl disable-mode disable-restores 'byte for byte' after "${M/644 root:root - bbbb/600 root:root - bbbb}"
ctl disable-agent disable-restores 'agent' agent-after '/etc/pam.d/polkit-1 file 600 root:root - cccc'
ctl disable-before-has-file disable-restores 'holds polkit-1' before "$M"$'\n/etc/pam.d/polkit-1 file 644 root:root - cccc'
ctl pau-enable-alters pam-auth-update 'altered the override' override-enabled 'ffff 644 root:root'
ctl pau-disable-alters pam-auth-update 'altered the override' override-disabled 'ffff 644 root:root'
ctl pau-no-change pam-auth-update 'did not change' common-enabled one
ctl pau-not-back pam-auth-update 'not back' common-disabled two
ctl label-wrong selinux-label 'policy default' label 'unconfined_u:object_r:user_home_t:s0'
ctl label-restorecon selinux-label 'restorecon' restorecon 'Would relabel /etc/pam.d/polkit-1'
ctl label-rc selinux-label 'did not exit 0' rc 1
ctl as-altered authselect 'altered the override' override-after 'cccc 644'
ctl as-rc authselect 'failed' rc 1
ctl as-no-act authselect 'did not act' system-after edited
ctl as-unmodified authselect 'not modified' system-modified orig
# the not-enforcing branch: accepted, and the run record must say so
d=$tmp/ne; cp -r "$tmp/ok" "$d"; printf 0 > "$d/selinux-label.enforcing"; printf 'wrong' > "$d/selinux-label.label"
J selinux-label "$d" 2> "$tmp/note" > "$tmp/out" || bad "not-enforcing branch rejected: $(cat "$tmp/out")"
grep -qF 'SELinux not enforcing here' "$tmp/note" || bad "the not-enforcing branch does not say so"
# a missing observation is a rejection
rm "$tmp/ok/enable-file.stat"; J enable-file "$tmp/ok" > "$tmp/out" 2>&1 && bad "a missing observation was accepted"
[ "$fail" = 0 ] || exit 1
echo "test-e2e-fingerprint: passed"
