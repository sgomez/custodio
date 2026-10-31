#!/usr/bin/env bash
# Self-test of lifecycle-lib.sh, run by the guest before it relies on the library and by `just test-scripts`. Each rejection has its own
# control: the check must fail AND say the expected thing; the good fixture must pass. Usage: lifecycle-selftest.sh
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/upgrade-lib.sh
source "$here/upgrade-lib.sh"
# shellcheck source=e2e/lifecycle-lib.sh
source "$here/lifecycle-lib.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0
bad() { echo "lifecycle-selftest: FAIL: $*" >&2; failures=$((failures + 1)); }
rejects() {
    local what=$1 text=$2 out
    shift 2
    if out=$("$@" 2>&1); then bad "$what: accepted"; return; fi
    grep -q -- "$text" <<< "$out" || bad "$what: rejected, but without '$text': $out"
}
accepts() { local what=$1 out; shift; out=$("$@" 2>&1) || bad "$what: rejected: $out"; }

# --- the shared directories: fixed, explicit, nothing named after custodio ---------------------------------------------------------
for d in "${SHARED_DIRS[@]}"; do
    case $d in *custodio*) bad "the shared directory $d is named after custodio" ;; esac
    [[ $d == /* ]] || bad "the shared directory '$d' is not absolute"
    [[ $d =~ [\*\?\[] ]] && bad "the shared directory '$d' is a pattern"
done
for d in /usr/lib/custodio /usr/share/doc/custodio /usr/share/licenses/custodio; do
    if is_shared_dir "$d"; then bad "$d is excused as a shared directory"; fi
done
is_shared_dir /usr/share/polkit-1/actions || bad "the polkit actions directory is not shared"

# --- the package lists, from the output of each tool -------------------------------------------------------------------------------
deb_out='drwxr-xr-x root/root 0 2026-01-01 00:00 ./
drwxr-xr-x root/root 0 2026-01-01 00:00 ./usr/
drwxr-xr-x root/root 0 2026-01-01 00:00 ./usr/lib/custodio/
-rwxr-xr-x root/root 10 2026-01-01 00:00 ./usr/lib/custodio/custodiod
lrwxrwxrwx root/root 0 2026-01-01 00:00 ./usr/lib/custodio/link -> custodiod'
[ "$(entries_from_deb <<< "$deb_out" | tr '\n' ',')" = 'd /usr,d /usr/lib/custodio,f /usr/lib/custodio/custodiod,f /usr/lib/custodio/link,' ] \
    || bad "deb entries: $(entries_from_deb <<< "$deb_out" | tr '\n' ',')"
[ "$(entries_from_rpm <<< $'-rwxr-xr-x /usr/lib/custodio/custodiod\ndrwxr-xr-x /usr/lib/custodio' | tr '\n' ',')" = 'f /usr/lib/custodio/custodiod,d /usr/lib/custodio,' ] || bad "rpm entries"
[ "$(entries_from_arch <<< $'custodio /usr/\ncustodio /usr/lib/custodio/custodiod' | tr '\n' ',')" = 'd /usr,f /usr/lib/custodio/custodiod,' ] || bad "arch entries"
[ "$(with_ancestors <<< 'f /usr/lib/custodio/custodiod' | tr '\n' ',')" = 'd /usr,d /usr/lib,d /usr/lib/custodio,f /usr/lib/custodio/custodiod,' ] || bad "ancestors: $(with_ancestors <<< 'f /usr/lib/custodio/custodiod' | tr '\n' ',')"

# a full list of the files the package must install, with their directories
full=$tmp/full.list
for p in "${REQUIRED_PATHS[@]}" /usr/share/doc/custodio/copyright /usr/share/licenses/custodio/LICENSE; do echo "f $p"; done | with_ancestors > "$full"
accepts "a full list" entries_problems "$full"
grep -v '^f /usr/lib/systemd/system/custodio.service$' "$full" > "$tmp/nounit.list"
rejects "a list without the unit" 'lacks /usr/lib/systemd/system/custodio.service' entries_problems "$tmp/nounit.list"
: > "$tmp/empty.list"
rejects "an empty list" 'no file' entries_problems "$tmp/empty.list"
grep -v '^d ' "$full" > "$tmp/nodirs.list"
rejects "a list without directories" 'no directory' entries_problems "$tmp/nodirs.list"

# --- no packaged file remains: a fixture root ---------------------------------------------------------------------------------------
root=$tmp/root
tree() { # a root that holds the shared directories and nothing of the package
    rm -rf "$root"
    local d
    for d in "${SHARED_DIRS[@]}"; do mkdir -p "$root$d"; done
}
no_owner() { return 1; }
other_owner() { [ "$1" = /usr/lib/custodio ]; } # another package owns this directory
tree
accepts "a clean tree" leftover_problems "$full" no_owner "$root"
tree
touch "$root/usr/lib/systemd/system/custodio.service"
rejects "one file left" 'leftover: file /usr/lib/systemd/system/custodio.service' leftover_problems "$full" no_owner "$root"
tree
ln -s /nowhere "$root/usr/share/doc/custodio"
rejects "a dangling link left" 'leftover: directory /usr/share/doc/custodio' leftover_problems "$full" no_owner "$root"
tree
mkdir -p "$root/usr/lib/custodio"
rejects "only a directory left" 'leftover: directory /usr/lib/custodio' leftover_problems "$full" no_owner "$root"
tree
mkdir -p "$root/usr/share/doc/custodio" "$root/usr/share/licenses/custodio"
rejects "the doc directory left" 'leftover: directory /usr/share/doc/custodio' leftover_problems "$full" no_owner "$root"
rejects "the licenses directory left" 'leftover: directory /usr/share/licenses/custodio' leftover_problems "$full" no_owner "$root"
tree
mkdir -p "$root/usr/lib/custodio"
accepts "a directory that another package owns" leftover_problems "$full" other_owner "$root"
tree
mkdir -p "$root/usr/lib/custodio"
touch "$root/usr/lib/custodio/custodiod"
rejects "a file under a directory that another package owns" 'leftover: file /usr/lib/custodio/custodiod' leftover_problems "$full" other_owner "$root"
tree
rejects "a list that lacks the files" 'no file' leftover_problems "$tmp/empty.list" no_owner "$root"

# --- the service ----------------------------------------------------------------------------------------------------------------------
proc=$tmp/proc
mkdir -p "$proc/100"
accepts "stopped" stopped_problems inactive 0 "$tmp/none" 100
accepts "failed is not active" stopped_problems failed 0 "$tmp/none" 100
rejects "an active unit" 'still active' stopped_problems active 0 "$tmp/none" 100
rejects "a main pid" 'main pid' stopped_problems inactive 555 "$tmp/none" 100
rejects "the old pid alive" 'still there' stopped_problems inactive 0 "$proc" 100
accepts "running" running_problems active 100
rejects "inactive before the removal" 'not active' running_problems inactive 100
rejects "no main pid" 'no main pid' running_problems active 0
rejects "an empty main pid" 'no main pid' running_problems active ''
accepts "not active before the first call" not_active_problems inactive
rejects "an active unit before the first call" 'would prove nothing' not_active_problems active

# --- activation -----------------------------------------------------------------------------------------------------------------------
printf 'org.freedesktop.systemd1 (activatable) - -\ncom.rfirma.Custodio1 (activatable) - -\n' > "$tmp/act.yes"
printf 'org.freedesktop.systemd1 (activatable) - -\n' > "$tmp/act.no"
accepts "the name is activatable" activatable_problems "$tmp/act.yes"
rejects "the name is not activatable before" 'not in the list' activatable_problems "$tmp/act.no"
err='Call failed: The name is not activatable'
accepts "not activatable" not_activatable_problems "$tmp/act.no" 1 "$err" ''
accepts "ServiceUnknown" not_activatable_problems "$tmp/act.no" 1 'org.freedesktop.DBus.Error.ServiceUnknown' ''
rejects "a listing that still holds the name" 'still in the list' not_activatable_problems "$tmp/act.yes" 1 "$err" ''
rejects "a call that succeeded" 'succeeded' not_activatable_problems "$tmp/act.no" 0 '' ''
rejects "a call that failed for another reason" 'not with a no-such-service error' not_activatable_problems "$tmp/act.no" 1 'Failed to connect to bus' ''
rejects "a process that exists" 'custodiod process exists' not_activatable_problems "$tmp/act.no" 1 "$err" '1234'

# --- the state directory and the account ----------------------------------------------------------------------------------------------
st=$tmp/state
mkdir -p "$st/keys"
printf 'key one\n' > "$st/keys/a.p12"
printf 'key two\n' > "$st/keys/b.p12"
snapshot_state "$st" > "$tmp/state.before"
accepts "the state directory unchanged" state_problems "$st" "$tmp/state.before" "$tmp/state.after"
printf 'key onE\n' > "$st/keys/a.p12"
rejects "a changed key file" 'content changed' state_problems "$st" "$tmp/state.before" "$tmp/state.after"
printf 'key one\n' > "$st/keys/a.p12"
ln -s "$st" "$tmp/link"
accepts "through a link" state_problems "$tmp/link" "$tmp/state.before" "$tmp/state.after"
rm -rf "$st"
rejects "the state directory gone" 'is gone' state_problems "$tmp/link" "$tmp/state.before" "$tmp/state.after"
rejects "the state directory never there" 'is gone' state_problems "$tmp/nowhere" "$tmp/state.before" "$tmp/state.after"
line='custodio:x:990:990::/var/lib/custodio:/usr/sbin/nologin'
accepts "the account kept" account_problems "$line" "$line"
rejects "the account gone" 'is gone' account_problems "$line" ''
rejects "another uid" 'uid:gid was 990:990 and is 991:990' account_problems "$line" 'custodio:x:991:990::/var/lib/custodio:/usr/sbin/nologin'
rejects "another gid" 'uid:gid' account_problems "$line" 'custodio:x:990:5::/var/lib/custodio:/usr/sbin/nologin'
rejects "no entry before" 'no entry was recorded' account_problems '' "$line"

# --- the notice ------------------------------------------------------------------------------------------------------------------------
good_notice() {
    echo 'custodio: the signing keys are still on disk in /var/lib/custodio (the real directory is /var/lib/private/custodio).'
    echo 'custodio: deleting that directory by hand destroys the keys for good; they cannot be exported or recreated.'
}
good_notice > "$tmp/notice.good"
accepts "a good notice" notice_problems "$tmp/notice.good"
: > "$tmp/notice.empty"
rejects "an empty capture" 'is empty' notice_problems "$tmp/notice.empty"
echo 'custodio: the keys are still on disk in /var/lib/custodio.' > "$tmp/notice.nowarn"
rejects "the path without the warning" 'lacks the warning' notice_problems "$tmp/notice.nowarn"
echo 'custodio: deleting by hand destroys the keys for good.' > "$tmp/notice.nopath"
rejects "the warning without the path" 'does not name /var/lib/custodio' notice_problems "$tmp/notice.nopath"
echo 'Removing custodio (0.1.1-1) ... /var/lib/custodio destroys the keys for good' > "$tmp/notice.nodisk"
rejects "no word that the keys stay" 'still on disk' notice_problems "$tmp/notice.nodisk"
# the phrase is the one the maintainer scripts print on all three targets
for f in packaging/deb/postrm packaging/rpm/postun packaging/arch/post_remove; do
    if [ -f "$here/../$f" ]; then grep -qF 'destroys the keys for good' "$here/../$f" || bad "$f does not print the phrase the case checks"; fi
done

# --- the package database ---------------------------------------------------------------------------------------------------------------
accepts "removed" removed_problems not-installed remove
accepts "removed, deb configuration kept" removed_problems config-files remove
rejects "still installed after the removal" 'is .installed' removed_problems installed remove
rejects "configuration left after a purge" "config-files" removed_problems config-files purge
rejects "still installed after a purge" 'installed' removed_problems installed purge
accepts "reinstalled" installed_problems installed 0.1.1-1 0.1.1-1
rejects "not installed after the reinstall" 'not-installed' installed_problems not-installed '' 0.1.1-1
rejects "another version after the reinstall" 'not 0.1.1-1' installed_problems installed 0.1.0-1 0.1.1-1

# --- no import, no manual start or stop ------------------------------------------------------------------------------------------------------
sect=$tmp/sect.sh
mkdir -p "$tmp/bad"
mk() { printf '# BEGIN lifecycle-case\n%s\n# END lifecycle-case\n' "$1" > "$sect"; }
printf '#!/bin/sh\napt-get remove -y custodio\n' > "$tmp/remove.sh"
# shellcheck disable=SC2016 # the fixture holds a literal "$1"
printf '#!/bin/sh\napt-get install -y "$1"\n' > "$tmp/install.sh"
mk 'bash remove.sh
systemctl is-active custodio
systemctl show -p MainPID custodio
pgrep -x custodiod'
accepts "a clean section and clean scripts" lifecycle_static_problems "$sect" "$tmp/remove.sh" "$tmp/install.sh"
accepts "the library itself" lifecycle_static_problems "$sect" "$here/lifecycle-lib.sh"
for c in 'python3 -I /e2e/import.py a.p12 rsa1 pw' 'custodio import a.p12' 'pkcs11-tool --module m --write-object k --type privkey' 'systemctl start custodio' 'systemctl restart custodio' \
    'systemctl stop custodio' 'systemctl --no-block try-restart custodio' 'systemctl daemon-reload' 'systemctl reload dbus' 'systemctl kill custodio' 'pkill custodiod' 'killall custodiod' 'kill 123' 'service custodio start'; do
    mk "$c"
    rejects "'$c' in the section" 'by hand' lifecycle_static_problems "$sect" "$tmp/remove.sh"
    printf '#!/bin/sh\n%s\napt-get remove -y custodio\n' "$c" > "$tmp/remove.bad"
    mv "$tmp/remove.bad" "$tmp/bad/remove.sh"
    mk 'ls'
    rejects "'$c' in remove.sh" 'remove.sh imports' lifecycle_static_problems "$sect" "$tmp/bad/remove.sh"
    cp "$tmp/bad/remove.sh" "$tmp/bad/install.sh"
    rejects "'$c' in install.sh" 'install.sh imports' lifecycle_static_problems "$sect" "$tmp/bad/install.sh"
done
mk '# systemctl stop custodio is not run here
ls'
accepts "a comment that names a stop" lifecycle_static_problems "$sect" "$tmp/remove.sh"
printf '#!/bin/sh\n# pkill custodiod\napt-get remove -y custodio\n' > "$tmp/remove.sh"
accepts "a comment in remove.sh" lifecycle_static_problems "$sect" "$tmp/remove.sh"
printf '#!/bin/sh\napt-get remove -y custodio > /dev/null 2>&1\n' > "$tmp/bad/remove.sh"
rejects "remove.sh that discards the output" 'throws output away' lifecycle_static_problems "$sect" "$tmp/bad/remove.sh"
printf '#!/bin/sh\napt-get purge -y custodio > /dev/null\n' > "$tmp/bad/purge.sh"
rejects "purge.sh that discards the output" 'throws output away' lifecycle_static_problems "$sect" "$tmp/bad/purge.sh"
printf 'ls\n' > "$tmp/outside.sh"
rejects "no markers" 'BEGIN and one END' lifecycle_static_problems "$tmp/outside.sh" "$tmp/remove.sh"
printf '# BEGIN lifecycle-case\n# END lifecycle-case\n' > "$tmp/emptysect.sh"
rejects "an empty section" 'is empty' lifecycle_static_problems "$tmp/emptysect.sh" "$tmp/remove.sh"
printf '# BEGIN lifecycle-case\nls\n' > "$tmp/noend.sh"
rejects "a missing END marker" 'BEGIN and one END' lifecycle_static_problems "$tmp/noend.sh" "$tmp/remove.sh"
rejects "a missing file" 'does not exist' lifecycle_static_problems "$sect" "$tmp/none.sh"
: > "$tmp/emptyfile.sh"
rejects "an empty script" 'is empty' lifecycle_static_problems "$sect" "$tmp/emptyfile.sh"
# the real case: its section and the scripts it calls
tdirs=("$here"/targets/*/)
real=("$here/lifecycle-lib.sh")
for d in "${tdirs[@]}"; do [ -f "${d}remove.sh" ] || continue; real+=("${d}install.sh" "${d}remove.sh"); [ ! -f "${d}purge.sh" ] || real+=("${d}purge.sh"); done
[ -f "$here/lifecycle.sh" ] && { accepts "the real lifecycle case" lifecycle_static_problems "$here/lifecycle.sh" "${real[@]}"; }
# the real section runs the tool of the target, not an import
if [ -f "$here/lifecycle.sh" ]; then
    sed -n '/^# BEGIN lifecycle-case$/,/^# END lifecycle-case$/p' "$here/lifecycle.sh" | grep -q 'cycle remove' || bad "the real section does not run a removal script"
fi

[ "$failures" -eq 0 ] || exit 1
echo "lifecycle-selftest: passed"
