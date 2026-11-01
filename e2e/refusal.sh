#!/usr/bin/env bash
# The refusal case of F50, run by guest.sh on a target with a `refusal-only` marker (Ubuntu 24.04 on dbus-daemon): the package must refuse to install
# on a bus without ProcessFD, and leave nothing behind. Usage: refusal.sh PACKAGE. Reports the refusal-* cases (report.sh). The package's own check does
# the refusing: this file only installs, looks, and compares (refusal-static.sh forbids stopping, starting or removing anything).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/refusal-lib.sh
source "$here/refusal-lib.sh"
# shellcheck source=e2e/refusal-static.sh
source "$here/refusal-static.sh"
die() { echo "e2e: FAIL: refusal: $*" >&2; exit 1; }
# need ID MESSAGES...: the case passes when the messages are empty
need() { local id=$1; shift; if [ -n "$*" ]; then die "$id: $*"; fi; case_run "$id"; }
pkg=$1
work=$(mktemp -d /tmp/refusal.XXXXXX)
static_problems "$here/refusal.sh" "$here/refusal-lib.sh" /e2e-target/install.sh > "$work/static" || die "the refusal case does more than install and look: $(cat "$work/static")"

# BEGIN refusal-case
package_files "$pkg" > "$work/files"
[ -z "$(list_problems "$work/files")" ] || die "package list: $(list_problems "$work/files")"
# The bus is up and lacks ProcessFD before the install (asked with a call written here, not with the package's own check).
state=$(systemctl is-system-running 2> /dev/null || true)
case $state in running | degraded) ;; *) die "the system is $state" ;; esac
systemctl is-active --quiet dbus || die "dbus.service is not active"
rc=0
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionCredentials s org.freedesktop.DBus > "$work/creds" 2>&1 || rc=$?
need refusal-bus-lacks-processfd "$(precondition_problems "$rc" "$work/creds")"
getent passwd custodio > /dev/null && account_before=yes || account_before=no
# The install, with the tool of the target; its status and output come back here.
rc=0
bash /e2e-target/install.sh "$pkg" > "$work/install.out" 2>&1 || rc=$?
echo "e2e: install exit status $rc; output:"
sed 's/^/e2e:   /' "$work/install.out"
need refusal-install-fails-naming-processfd "$(install_problems "$rc" "$work/install.out")"
need refusal-no-custodio-file "$(files_problems "" "$work/files")"
st=$(dpkg-query -W -f '${db:Status-Status}' custodio 2> /dev/null) || st=absent
dpkg --audit > "$work/audit" 2>&1 || true
echo "e2e: dpkg status of custodio: $st"
need refusal-dpkg-not-configured "$(status_problems "$st"; audit_problems "$work/audit")"
busctl --system list --no-pager > "$work/names" 2>&1 || true
busctl --system list --activatable --no-pager > "$work/activatable" 2>&1 || true
rc=0
busctl --system call "$BUS_NAME" /com/rfirma/Custodio1 org.freedesktop.DBus.Peer Ping > "$work/call" 2>&1 || rc=$?
pids=$(pgrep -x custodiod || true)
cat_rc=0
systemctl cat custodio > /dev/null 2>&1 || cat_rc=$?
active=$(systemctl is-active custodio 2> /dev/null || true)
need refusal-nothing-listens "$(listing_problems owned "$work/names"; listing_problems activatable "$work/activatable"; call_problems "$rc" "$work/call"; process_problems "$pids"; unit_problems "$cat_rc" "$active")"
getent passwd custodio > /dev/null && account_after=yes || account_after=no
echo "e2e: custodio account before: $account_before, after: $account_after"
# END refusal-case
