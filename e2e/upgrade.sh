#!/usr/bin/env bash
# The upgrade case (F48), run as root by guest.sh after all other cases, from the state they left: keys imported with package N,
# custodio.service running. Installs package N+1 (the same tree, only the version raised) with the target's own install.sh and checks
# that the key files, the key listing, polkit and the running service survived. Usage: upgrade.sh PKG_N PKG_N1 (needs WORK and MODULE).
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/upgrade-lib.sh
source "$here/upgrade-lib.sh"
: "${WORK:?}" "${MODULE:?}"
[ $# -eq 2 ] || fail "usage: upgrade.sh PKG_N PKG_N1"
pkg=$1
next=$2
if [ ! -f "$pkg" ] || [ ! -f "$next" ] || [ "$pkg" = "$next" ]; then fail "N and N+1 must be two package files"; fi
fmt=$(pkg_format "$next")
[ "$(pkg_format "$pkg")" = "$fmt" ] || fail "N and N+1 are not in the same format"

# The checks come first; a broken comparison would make the case worthless.
bash "$here/upgrade-selftest.sh" "$fmt" || fail "the upgrade self-test failed"
manual_step_problems "$here/upgrade.sh" || fail "the upgrade case runs a manual step (see above)"

user_run() { su -l alice -c "WORK=$WORK MODULE=$MODULE bash /e2e/upgrade-user.sh $1"; }

# BEGIN upgrade-case
vn=$(pkg_file_version "$fmt" "$pkg")
vn1=$(pkg_file_version "$fmt" "$next")
[ "$(installed_version "$fmt")" = "$vn" ] || fail "before the upgrade the database holds $(installed_version "$fmt"), not N=$vn"
[ "$vn" != "$vn1" ] || fail "N and N+1 have the same version ($vn)"
# N+1 must be strictly greater than N by the target's own tool, before it is installed.
version_greater "$fmt" "$vn1" "$vn" || fail "N+1 ($vn1) is not greater than N ($vn) by $(version_tool "$fmt")"
echo "e2e: upgrade: $(version_tool "$fmt") says N+1=$vn1 is greater than N=$vn"
case_run "upgrade-version-greater"

# Before: the service runs, and runs the installed file (device:inode; N+1 has the same content as N, so a hash cannot tell them apart).
systemctl is-active --quiet custodio || fail "custodio.service was not running before the upgrade"
pid1=$(systemctl show -p MainPID --value custodio)
[ "$pid1" -gt 0 ] || fail "custodio.service has no main pid before the upgrade"
exe_problems /proc "$pid1" "$INSTALLED_BINARY" || fail "before the upgrade the service does not run the installed file"
id1=$(stat -L -c '%d:%i' "/proc/$pid1/exe")
snapshot_state "$STATE_LINK" > "$WORK/state.before"
user_run list > "$WORK/listing.before" || fail "the key listing before the upgrade failed"
uid1=$(id -u custodio):$(id -g custodio)
echo "e2e: upgrade: before: version $vn, pid $pid1, executable device:inode $id1, $(grep -c '^f ' "$WORK/state.before") state files"

bash /e2e-target/install.sh "$next" || fail "N+1 could not be installed with install.sh"
echo "e2e: upgrade: installed $(basename "$next") with /e2e-target/install.sh, nothing else was run"

# After: wait (reading state only) for the service to be up with a new main pid.
pid2=$pid1
for _ in $(seq 60); do
    pid2=$(systemctl show -p MainPID --value custodio)
    if [ "$pid2" -gt 0 ] && [ "$pid2" != "$pid1" ] && systemctl is-active --quiet custodio; then break; fi
    sleep 1
done
sleep 5
[ "$(systemctl show -p MainPID --value custodio)" = "$pid2" ] || fail "the main pid changed again after the upgrade (not $pid2): the service keeps restarting"
systemctl is-active --quiet custodio || fail "custodio.service is not active after the upgrade"
[ "$(installed_version "$fmt")" = "$vn1" ] || fail "after the upgrade the database holds $(installed_version "$fmt"), not N+1=$vn1"
service_problems /proc "$pid1" "$pid2" "$INSTALLED_BINARY" || fail "the service does not run the new binary"
id2=$(stat -L -c '%d:%i' "/proc/$pid2/exe")
echo "e2e: upgrade: after: version $vn1, pid $pid2, executable device:inode $id2 (the installed file's), old pid $pid1 gone or deleted"
case_run "upgrade-service-new-binary"

snapshot_state "$STATE_LINK" > "$WORK/state.after"
compare_state "$WORK/state.before" "$WORK/state.after" || fail "the key files changed in the upgrade (see above)"
[ "$uid1" = "$(id -u custodio):$(id -g custodio)" ] || fail "the uid or gid of the custodio account changed"
echo "e2e: upgrade: the state directory is identical: $(grep -c . "$WORK/state.after") entries with sha256, owner and mode"
case_run "upgrade-state-unchanged"

user_run list > "$WORK/listing.after" || fail "the key listing after the upgrade failed"
compare_listing "$WORK/listing.before" "$WORK/listing.after" || fail "the keys listed after the upgrade differ (see above)"
case_run "upgrade-keys-listed"

user_run sign || fail "signing after the upgrade failed"
case_run "upgrade-signs-with-polkit"
# END upgrade-case
case_run "upgrade-no-manual-step"
