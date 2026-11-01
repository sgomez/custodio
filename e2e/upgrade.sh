#!/usr/bin/env bash
# The upgrade case (F48, F60), run as root by guest.sh from the state the earlier steps left: keys imported with the old package,
# custodio.service running. Installs the new package with the target's own install.sh and checks that the key files, the key listing,
# polkit and the running service survived. Usage: upgrade.sh PKG_FROM PKG_TO [ID_PREFIX] (needs WORK and MODULE).
#   F48: PKG_FROM is package N, PKG_TO is N+1 (the same tree, only the version raised), ID_PREFIX is "upgrade" (the default).
#   F60: PKG_FROM is the last cargo-deb .deb, PKG_TO is N+1, ID_PREFIX is "upgrade-cargo-deb".
#   F61: PKG_FROM is the current package with the daemon at the old path (scripts/package-oldpath.sh), ID_PREFIX is "upgrade-oldpath".
# E2E_INSTALL overrides the install step (the self-test of the case uses it to see that it is never reached).
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/upgrade-lib.sh
source "$here/upgrade-lib.sh"
: "${WORK:?}" "${MODULE:?}"
[ $# -eq 2 ] || [ $# -eq 3 ] || fail "usage: upgrade.sh PKG_FROM PKG_TO [ID_PREFIX]"
pkg=$1
next=$2
id=${3:-upgrade}
[[ $id =~ ^upgrade(-[a-z0-9]+)*$ ]] || fail "bad case id prefix '$id'"
install=${E2E_INSTALL:-/e2e-target/install.sh}
if [ ! -f "$pkg" ] || [ ! -f "$next" ] || [ "$pkg" = "$next" ]; then fail "the old and the new package must be two package files"; fi
fmt=$(pkg_format "$next")
[ "$(pkg_format "$pkg")" = "$fmt" ] || fail "the old and the new package are not in the same format"

# The checks come first; a broken comparison would make the case worthless. (E2E_NO_SELFTEST is for the tests of this script, which
# run the self-test on its own.)
[ -n "${E2E_NO_SELFTEST:-}" ] || bash "$here/upgrade-selftest.sh" "$fmt" || fail "the upgrade self-test failed"
manual_step_problems "$here/upgrade.sh" || fail "the upgrade case runs a manual step (see above)"

user_run() { su -l alice -c "WORK=$WORK MODULE=$MODULE bash /e2e/upgrade-user.sh $1"; }

# BEGIN upgrade-case
vn=$(pkg_file_version "$fmt" "$pkg")
vn1=$(pkg_file_version "$fmt" "$next")
# The new package must be strictly greater than the old one by the target's own tool, before anything is installed.
upgrade_gate "$fmt" "$pkg" "$next" || fail "the upgrade gate refused the pair (see above); nothing was installed"
case_run "$id-version-greater"

# Before: the service runs, and runs the installed file (device:inode; N+1 has the same content as N, so a hash cannot tell them apart).
systemctl is-active --quiet custodio || fail "custodio.service was not running before the upgrade"
pid1=$(systemctl show -p MainPID --value custodio)
[ "$pid1" -gt 0 ] || fail "custodio.service has no main pid before the upgrade"
bin1=$(unit_binary "$(unit_file)") || fail "cannot read the executable of the unit before the upgrade"
exe_problems /proc "$pid1" "$bin1" || fail "before the upgrade the service does not run the installed file"
id1=$(stat -L -c '%d:%i' "/proc/$pid1/exe")
snapshot_state "$STATE_LINK" > "$WORK/state.before"
user_run list > "$WORK/listing.before" || fail "the key listing before the upgrade failed"
uid1=$(id -u custodio):$(id -g custodio)
echo "e2e: upgrade: before: version $vn, pid $pid1, executable $bin1 device:inode $id1, $(grep -c '^f ' "$WORK/state.before") state files"

bash "$install" "$next" || fail "$(basename "$next") could not be installed with install.sh"
echo "e2e: upgrade: installed $(basename "$next") with $install, nothing else was run"

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
bin2=$(unit_binary "$(unit_file)") || fail "cannot read the executable of the unit after the upgrade"
[ "$bin2" = "$(daemon_path "$fmt")" ] || fail "after the upgrade the unit starts $bin2, not $(daemon_path "$fmt"), the daemon of this package"
if [ "$id" = upgrade-oldpath ]; then oldpath_problems "$bin1" "$bin2" || fail "the upgrade from the old path did not move the service (see above)"; fi
service_problems /proc "$pid1" "$pid2" "$bin2" || fail "the service does not run the new binary"
id2=$(stat -L -c '%d:%i' "/proc/$pid2/exe")
echo "e2e: upgrade: after: version $vn1, pid $pid2, executable $bin2 device:inode $id2 (the installed file's), old pid $pid1 gone or deleted"
case_run "$id-service-new-binary"

snapshot_state "$STATE_LINK" > "$WORK/state.after"
compare_state "$WORK/state.before" "$WORK/state.after" || fail "the key files changed in the upgrade (see above)"
[ "$uid1" = "$(id -u custodio):$(id -g custodio)" ] || fail "the uid or gid of the custodio account changed"
echo "e2e: upgrade: the state directory is identical: $(grep -c . "$WORK/state.after") entries with sha256, owner and mode"
case_run "$id-state-unchanged"

user_run list > "$WORK/listing.after" || fail "the key listing after the upgrade failed"
compare_listing "$WORK/listing.before" "$WORK/listing.after" || fail "the keys listed after the upgrade differ (see above)"
case_run "$id-keys-listed"

user_run sign || fail "signing after the upgrade failed"
case_run "$id-signs-with-polkit"
# END upgrade-case
case_run "$id-no-manual-step"
