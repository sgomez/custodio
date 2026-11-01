#!/usr/bin/env bash
# The removal, purge and reinstall cases (F49), run as root by guest.sh after the upgrade case, from the state it leaves: package N+1 installed,
# the two keys imported, custodio.service running. Removes the package with the target's own tool (/e2e-target/remove.sh; on the deb targets also
# purge.sh), checks what the removal left, installs N+1 again with install.sh and checks that the same keys are listed and sign.
# Usage: lifecycle.sh PKG_NEXT (needs WORK and MODULE). E2E_TARGET_DIR overrides /e2e-target (the tests of this script).
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/upgrade-lib.sh
source "$here/upgrade-lib.sh"
# shellcheck source=e2e/lifecycle-lib.sh
source "$here/lifecycle-lib.sh"
: "${WORK:?}" "${MODULE:?}"
[ $# -eq 1 ] || fail "usage: lifecycle.sh PKG_NEXT"
next=$1
tdir=${E2E_TARGET_DIR:-/e2e-target}
[ -f "$next" ] || fail "$next is not a package file"
fmt=$(pkg_format "$next")

# The checks come first; a broken check would make the case worthless.
[ -n "${E2E_NO_SELFTEST:-}" ] || bash "$here/lifecycle-selftest.sh" || fail "the lifecycle self-test failed"
scripts=("$tdir/install.sh" "$tdir/remove.sh" "$here/lifecycle-lib.sh")
[ ! -f "$tdir/purge.sh" ] || scripts+=("$tdir/purge.sh")
lifecycle_static_problems "$here/lifecycle.sh" "${scripts[@]}" || fail "the lifecycle case imports a key or starts or stops something by hand (see above)"

user_run() { su -l alice -c "WORK=$WORK MODULE=$MODULE bash /e2e/upgrade-user.sh $1"; }
state() { systemctl is-active custodio 2> /dev/null || true; }
mainpid() { systemctl show -p MainPID --value custodio; }
activatable() { busctl --system list --activatable --no-legend --no-pager > "$1"; }
account() { getent passwd custodio || true; }

# BEGIN lifecycle-case
vn1=$(pkg_file_version "$fmt" "$next")
packaged_entries "$fmt" "$next" > "$WORK/packaged.list"
entries_problems "$WORK/packaged.list" "$fmt" || fail "the package file lists too little (see above)"
echo "e2e: lifecycle: $(grep -c '^f ' "$WORK/packaged.list") files and $(grep -c '^d ' "$WORK/packaged.list") directories in $(basename "$next")"

# Before: N+1 installed, the service running, the name activatable; what must survive is recorded.
[ "$(db_status "$fmt")" = installed ] || fail "the package is not installed before the removal"
[ "$(installed_version "$fmt")" = "$vn1" ] || fail "the database holds $(installed_version "$fmt") before the removal, not N+1=$vn1"
running_problems "$(state)" "$(mainpid)" || fail "the service was not running before the removal (see above)"
activatable "$WORK/activatable.before"
activatable_problems "$WORK/activatable.before" || fail "before the removal (see above)"
snapshot_state "$STATE_LINK" > "$WORK/lc-state.before"
user_run list > "$WORK/lc-listing.before" || fail "the key listing before the removal failed"
account > "$WORK/lc-account.before"
[ -s "$WORK/lc-account.before" ] || fail "no custodio account before the removal"
echo "e2e: lifecycle: before: version $vn1, pid $(mainpid), $(grep -c '^f ' "$WORK/lc-state.before") state files, account $(cut -d: -f1,3,4 "$WORK/lc-account.before")"

# cycle KIND TOOL PREFIX AFTER_PREFIX: removes with TOOL, checks, installs N+1 again, checks. KIND is remove or purge.
cycle() {
    local kind=$1 tool=$2 p=$3 ap=$4 pid status
    pid=$(mainpid)
    running_problems "$(state)" "$pid" || fail "the service was not running before the $kind (see above)"
    # the output of the tool is captured, scriptlets included, and shown
    bash "$tool" > "$WORK/$kind.out" 2>&1 || { tail -n 20 "$WORK/$kind.out" >&2; fail "$tool failed"; }
    sed "s/^/e2e: $kind output: /" "$WORK/$kind.out" | tail -n 25
    status=$(db_status "$fmt")
    echo "e2e: lifecycle: after the $kind the database says $status; $(db_leftovers "$fmt")"
    removed_problems "$status" "$kind" || fail "(see above)"

    stopped_problems "$(state)" "$(mainpid)" /proc "$pid" || fail "the service is not stopped after the $kind (see above)"
    echo "e2e: lifecycle: after the $kind: ActiveState $(state), MainPID $(mainpid), pid $pid gone"
    case_run "$p-service-stopped"

    leftover_problems "$WORK/packaged.list" "owner_of $fmt" || fail "files remain after the $kind (see above)"
    echo "e2e: lifecycle: after the $kind none of the $(grep -c '^f ' "$WORK/packaged.list") files and no directory of the package remains"
    case_run "$p-no-packaged-files"

    activatable "$WORK/activatable.$kind"
    set +e
    call=$(busctl --system call "$BUS_NAME" /com/rfirma/Custodio1 org.freedesktop.DBus.Peer Ping 2>&1)
    rc=$?
    set -e
    not_activatable_problems "$WORK/activatable.$kind" "$rc" "$call" "$(pgrep -x custodiod || true)" || fail "$BUS_NAME is still activatable after the $kind (see above)"
    echo "e2e: lifecycle: after the $kind $BUS_NAME is not activatable: ${call%%$'\n'*}"
    case_run "$p-not-activatable"

    state_problems "$STATE_LINK" "$WORK/lc-state.before" "$WORK/lc-state.$kind" || fail "the state directory changed in the $kind (see above)"
    echo "e2e: lifecycle: after the $kind the state directory is identical: $(grep -c . "$WORK/lc-state.$kind") entries"
    case_run "$p-state-unchanged"

    account > "$WORK/lc-account.$kind"
    account_problems "$(cat "$WORK/lc-account.before")" "$(cat "$WORK/lc-account.$kind")" || fail "the custodio account changed in the $kind (see above)"
    case_run "$p-account-kept"

    notice_problems "$WORK/$kind.out" || fail "the output of the $kind does not say where the keys are (see above)"
    case_run "$p-notice-keys"

    # Reinstall. Nothing starts the service but the first call below: it must not be active right after the install.
    bash "$tdir/install.sh" "$next" || fail "$(basename "$next") could not be installed again after the $kind"
    installed_problems "$(db_status "$fmt")" "$(installed_version "$fmt" 2> /dev/null || true)" "$vn1" || fail "(see above)"
    activatable "$WORK/activatable.again"
    activatable_problems "$WORK/activatable.again" || fail "after the reinstall (see above)"
    not_active_problems "$(state)" || fail "(see above)"
    user_run list > "$WORK/lc-listing.$kind" || fail "the key listing after the reinstall failed"
    running_problems "$(state)" "$(mainpid)" || fail "the first call after the reinstall did not activate the service (see above)"
    compare_listing "$WORK/lc-listing.before" "$WORK/lc-listing.$kind" || fail "the keys listed after the reinstall differ (see above)"
    state_problems "$STATE_LINK" "$WORK/lc-state.before" "$WORK/lc-state.again" || fail "the state directory changed in the reinstall (see above)"
    echo "e2e: lifecycle: reinstalled $vn1 after the $kind; the first call activated the service (pid $(mainpid)); the same keys are listed"
    case_run "$ap-keys-listed"

    user_run sign || fail "signing after the reinstall failed"
    case_run "$ap-signs-with-polkit"
    case_run "$ap-no-import"
}

cycle remove "$tdir/remove.sh" removal reinstall
if [ -f "$tdir/purge.sh" ]; then
    cycle purge "$tdir/purge.sh" purge reinstall-after-purge
fi
# END lifecycle-case
