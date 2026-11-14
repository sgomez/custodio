# shellcheck shell=bash
# Sourced by e2e/vm/snap.sh (the snap-* cases, F179, acceptances 17 and 18 of SPEC.md) and by scripts/test-e2e-vm-snap.sh, which runs it on fixtures and with stubs.
# snap_problems CASE DIR: the problems of a case (judged by snap.py from the evidence in DIR); a judge that cannot run is a problem, not an empty answer.
# The test profile of the other-snap case: loaded with apparmor_parser, unloaded on every exit (success, a failing judge, a signal).
# Overridable for the self-test: SN_E2E (where snap.py is), SN_PARSER (apparmor_parser), SN_PROFILE (the profile file).
SN_E2E=${SN_E2E:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
SN_PARSER=${SN_PARSER:-apparmor_parser}
SN_PROFILE=${SN_PROFILE:-$SN_E2E/snap-other.profile}
SN_LOADED=''

snap_problems() {
    local o
    o=$(python3 -I "$SN_E2E/snap.py" "$1" "$2" 2>&1) || o="the judge snap.py failed for $1: $o"
    printf '%s\n' "$o" | sed '/^$/d'
}

# snap_profile_load: enforce mode, replacing any earlier load
snap_profile_load() {
    "$SN_PARSER" -r "$SN_PROFILE" || return 1
    SN_LOADED=1
}
snap_profile_unload() {
    [ -n "$SN_LOADED" ] || return 0
    "$SN_PARSER" -R "$SN_PROFILE" || return 1
    SN_LOADED=''
}
snap_on_exit() {
    local rc=$?
    trap - EXIT
    if declare -F snap_extra_cleanup > /dev/null; then snap_extra_cleanup || true; fi
    snap_profile_unload || { echo "snap: FAIL: the test profile could not be unloaded" >&2; [ "$rc" -ne 0 ] || rc=1; }
    exit "$rc"
}
snap_install_trap() {
    trap snap_on_exit EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    trap 'exit 129' HUP
}

# ---- the snap in the guest (run by e2e/vm/run.sh through the guest's shell, as root)
# snap_preconditions: what the image must give (F171): AppArmor enabled and snapd's socket active. Asserted, nothing is installed from the archive.
snap_preconditions() {
    [ "$(cat /sys/module/apparmor/parameters/enabled 2> /dev/null)" = Y ] || { echo "snap: AppArmor is not enabled in the guest" >&2; return 1; }
    systemctl is-active --quiet snapd.socket || { echo "snap: snapd.socket is not active in the guest" >&2; return 1; }
}
# snap_start_install: starts the install of the Firefox snap from stable (snapd checks the signed assertions itself) as a transient unit and returns at once, so that
# the install overlaps with the setup; the hold keeps a refresh from changing the revision under the run (F171: no cache by revision)
snap_start_install() {
    snap_preconditions || return 1
    systemd-run --quiet --unit=e2e-snap-install -p Type=oneshot -p RemainAfterExit=yes --no-block \
        bash -c 'snap install firefox && snap refresh --hold firefox' || return 1
}
# snap_wait_install SECONDS: waits on the unit's state (never a fixed sleep) and fails with the log when it did not end well
snap_wait_install() {
    local i st
    for ((i = 0; i < ${1:-900}; i++)); do
        st=$(systemctl show -p ActiveState --value e2e-snap-install)
        [ "$st" = activating ] || break
        sleep 1
    done
    if [ "$(systemctl show -p Result --value e2e-snap-install)" != success ] || [ "$st" = activating ]; then
        journalctl -u e2e-snap-install --no-pager | tail -n 15 >&2
        echo "snap: the install of firefox did not finish (state $st)" >&2
        return 1
    fi
}
