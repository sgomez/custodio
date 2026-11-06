#!/usr/bin/env bash
# The install scripts and the restart hook of the Arch package under the real pacman (F58), in the Arch image of the F42 test (pinned base, rootless
# podman or docker; scripts/test-install-real.sh builds the image). Every scenario runs in a fresh container. Its systemctl, journalctl,
# systemd-detect-virt, systemd-notify and systemd-sysusers are stand-ins (scripts/lib/arch-real-stubs.sh) that log every call with a sequence number, the
# parent command line (the script or hook that made the call: `. .INSTALL; pre_install` or `systemd-hook daemon-reload-system`) and whether the unit
# file and the bus policy exist at that moment; the real hooks of systemd and dbus run on top of them (the stand-ins answer "booted, not a chroot" so
# that the hooks do not skip). systemd-sysusers records whether the policy was unpacked and then runs the real tool. The bus is the stub bus of the
# F42 tests (with or without ProcessFD) on a bound socket. "After unpacking" is the files= field: the call saw the unit file.
#
# Scenarios (scripts/lib/arch-real-steps.sh; the stub test scripts/test-arch-lifecycle.sh decides the calls of each script, this one proves the pacman order):
#   flow      install 0.1.0, upgrade 0.1.1 with the service active, upgrade 0.1.2 inactive, remove (state kept), install again, remove with -Rns.
#   f42era    a package built from the tree before F58 (commit cd5afb6: the F42-era scripts, no hook), active, upgraded to this tree's package. The
#             scripts of the old package do not run on an upgrade; the hook of the NEW package does, since pacman reads PostTransaction hooks again.
#   refusing  a bus without ProcessFD: pacman goes on, the account is created before the policy is unpacked, the message shows.
#   nosysusers / failsysusers / failsysusers-upgrade: the status of the failing pre script is recorded: pacman prints "command failed to execute
#             correctly" and goes on (docs/findings/F42.md).
#   mutants   packages whose scripts were changed (account in post_install, reloads repeated in post_*, an unconditional restart, a restart hook that
#             sorts before dbus-reload, a restart in post_upgrade, no stop in pre_remove, a deleted state directory): the checks of `flow` fail for each.
# What this does not prove: a real running systemd (restart semantics, F45), and the separation of stdout from stderr: libalpm merges the output of a
# script into one stream, so the notice's stream is proven by scripts/test-arch-lifecycle.sh. pacman never runs pre_remove on an upgrade (the logs of
# the upgrades have no stop). In a real upgrade the PreTransaction hook aborts before pre_upgrade runs when the bus lacks ProcessFD, so the failed-check
# path of pre_upgrade is stub-only. Needs a container engine; CUSTODIO_SKIP_ARCH_INSTALL=1 skips with a message (the verify run does not set it).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
# shellcheck source=scripts/lib/bus-fixtures.sh
. "$ROOT/scripts/lib/bus-fixtures.sh"

fx_init
bf_init
trap 'bf_cleanup; fx_cleanup' EXIT
fail=0
mutant_mode=0
mutant_hit=0
bad() {
    if [ "$mutant_mode" = 1 ]; then mutant_hit=1; else echo "test-arch-lifecycle-real: $*" >&2; fail=1; fi
}
F42_COMMIT=cd5afb6

arch_image() { # prints "ENGINE TAG"; the same image and tag as scripts/test-install-real.sh
    local rt='' pins=$ROOT/packaging/lint/pins.txt base ala namcap tag
    command -v podman > /dev/null && rt=podman
    [ -n "$rt" ] || { command -v docker > /dev/null && rt=docker; }
    [ -n "$rt" ] || { echo "no container engine (podman or docker)" >&2; return 1; }
    base=$(sed -n 's/^base_arch *= *//p' "$pins")
    ala=$(sed -n 's/^namcap_ala_date *= *//p' "$pins")
    namcap=$(sed -n 's/^namcap *= *//p' "$pins")
    tag=custodio-f42-arch:$(cat "$ROOT/packaging/lint/namcap.Containerfile" <(printf '%s\n' "$base" "$ala" "$namcap") | sha256sum | cut -c1-12)
    if ! "$rt" image inspect "$tag" > /dev/null 2>&1; then
        "$rt" build -q -t "$tag" -f "$ROOT/packaging/lint/namcap.Containerfile" --build-arg "BASE=docker.io/library/$base" \
            --build-arg "ALA_DATE=$ala" --build-arg "NAMCAP=$namcap" "$ROOT/packaging/lint" > "$BF_DIR/image-build.log" 2>&1 \
            || { echo "cannot build the Arch image: $(tail -n 3 "$BF_DIR/image-build.log")" >&2; return 1; }
    fi
    printf '%s %s' "$rt" "$tag"
}
if ! image=$(arch_image 2> "$BF_DIR/arch-why"); then
    if [ "${CUSTODIO_SKIP_ARCH_INSTALL:-}" = 1 ]; then
        echo "test-arch-lifecycle-real: SKIPPED the Arch (pacman) cases: $(cat "$BF_DIR/arch-why") (CUSTODIO_SKIP_ARCH_INSTALL=1)" >&2
        exit 0
    fi
    echo "test-arch-lifecycle-real: the Arch cases cannot run: $(cat "$BF_DIR/arch-why"); set CUSTODIO_SKIP_ARCH_INSTALL=1 to skip them" >&2
    exit 1
fi
read -r rt tag <<< "$image"

# ---- the packages: this tree at three versions, the F42-era tree, and mutants ----
PKG=$BF_DIR/pkg
mkdir -p "$PKG"
build_to() { # NAME VERSION [NFPM-YAML-SED...]: the Arch package of this tree (the fixture binaries) as $PKG/NAME.pkg.tar.zst
    local name=$1 version=$2 dir e
    shift 2
    dir=$FX_DIR/out/$name
    mkdir -p "$dir"
    cp "$ROOT/packaging/nfpm.yaml" "$FX_DIR/nfpm-$name.yaml"
    for e in "$@"; do sed -i "$e" "$FX_DIR/nfpm-$name.yaml"; done
    (cd "$FX_DIR" && NFPM_VERSION=$version NFPM_PRERELEASE='' nfpm package -f "nfpm-$name.yaml" -p archlinux -t "$dir" > /dev/null)
    cp "$dir"/*.pkg.tar.zst "$PKG/$name.pkg.tar.zst"
}
build_to v1 0.1.0
build_to v2 0.1.1
build_to v3 0.1.2
# The F42-era package: the packaging and data of that commit with the same fixture binaries.
if ! git -C "$ROOT" cat-file -e "$F42_COMMIT^{commit}" 2> /dev/null; then
    echo "test-arch-lifecycle-real: the commit $F42_COMMIT (the tree before F58) is not in this checkout, so the first upgrade from the F42-era package cannot be built (fetch the full history)" >&2
    exit 1
fi
old=$FX_DIR/old-tree
mkdir -p "$old"
git -C "$ROOT" archive "$F42_COMMIT" packaging data LICENSE | tar -x -C "$old"
cp -r "$FX_DIR/target" "$old/target"
(cd "$old" && NFPM_VERSION=0.1.0 NFPM_PRERELEASE='' nfpm package -f packaging/nfpm.yaml -p archlinux -t "$old" > /dev/null)
cp "$old"/*.pkg.tar.zst "$PKG/old.pkg.tar.zst"
if bsdtar -tf "$PKG/old.pkg.tar.zst" | grep -q 'zz-custodio-restart.hook'; then bad "the F42-era package has the restart hook"; fi

# mutant_pkg NAME NFPM-SED FILE SED [FILE SED]...: this tree's packaging/arch with sed edits on files; builds $PKG/NAME-a (0.1.0) and NAME-b (0.1.1).
mutant_pkg() {
    local name=$1 nfpm_sed=$2 dir=$FX_DIR/mut-$1 file expr
    shift 2
    rm -rf "$dir"
    cp -r "$ROOT/packaging/arch" "$dir"
    while [ $# -gt 0 ]; do
        file=$1 expr=$2
        shift 2
        sed -i "$expr" "$dir/$file"
        cmp -s "$dir/$file" "$ROOT/packaging/arch/$file" && bad "mutant $name: the edit of $file changes nothing"
    done
    build_to "$name-a" 0.1.0 "s|packaging/arch/|$dir/|" "$nfpm_sed"
    build_to "$name-b" 0.1.1 "s|packaging/arch/|$dir/|" "$nfpm_sed"
}

# ---- the container side ----
STUBS=$BF_DIR/arch-stubs
mkdir -p "$STUBS"
cp "$ROOT/scripts/lib/arch-real-stubs.sh" "$ROOT/scripts/lib/arch-real-steps.sh" "$STUBS/"
scenario() { # NAME BUS-ADDRESS [PKG-PREFIX]: runs it in a fresh container; sets OUT to the directory of its step files
    local name=$1 address=$2 prefix=${3:-v1}
    OUT=$BF_DIR/out/$name-$prefix
    rm -rf "$OUT"
    mkdir -p "$OUT"
    chmod 777 "$OUT"
    "$rt" run --rm --network none --user 0:0 -v "$PKG:/pkg:ro" -v "$STUBS:/stubs:ro" -v "$BF_SOCKDIR:/bus" -v "$OUT:/out" \
        -e "DBUS_SYSTEM_BUS_ADDRESS=$address" "$tag" sh /stubs/arch-real-steps.sh "$name" "$prefix" > "$OUT/container.log" 2>&1 || bad "scenario $name: the container run failed: $(tail -n 5 "$OUT/container.log")"
}

# shellcheck source=scripts/lib/arch-real-helpers.sh
. "$ROOT/scripts/lib/arch-real-helpers.sh"

# check_flow PREFIX: the assertions on the flow scenario (a mutant must fail them)
check_flow() {
    local s
    OUT=$BF_DIR/out/flow-$1
    s=install
    [ "$(rc_of $s)" = 0 ] || bad "$s: pacman failed: $(tail -n 5 "$OUT/$s.out")"
    grep -q '^custodio:' "$OUT/$s.passwd" || bad "$s: the account is not in passwd"
    L $s | grep -E ' systemd-sysusers - ' | grep -q ':: .*pre_install' || bad "$s: pre_install did not create the account"
    [ "$(count $s ' systemd-sysusers - ')" = 1 ] || bad "$s: the account was not created exactly once by a script"
    L $s | grep -E ' systemd-sysusers - ' | grep -q 'policy=absent' || bad "$s: the bus policy already existed when the account was created"
    L $s | grep -E ' systemd-sysusers +files=' | grep -q 'policy=present' || bad "$s: the sysusers hook did not run after the policy was unpacked (the record is not working)"
    hooks_once $s present
    never_enable $s
    if L $s | grep -E ' systemctl (stop|restart|try-restart custodio)' > /dev/null; then bad "$s: a stop or restart was made on a first installation"; fi
    [ "$(count $s "$EFFECT_RESTART")" = 0 ] || bad "$s: the service was restarted on a first installation"
    [ "$(cat "$OUT/$s.active")" = inactive ] || bad "$s: the service is active"
    [ ! -s "$OUT/$s.wants" ] || bad "$s: the unit is enabled (a .wants link exists): $(cat "$OUT/$s.wants")"
    [ "$(cat "$OUT/$s.state")" = none ] || bad "$s: a state directory exists after the first installation"

    s=upgrade-active
    [ "$(rc_of $s)" = 0 ] || bad "$s: pacman failed: $(tail -n 5 "$OUT/$s.out")"
    L $s | grep -E ' systemd-sysusers - ' | grep -q ':: .*pre_upgrade' || bad "$s: pre_upgrade did not run the account step"
    hooks_once $s present
    never_enable $s
    restart_after_reloads $s
    [ "$(cat "$OUT/$s.active")" = active ] || bad "$s: the service is not active afterwards"
    state_same $s
    { [ -n "$(account_uid install)" ] && [ "$(account_uid install)" = "$(account_uid $s)" ]; } || bad "$s: the uid of custodio changed"
    if L $s | grep -E ' (userdel|groupdel) ' > /dev/null; then bad "$s: the account was touched"; fi

    s=upgrade-inactive
    [ "$(rc_of $s)" = 0 ] || bad "$s: pacman failed: $(tail -n 5 "$OUT/$s.out")"
    hooks_once $s present
    never_enable $s
    [ "$(count $s "$EFFECT_RESTART")" = 0 ] || bad "$s: a stopped service was restarted"
    [ "$(cat "$OUT/$s.active")" = inactive ] || bad "$s: the service is active afterwards"
    state_same $s
    [ "$(account_uid install)" = "$(account_uid $s)" ] || bad "$s: the uid of custodio changed"

    local step
    for step in remove purge; do
        s=$step
        [ "$(rc_of $s)" = 0 ] || bad "$s: pacman failed: $(tail -n 5 "$OUT/$s.out")"
        [ "$(count $s ' systemctl stop custodio.service')" -ge 1 ] || bad "$s: the service was not stopped"
        L $s | grep -E ' systemctl stop custodio.service' | head -n 1 | grep -q ':: .*pre_remove' || bad "$s: the first stop is not from pre_remove"
        [ "$(count $s "$RS")" = 0 ] || bad "$s: the service was restarted on a removal"
        hooks_once $s absent
        never_enable $s
        [ "$(cat "$OUT/$s.active")" = inactive ] || bad "$s: the service is left running"
        [ ! -s "$OUT/$s.files" ] || bad "$s: packaged files are left: $(cat "$OUT/$s.files")"
        grep -q '^custodio:' "$OUT/$s.passwd" || bad "$s: the account is gone"
        [ "$(account_uid install)" = "$(account_uid $s)" ] || bad "$s: the uid of custodio changed"
        state_same $s
        grep -qF 'the signing keys are still on disk in /var/lib/custodio' "$OUT/$s.out" || bad "$s: the notice is missing from the pacman output"
        grep -qF 'destroys the keys for good' "$OUT/$s.out" || bad "$s: the notice lacks the warning"
        if L $s | grep -E ' (userdel|groupdel) ' > /dev/null; then bad "$s: the account was removed"; fi
        [ "$(grep -c 'the signing keys are still on disk' "$OUT/$s.out")" = 1 ] || bad "$s: the notice does not appear exactly once"
    done
    for s in upgrade-active upgrade-inactive; do
        if L $s | grep -E ':: .*pre_remove' > /dev/null; then bad "$s: pre_remove ran during an upgrade"; fi
    done
    s=reinstall
    [ "$(rc_of $s)" = 0 ] || bad "$s: pacman failed"
    grep -q '^custodio:' "$OUT/$s.passwd" || bad "$s: no account"
}

bf_stub with_bus with
bf_stub without_bus without
arch_with="unix:path=/bus/with_bus.sock"
arch_without="unix:path=/bus/without_bus.sock"

scenario flow "$arch_with"
check_flow v1

# ---- the first upgrade from the F42-era package (note: its own scripts do not run; the hook of the new package does) ----
scenario f42era "$arch_with"
[ "$(rc_of install)" = 0 ] || bad "f42era: the F42-era package did not install: $(tail -n 5 "$OUT/install.out")"
for s in upgrade-active upgrade-inactive; do
    [ "$(rc_of $s)" = 0 ] || bad "f42era $s: pacman failed: $(tail -n 5 "$OUT/$s.out")"
    hooks_once $s present
    never_enable $s
    state_same $s
done
restart_after_reloads upgrade-active
[ "$(count upgrade-inactive "$EFFECT_RESTART")" = 0 ] || bad "f42era: a stopped service was restarted"
if L upgrade-inactive | grep -E ' systemctl stop|EFFECT stopped|EFFECT started' > /dev/null; then bad "f42era: a stop or start in the inactive upgrade"; fi
[ "$(cat "$OUT/upgrade-active.active")" = active ] || bad "f42era: the service is not active after the upgrade"
{ [ -n "$(account_uid install)" ] && [ "$(account_uid install)" = "$(account_uid upgrade-active)" ]; } || bad "f42era: the uid of custodio changed"

# ---- a bus without ProcessFD: pacman goes on; the account exists before the policy ----
scenario refusing "$arch_without"
s=install
[ "$(rc_of $s)" = 0 ] || bad "refusing: pacman did not go on: $(tail -n 5 "$OUT/$s.out")"
grep -qF 'does not provide ProcessFD' "$OUT/$s.out" || bad "refusing: the F42 message is not shown"
grep -qF 'command failed to execute correctly' "$OUT/$s.out" || bad "refusing: pacman did not report the failing pre_install"
grep -q '^custodio:' "$OUT/$s.passwd" || bad "refusing: the account does not exist"
L $s | grep -E ' systemd-sysusers - ' | grep -q ':: .*pre_install' || bad "refusing: the account was not created by pre_install"
L $s | grep -E ' systemd-sysusers - ' | grep -q 'policy=absent' || bad "refusing: the policy existed when pre_install created the account"
[ -s "$OUT/$s.files" ] || bad "refusing: the files were not installed (pacman should have gone on)"

# ---- the account step failing: pacman goes on whatever the status ----
scenario nosysusers "$arch_with"
s=install
[ "$(rc_of $s)" = 0 ] || bad "nosysusers: pacman stopped (status $(rc_of $s))"
grep -qF 'systemd-sysusers is not installed' "$OUT/$s.out" || bad "nosysusers: the message does not show: $(tail -n 8 "$OUT/$s.out")"
grep -qF 'command failed to execute correctly' "$OUT/$s.out" || bad "nosysusers: pacman did not report the failing pre_install"
[ -s "$OUT/$s.files" ] || bad "nosysusers: pacman did not go on"
scenario failsysusers "$arch_with"
s=install
[ "$(rc_of $s)" = 0 ] || bad "failsysusers: pacman stopped (status $(rc_of $s))"
grep -qF 'systemd-sysusers failed' "$OUT/$s.out" || bad "failsysusers: the message does not show: $(tail -n 8 "$OUT/$s.out")"
grep -qF 'command failed to execute correctly' "$OUT/$s.out" || bad "failsysusers: pacman did not report the failing pre_install"
scenario failsysusers-upgrade "$arch_with"
s=upgrade
[ "$(rc_of $s)" = 0 ] || bad "failsysusers-upgrade: pacman stopped (status $(rc_of $s))"
grep -qF 'systemd-sysusers failed' "$OUT/$s.out" || bad "failsysusers-upgrade: the message does not show: $(tail -n 8 "$OUT/$s.out")"
grep -qF 'command failed to execute correctly' "$OUT/$s.out" || bad "failsysusers-upgrade: pacman did not report the failing pre_upgrade"
grep -qx "custodio 0.1.1-1" "$OUT/$s.version" || bad "failsysusers-upgrade: the upgrade did not go on: $(cat "$OUT/$s.version")"

# ---- the mutants: the checks of the flow must fail for each ----
# Each mutant has its own package, fixture files and container, so they run at once, each in a subshell whose exit status is its $fail.
mutant_pids=()
mutant_flow() { # runs in the background; mutant_wait collects them
    ( mutant_flow_run "$@"; exit "$fail" ) &
    mutant_pids+=($!)
}
mutant_wait() {
    local p
    for p in "${mutant_pids[@]}"; do wait "$p" || fail=1; done
}
mutant_flow_run() { # NAME NFPM-SED FILE SED [FILE SED]...
    local name=$1
    mutant_pkg "$@"
    mutant_mode=1
    mutant_hit=0
    scenario flow "$arch_with" "$name"
    check_flow "$name"
    mutant_mode=0
    [ "$mutant_hit" = 1 ] || bad "mutant '$name' survived"
}
# shellcheck disable=SC2016 # sed expressions
{
    mutant_flow account-in-post '' pre_install 's|^custodio_create_account \|\| custodio_status=1|:|' \
        post_install "s|^:\$|systemd-sysusers - <<'X'\nu custodio - \"Custodio signing service\" -\nX|"
    mutant_flow reloads-in-post '' post_install 's|^:$|systemctl daemon-reload\njournalctl --update-catalog|' post_upgrade 's|^:$|systemctl daemon-reload\njournalctl --update-catalog|'
    mutant_flow restart-unconditional '' zz-custodio-restart.hook 's|^Exec = .*|Exec = /usr/bin/systemctl restart custodio.service|'
    mutant_flow restart-hook-too-early 's|hooks/zz-custodio-restart.hook|hooks/custodio-restart.hook|' zz-custodio-restart.hook 's|^Operation = Upgrade|Operation = Upgrade|; s|^Description = .*|Description = Restarting early|'
    mutant_flow restart-in-post-upgrade '' post_upgrade 's|^:$|systemctl try-restart custodio.service|'
    mutant_flow no-stop-in-pre-remove '' pre_remove 's|^systemctl stop custodio.service.*|:|'
    mutant_flow delete-state-in-post-remove '' post_remove 's|^if systemctl is-active.*|rm -rf /var/lib/private/custodio\n&|'
    mutant_flow remove-account-in-post-remove '' post_remove 's|^if systemctl is-active.*|userdel custodio\n&|'
    mutant_flow enable-by-link-in-post-install '' post_install 's|^:$|mkdir -p /etc/systemd/system/multi-user.target.wants\nln -s /usr/lib/systemd/system/custodio.service /etc/systemd/system/multi-user.target.wants/custodio.service|'
    mutant_flow enable-in-post-install '' post_install 's|^:$|systemctl enable custodio.service|'
}
mutant_wait

exit "$fail"
