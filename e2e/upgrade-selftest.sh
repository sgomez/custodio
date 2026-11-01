#!/usr/bin/env bash
# Self-test of upgrade-lib.sh, run by the guest before it relies on the library and by `just test-scripts`. Each rejection has its
# own control: the check must fail AND say the expected thing; the unchanged fixture must pass. Usage: upgrade-selftest.sh [FORMAT]
# FORMAT (deb, rpm or arch) is the format of the target: its comparison tool must exist and its controls run. Without it, the
# controls of every tool present run (the dev container has dpkg and rpm).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/upgrade-lib.sh
source "$here/upgrade-lib.sh"
want=${1:-}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0
bad() { echo "upgrade-selftest: FAIL: $*" >&2; failures=$((failures + 1)); }

# rejects DESCRIPTION EXPECTED_TEXT COMMAND...: the command fails and its output contains the text.
rejects() {
    local what=$1 text=$2 out
    shift 2
    if out=$("$@" 2>&1); then bad "$what: accepted"; return; fi
    grep -q -- "$text" <<< "$out" || bad "$what: rejected, but without '$text': $out"
}
accepts() { local what=$1 out; shift; out=$("$@" 2>&1) || bad "$what: rejected: $out"; }

# --- the state directory -----------------------------------------------------------------------------------------------------
st=$tmp/state
mkdir -p "$st/keys"
printf 'key one\n' > "$st/keys/a.p12"
printf 'key two\n' > "$st/keys/b.p12"
chmod 600 "$st/keys/a.p12" "$st/keys/b.p12"
chmod 700 "$st/keys"
snapshot_state "$st" > "$tmp/before"
[ "$(grep -c '^f ' "$tmp/before")" -eq 2 ] || bad "the snapshot does not hold the two files: $(cat "$tmp/before")"
snapshot_state "$st" > "$tmp/same"
accepts "unchanged state" compare_state "$tmp/before" "$tmp/same"

mutate() { # NAME COMMAND...: snapshot after a change of the fixture, then undo it by rebuilding
    local name=$1
    shift
    "$@"
    snapshot_state "$st" > "$tmp/after.$name"
}
restore() { printf 'key one\n' > "$st/keys/a.p12"; chmod 600 "$st/keys/a.p12"; chmod 700 "$st/keys"; rm -f "$st/keys/c.p12"; printf 'key two\n' > "$st/keys/b.p12"; }
mutate byte sh -c "printf 'key onE\n' > '$st/keys/a.p12'"
restore
mutate mode chmod 640 "$st/keys/a.p12"
restore
mutate dirmode chmod 750 "$st/keys"
restore
mutate added sh -c "printf 'x\n' > '$st/keys/c.p12'"
restore
mutate removed rm "$st/keys/b.p12"
restore
rejects "one flipped byte" 'content changed: ./keys/a.p12' compare_state "$tmp/before" "$tmp/after.byte"
rejects "a changed mode" 'mode changed: ./keys/a.p12' compare_state "$tmp/before" "$tmp/after.mode"
rejects "a changed directory mode" 'directory mode changed: ./keys' compare_state "$tmp/before" "$tmp/after.dirmode"
rejects "an added file" 'added: ./keys/c.p12' compare_state "$tmp/before" "$tmp/after.added"
rejects "a removed file" 'removed: ./keys/b.p12' compare_state "$tmp/before" "$tmp/after.removed"
# A changed owner needs no privilege here: the snapshot lines are edited, which is what the comparison reads.
awk '$1 == "f" && !done { $2 = 4242; done = 1 } { print }' "$tmp/before" > "$tmp/after.uid"
awk '$1 == "f" && !done { $3 = 4242; done = 1 } { print }' "$tmp/before" > "$tmp/after.gid"
rejects "a changed uid" 'owner changed' compare_state "$tmp/before" "$tmp/after.uid"
rejects "a changed gid" 'owner changed' compare_state "$tmp/before" "$tmp/after.gid"
grep -v '^f ' "$tmp/before" > "$tmp/nofiles"
rejects "a snapshot without key files" 'regular files' compare_state "$tmp/nofiles" "$tmp/nofiles"
ln -s a.p12 "$st/keys/link"
snapshot_state "$st" | grep -q '^l ' || bad "a symlink is not recorded"
rm "$st/keys/link"

# --- the listing -------------------------------------------------------------------------------------------------------------
printf 'Slot 0\n  token label: rsa1\nSlot 1\n  token label: ec1\n' > "$tmp/list.a"
cp "$tmp/list.a" "$tmp/list.b"
accepts "same listing" compare_listing "$tmp/list.a" "$tmp/list.b"
printf 'Slot 0\n  token label: rsa1\n' > "$tmp/list.one"
rejects "a listing without ec1" 'does not name ec1' compare_listing "$tmp/list.a" "$tmp/list.one"
rejects "a listing that changed" 'differs' compare_listing "$tmp/list.a" "$tmp/list.one"
: > "$tmp/list.empty"
rejects "an empty listing" 'is empty' compare_listing "$tmp/list.empty" "$tmp/list.empty"

# --- the service: a fake /proc whose exe links point at files of the fixture --------------------------------------------------
proc=$tmp/proc
mkdir -p "$proc/100" "$proc/200" "$proc/300"
printf 'binary\n' > "$tmp/installed"
printf 'binary\n' > "$tmp/other" # same content, another inode: the identity is the inode
ln -s "$tmp/installed" "$proc/200/exe"
ln -s "$tmp/other" "$proc/300/exe"
ln -s "$tmp/gone (deleted)" "$proc/100/exe"
accepts "restarted onto the installed file" service_problems "$proc" 100 200 "$tmp/installed"
rejects "an unchanged pid" 'did not change' service_problems "$proc" 200 200 "$tmp/installed"
rejects "an exe that is deleted" 'deleted' service_problems "$proc" 200 100 "$tmp/installed"
rejects "an exe with another inode and the same content" 'does not run the installed file' service_problems "$proc" 100 300 "$tmp/installed"
rejects "a pid with no process" 'no exe link' service_problems "$proc" 100 999 "$tmp/installed"
rejects "an old process that still runs the live binary" 'old pid 300 still runs' service_problems "$proc" 300 200 "$tmp/installed"

# --- the executable named by the unit: it differs between the old and the new package, so it is read, not assumed ---------------
unit() { printf '[Service]\nType=dbus\n%s\n' "$1" > "$tmp/unit.service"; }
unit 'ExecStart=/usr/libexec/custodiod'
accepts "the old unit" test "$(unit_binary "$tmp/unit.service")" = /usr/libexec/custodiod
unit 'ExecStart=/usr/lib/custodio/custodiod'
accepts "the new unit" test "$(unit_binary "$tmp/unit.service")" = /usr/lib/custodio/custodiod
for prefix in '-' '@' '!' '+' ':' '-!' '!!+' '@-'; do
    unit "ExecStart=$prefix/usr/libexec/custodiod --flag value --other=1"
    accepts "ExecStart with the prefix '$prefix' and arguments" test "$(unit_binary "$tmp/unit.service")" = /usr/libexec/custodiod
done
unit 'ExecStart=  -/usr/libexec/custodiod   --flag'
accepts "ExecStart with spaces around" test "$(unit_binary "$tmp/unit.service")" = /usr/libexec/custodiod
printf '[Service]\nExecStart=/usr/bin/old\nExecStart=\nExecStart=/usr/libexec/custodiod\n' > "$tmp/unit.service"
accepts "the last ExecStart wins" test "$(unit_binary "$tmp/unit.service")" = /usr/libexec/custodiod
printf '[Service]\nType=dbus\n' > "$tmp/unit.service"
rejects "a unit without ExecStart" 'no ExecStart' unit_binary "$tmp/unit.service"
unit 'ExecStart=custodiod'
rejects "a relative ExecStart" 'not an absolute path' unit_binary "$tmp/unit.service"
rejects "no unit file" 'no unit file' unit_binary "$tmp/none.service"
# F61: the upgrade from the package with the daemon at the old path moves the service from /usr/lib/custodio to /usr/libexec/custodio.
accepts "the service moved to the libexec path" oldpath_problems /usr/lib/custodio/custodiod /usr/libexec/custodio/custodiod
rejects "a before path equal to the after path" 'same path as before' oldpath_problems /usr/libexec/custodio/custodiod /usr/libexec/custodio/custodiod
rejects "a before path that is not the old path" 'not the old path' oldpath_problems /usr/libexec/custodiod /usr/libexec/custodio/custodiod
rejects "an after-unit naming the old path" 'still names the old path' oldpath_problems /usr/lib/custodio/custodiod /usr/lib/custodio/custodiod
rejects "an after path that is not the libexec path" 'not /usr/libexec/custodio/custodiod' oldpath_problems /usr/lib/custodio/custodiod /usr/bin/custodiod
accepts "the deb daemon path" test "$(daemon_path deb)" = /usr/libexec/custodio/custodiod
accepts "the rpm daemon path" test "$(daemon_path rpm)" = /usr/libexec/custodio/custodiod
accepts "the Arch daemon path" test "$(daemon_path arch)" = /usr/lib/custodio/custodiod
rejects "an unknown format" 'unknown format' daemon_path snap
# The process started from the old file must not pass for the new one: after the upgrade the process runs the file the NEW unit names.
mkdir -p "$tmp/oldroot" "$tmp/newroot"
printf 'binary\n' > "$tmp/oldroot/custodiod"
printf 'binary\n' > "$tmp/newroot/custodiod"
ln -sfn "$tmp/oldroot/custodiod" "$proc/200/exe" # the process runs the old path's file
ln -sfn "$tmp/newroot/custodiod" "$proc/300/exe"
accepts "before: the process runs the file the old unit names" exe_problems "$proc" 200 "$tmp/oldroot/custodiod"
rejects "after: an old exe path reused for the new process" 'does not run the installed file' service_problems "$proc" 100 200 "$tmp/newroot/custodiod"
accepts "after: the process runs the file the new unit names" service_problems "$proc" 100 300 "$tmp/newroot/custodiod"
rm -f "$tmp/oldroot/custodiod"
rejects "the old file is gone: the old unit's path no longer describes a live process" 'no exe link\|does not run\|deleted' exe_problems "$proc" 200 "$tmp/oldroot/custodiod"

# --- no manual step -----------------------------------------------------------------------------------------------------------
good=$tmp/good.sh
# shellcheck disable=SC2016 # the fixture sections hold a literal "$1"
printf '# BEGIN upgrade-case\nbash /e2e-target/install.sh "$1"\nsystemctl show -p MainPID custodio\n# END upgrade-case\n' > "$good"
accepts "a section with the install only" manual_step_problems "$good"
cmds=('systemctl restart custodio' 'systemctl start custodio' 'systemctl daemon-reload' 'systemctl reload dbus' 'systemctl --no-block try-restart custodio'
    'pkill custodiod' 'systemctl kill custodio')
for c in "${cmds[@]}"; do
    # shellcheck disable=SC2016 # the fixture holds a literal "$1"
    printf '# BEGIN upgrade-case\nbash /e2e-target/install.sh "$1"\n%s\n# END upgrade-case\n' "$c" > "$tmp/manual.sh"
    rejects "'$c' in the section" 'by hand' manual_step_problems "$tmp/manual.sh"
done
printf '# BEGIN upgrade-case\n# systemctl restart custodio is not run here\nls\n# END upgrade-case\n' > "$tmp/commented.sh"
accepts "a comment line that names a restart" manual_step_problems "$tmp/commented.sh"
printf 'systemctl restart custodio\n' > "$tmp/outside.sh"
rejects "no markers" 'BEGIN and one END' manual_step_problems "$tmp/outside.sh"
printf '# BEGIN upgrade-case\n# END upgrade-case\n' > "$tmp/empty.sh"
rejects "an empty section" 'is empty' manual_step_problems "$tmp/empty.sh"
printf '# BEGIN upgrade-case\nls\n' > "$tmp/noend.sh"
rejects "a missing END marker" 'BEGIN and one END' manual_step_problems "$tmp/noend.sh"

# --- the formats ------------------------------------------------------------------------------------------------------------
accepts "deb name" test "$(pkg_format custodio_0.1.0-1_amd64.deb)" = deb
accepts "rpm name" test "$(pkg_format custodio-0.1.0-1.x86_64.rpm)" = rpm
accepts "arch name" test "$(pkg_format custodio-0.1.0-1-x86_64.pkg.tar.zst)" = arch
rejects "an unknown package file" 'unknown package' pkg_format custodio.tar

# --- the version comparison, with the target's own tool: greater passes, equal and lower fail --------------------------------
tool_controls() { # FORMAT
    local f=$1
    accepts "$f: greater" version_greater "$f" 0.1.1-1 0.1.0-1
    accepts "$f: greater release" version_greater "$f" 0.1.0-2 0.1.0-1
    accepts "$f: 0.1.10 after 0.1.9" version_greater "$f" 0.1.10-1 0.1.9-1
    if version_greater "$f" 0.1.0-1 0.1.0-1; then bad "$f: equal versions accepted as greater"; fi
    if version_greater "$f" 0.1.0-1 0.1.1-1; then bad "$f: a lower version accepted as greater"; fi
    if version_greater "$f" "0.1.1-1;id" 0.1.0-1 2> /dev/null; then bad "$f: a version with odd characters accepted"; fi
}
if [ -z "$want" ] || [ "$want" = deb ]; then
    if command -v dpkg > /dev/null; then tool_controls deb; elif [ -n "$want" ]; then bad "dpkg is missing on a deb target"; fi
fi
if [ -z "$want" ] || [ "$want" = rpm ]; then
    if command -v rpm > /dev/null; then tool_controls rpm; elif [ -n "$want" ]; then bad "rpm is missing on an rpm target"; fi
fi
# Arch's vercmp prints 1, 0 or -1. Where the real one exists it runs; the branch is also run against stubs, to show that it reads the
# tool's output (a constant or an exit status alone would not tell these apart).
if [ "$want" = arch ]; then
    command -v vercmp > /dev/null || bad "vercmp is missing on an arch target"
    tool_controls arch
fi
stubs=$tmp/stubs
mkdir -p "$stubs"
stub_vercmp() { # OUTPUT [EXIT]
    printf '#!/bin/sh\nprintf "%%s\\n" "%s"\nexit %s\n' "$1" "${2:-0}" > "$stubs/vercmp"
    chmod +x "$stubs/vercmp"
}
(
    PATH="$stubs:$PATH"
    stub_vercmp 1
    version_greater arch 0.1.1-1 0.1.0-1 || bad "arch: a vercmp answering 1 was not accepted"
    for out in 0 -1 2 11 '' 'error: x'; do
        stub_vercmp "$out"
        if version_greater arch 0.1.1-1 0.1.0-1; then bad "arch: a vercmp answering '$out' was accepted"; fi
    done
    stub_vercmp 1 3
    if version_greater arch 0.1.1-1 0.1.0-1; then bad "arch: a vercmp that exits 3 was accepted"; fi
    # the stub answers 1 whatever it is asked, so the answer, not the arguments, decides: swapped arguments pass here by design;
    # the real tool is exercised by the target's own run
)

[ "$failures" -eq 0 ] || exit 1
echo "upgrade-selftest: passed"
