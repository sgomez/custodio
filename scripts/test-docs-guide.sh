#!/usr/bin/env bash
# Test of docs/guide-ubuntu-2604.md (F207, acceptance 16). It runs every `console` block of the guide, in order, as written, in one
# fixture system: the real `dpkg` installs, removes and purges the .deb built from packaging/nfpm.yaml into a small root (the way
# test-deb-lifecycle-real.sh does); the real `custodio` (the `fixture-root` build) runs `doctor` and `fingerprint` against a fixture root and a
# fake fprintd, and `import`, `list`, `delete` against the test server of test-docs-api.sh, on private buses; `register` runs on a HOME
# with Firefox profiles and a stub `modutil` (the namespace of test-docs-readme.sh). Stand-ins first on PATH, none of which proves more than
# the command it receives: `sudo` (fixture root), `apt-get` (dpkg into the root), `ls` and `getent` (look into the root), `custodio` (sends
# `doctor` and `fingerprint` to the fprintd bus, the rest to the server bus). A person's: enrolling a finger, exporting the .p12 from Firefox,
# restarting it and signing in (prose). Negative controls: broken copies of the guide must fail.
# Usage: scripts/test-docs-guide.sh   (DOC overrides the guide; CHECK_ONLY=1 skips the controls)
# The single-quoted strings are scripts for another shell or markdown with literal `$`, which must not expand here.
# shellcheck disable=SC2016
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
DOC=${DOC:-docs/guide-ubuntu-2604.md}
LIB=scripts/lib/docs_check.py
. scripts/lib/package-fixtures.sh
. scripts/lib/bus-fixtures.sh
. scripts/lib/lifecycle-fixtures.sh
. scripts/lib/docs-fprint-fixture.sh
CLI=$FP_CLI
. scripts/lib/docs-register-fixture.sh
fx_init
bf_init
TMP=$(mktemp -d)
trap 'chmod -R u+w "$TMP" 2> /dev/null || true; rm -rf "$TMP"; bf_cleanup; fx_cleanup; jobs -p | xargs -r kill 2> /dev/null || true' EXIT
fail=0
bad() { echo "test-docs-guide: $*" >&2; fail=1; }

fp_build test-docs-guide || exit 1
timeout 900 cargo build --quiet --locked -p custodio-it --example docs_api_server || { echo "test-docs-guide: cannot build the test server" >&2; exit 1; }
SERVER=$ROOT/target/debug/examples/docs_api_server
[ -s "$DOC" ] || { echo "test-docs-guide: $DOC is missing or empty" >&2; exit 1; }
NAME=test-docs-guide reg_probe "$TMP/probe" || exit 1

# The package and the skeleton of the root it installs into.
fx_build guide 0.9.0 "" none
DEB=$(fx_file guide deb)
SKEL=$TMP/skeleton
bf_mkroot "$SKEL"
lc_stubs "$SKEL"
bf_in_root "$SKEL" true || { echo "test-docs-guide: cannot make a user namespace for dpkg" >&2; exit 1; }

# wrappers BIN D: the stand-ins first on PATH.
wrappers() {
    local bin=$1 d=$2
    fp_wrappers "$bin"
    rm -f "$bin/custodio"
    cat > "$bin/custodio" << W
#!/bin/sh
case \$1 in
    doctor | fingerprint) DBUS_SYSTEM_BUS_ADDRESS=\$(cat $d/fp/address | head -n 1) ;;
    *) DBUS_SYSTEM_BUS_ADDRESS=\$(cat $d/srv/address | head -n 1) ;;
esac
export DBUS_SYSTEM_BUS_ADDRESS
exec $FP_CLI "\$@"
W
    cat > "$bin/sudo" << 'W'
#!/bin/sh
case $1 in
    custodio) CUSTODIO_FIXTURE_EUID=0 exec "$@" ;;
    apt-get | ls) exec "$@" ;;
    *) echo "sudo (test stand-in): not known: $*" >&2; exit 1 ;;
esac
W
    # apt-get install ./X.deb | remove custodio | purge custodio: the real dpkg on the root, as the lifecycle test runs it.
    cat > "$bin/apt-get" << W
#!/bin/sh
case "\$1 \$2" in
    "install ./"*) [ -f "\$2" ] || { echo "E: Unable to locate package \$2" >&2; exit 100; }; act=-i; arg=\${2#./} ;;
    "remove custodio") act=-r; arg=custodio ;;
    "purge custodio") act=-P; arg=custodio ;;
    *) echo "apt-get (test stand-in): not known: \$*" >&2; exit 1 ;;
esac
case \$act in
    -i) arg=\$PWD/\$arg ;;
    *) if grep -rqsi custodio \$HOME/.mozilla/firefox/*/pkcs11.txt \$HOME/snap/firefox/common/.mozilla/firefox/*/pkcs11.txt; then
           echo "the module is still registered in a Firefox profile: run custodio register --remove first" >&2; exit 1; fi ;;
esac
cd $d
unshare --map-root-user --mount env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket dpkg --root=$d/droot --log=$d/droot/dpkg.log \\
    --force-depends --force-bad-path --no-triggers \$act "\$arg" > $d/dpkg.out 2>&1 || { tail -n 5 $d/dpkg.out >&2; exit 1; }
echo "\$act" >> $d/dpkg.acts
# apt shows dpkg's progress too; the guide shows only what the package's maintainer scripts print (they start with "custodio:").
grep '^custodio:' $d/dpkg.out || true
W
    # ls and getent look into the root of the package, so that what removal leaves can be shown.
    cat > "$bin/ls" << W
#!/bin/sh
args=
for a in "\$@"; do case \$a in /*) args="\$args $d/droot\$a" ;; *) args="\$args \$a" ;; esac; done
/usr/bin/ls \$args | sed "s#$d/droot##"
W
    cat > "$bin/getent" << W
#!/bin/sh
[ "\$1" = passwd ] || exit 2
grep "^\$2:" $d/droot/etc/passwd
W
    # bash's `source` of an absolute path reads it from the root of the package.
    cat > "$bin/benv" << W
source() { local f=\$1; shift; case \$f in /*) f=$d/droot\$f ;; esac; builtin source "\$f" "\$@"; }
W
    chmod +x "$bin"/*
}

# check_script FILE D: the effect checks, run after each block with its first command.
check_script() {
    cat > "$1" << CHECK
#!/bin/bash
set -u
d=$2
snap() { . $ROOT/scripts/lib/lifecycle-fixtures.sh; lc_snapshot_state $2/droot; }
echo "\$1" >> \$d/ran
# Every command of the block has a handler that ran it (the stand-in or the real tool); one that no handler knows fails.
while IFS= read -r c; do
    case \$c in
        "sudo apt-get install ./"* | "sudo apt-get remove custodio" | "sudo apt-get purge custodio") h=apt-get-to-dpkg ;;
        "sudo custodio fingerprint enable" | "sudo custodio fingerprint disable") h=custodio-fixture-root-as-root ;;
        "custodio doctor" | "custodio import --id ana ana.p12" | "custodio register" | "custodio register --remove" | "custodio list" | "custodio delete ana") h=custodio-fixture ;;
        "sudo ls -d /var/lib/private/custodio") h=ls-in-package-root ;;
        "getent passwd custodio | cut -d: -f1") h=getent-in-package-root ;;
        "source /usr/share/bash-completion/completions/custodio" | "COMP_WORDS=(custodio li) COMP_CWORD=1" | '_custodio; echo "\${COMPREPLY[@]}"') h=bash-completion ;;
        *) echo "no handler knows: \$c" >&2; exit 1 ;;
    esac
    echo "  \$h: \$c" >> \$d/handlers
done <<< "\$DOCS_COMMANDS"
case \$1 in
    "sudo apt-get install ./custodio_0.9.0-1_amd64.deb")
        [ -x \$d/droot/usr/libexec/custodio/custodiod ] || { echo "the package's files are not in the root" >&2; exit 1; }
        grep -q '^custodio:' \$d/droot/etc/passwd || { echo "no account" >&2; exit 1; }
        snap > \$d/state.before ;;
    "sudo custodio fingerprint enable") [ -s \$d/root/etc/pam.d/polkit-1 ] || { echo "no override" >&2; exit 1; } ;;
    "sudo custodio fingerprint disable") [ ! -e \$d/root/etc/pam.d/polkit-1 ] || { echo "the override is still there" >&2; exit 1; } ;;
    "sudo apt-get remove custodio" | "sudo apt-get purge custodio")
        [ ! -e \$d/droot/usr/libexec/custodio/custodiod ] || { echo "files are left" >&2; exit 1; }
        grep -q '^custodio:' \$d/droot/etc/passwd || { echo "the account is gone" >&2; exit 1; }
        [ "\$(snap)" = "\$(cat \$d/state.before)" ] || { echo "the state directory changed" >&2; exit 1; } ;;
esac
$d/regcheck "\$1"
CHECK
    chmod +x "$1"
}

# run_guide DOC DIR: the console blocks of DOC; the status of the runner and the checks.
run_guide() {
    local doc=$1 d=$2 rc=0 want uid
    mkdir -p "$d/ov" "$d/ctl" "$d/state" "$d/work" "$d/stage/custodio" "$d/fp" "$d/srv"
    chmod 700 "$d/state"
    : > "$d/stage/custodio/libcustodio_pkcs11.so"
    reg_stub "$d/bin"
    reg_check "$d/regcheck"
    reg_home "$d"
    wrappers "$d/bin" "$d"
    check_script "$d/check.sh" "$d"
    cp crates/custodiod/tests/fixtures/p256.p12 "$d/work/ana.p12"
    cp "$DEB" "$d/work/"
    cp -a "$SKEL" "$d/droot"
    mkdir -p "$d/droot/var/lib"
    lc_populate "$d/droot"
    fp_root "$d/root" ubuntu
    # The fprintd bus (a reader and a finger) and the bus of the service.
    fp_bus "$d/fpbus" 1 list || { echo "the fake fprintd did not start" >&2; return 1; }
    cp "$d/fpbus/address" "$d/fp/address"
    local fpbus_pid=$FP_BUS_PID fake_pid=$FP_FAKE_PID
    local srv_bus="$d/srv/bus.conf"
    sed "s#$d/fpbus#$d/srv#" "$d/fpbus/bus.conf" > "$srv_bus"
    dbus-daemon --config-file="$srv_bus" --nofork --print-address=3 3> "$d/srv/address" > /dev/null 2>&1 &
    local srv_bus_pid=$!
    timeout 20 sh -c 'until [ -s "$1" ]; do sleep 0.1; done' _ "$d/srv/address"
    echo approve > "$d/ctl/mode"
    "$SERVER" "$(head -n 1 "$d/srv/address")" "$d/state" "$d/ctl" > "$d/server.out" &
    local srv_pid=$!
    timeout 20 sh -c 'until grep -q ready "$1"; do sleep 0.1; done' _ "$d/server.out"
    uid=$(reg_uid)
    BASH_ENV=$d/bin/benv HOME=$d/home PATH=$d/bin:$PATH STUB_LOG=$d/modutil.log CHECK_DIR=$d GS_LOG=$d/gs.log \
        CUSTODIO_FIXTURE_ROOT=$d/root CUSTODIO_FIXTURE_EUID=$uid \
        DOCS_PASSWORD=test-password DOCS_ANSWER=yes DOCS_HOME_SHOWN=/home/ana DOCS_CHECK=$d/check.sh \
        timeout 300 unshare -rm sh -c '
            mount -t tmpfs tmpfs "$1/ov" && mkdir "$1/ov/up" "$1/ov/wk" &&
            mount -t overlay overlay -o "lowerdir=$1/stage:/usr/lib,upperdir=$1/ov/up,workdir=$1/ov/wk" /usr/lib &&
            exec unshare --user --map-user="$3" --map-group="$3" python3 -I "$4" run "$2" "$1/work"' \
        sh "$d" "$doc" "$uid" "$ROOT/$LIB" 2> "$d/run.err" > "$d/run.out" || rc=$?
    kill "$srv_pid" "$srv_bus_pid" "$fake_pid" "$fpbus_pid" 2> /dev/null || true
    wait "$srv_pid" "$srv_bus_pid" "$fake_pid" "$fpbus_pid" 2> /dev/null || true
    for want in registered removed; do
        grep -qx "$want" "$d/checked" 2> /dev/null || { echo "the effect '$want' was never checked: the guide lacks the command" >&2; rc=1; }
    done
    # Every command the guide's blocks hold was run by a handler: the list of what ran is the list of the first commands.
    [ "$(tr '\n' ' ' < "$d/dpkg.acts" 2> /dev/null)" = "-i -r -P " ] || { echo "dpkg did not run install, remove and purge in that order: $(tr '\n' ' ' < "$d/dpkg.acts" 2> /dev/null)" >&2; rc=1; }
    # AFTER_RUN COMMAND: the caller's checks on the fixture once the way back is done (test-docs-manual-m7.sh); $d is its argument.
    [ -z "${AFTER_RUN:-}" ] || "$AFTER_RUN" "$d" || rc=1
    sed -n 's/^/    /p' "$d/run.out" "$d/run.err" | tail -n 30 >&2
    return "$rc"
}

python3 -I "$LIB" kinds --only-console "$DOC" || fail=1
python3 -I "$LIB" links "$DOC" || fail=1
run_guide "$DOC" "$TMP/real" || fail=1
echo "commands run, in order (first command of each block):"
sed 's/^/  /' "$TMP/real/ran" 2> /dev/null || true
echo "every command and the handler that ran it:"
cat "$TMP/real/handlers" 2> /dev/null || true

if [ -z "${CHECK_ONLY:-}" ] && [ "$fail" = 0 ]; then
    pids=() names=()
    control() {
        local name=$1 kind=$2 n=${#names[@]} copy
        shift 2
        copy=$TMP/copy$n.md
        "$@" < "$DOC" > "$copy"
        if cmp -s "$copy" "$DOC"; then bad "control '$name' did not change the guide"; return; fi
        if [ "$kind" = static ]; then
            if python3 -I "$LIB" kinds --only-console "$copy" > /dev/null 2>&1; then bad "control '$name' passed on a broken guide"; else echo "control ok: $name"; fi
            return
        fi
        (run_guide "$copy" "$TMP/ctl$n" > /dev/null 2>&1 && exit 1 || exit 0) &
        pids+=($!)
        names+=("$name")
    }
    control "command moved into a bash block" static sed '0,/^```console$/s//```bash/'
    control "command in a text block" static sed '0,/^## 1\. Install the package$/s//```text\n$ rm -rf \/etc\n```\n\n&/'
    control "an extra command" run sed '0,/^\$ custodio list$/s//$ custodio frobnicate\n$ custodio list/'
    control "output altered" run sed '0,/^warn  ana  /s//warn  anx  /'
    control "install notice altered" run sed '0,/^custodio: to check the setup at any time, run: custodio doctor$/s//custodio: to check the setup, run: custodio doctor/'
    control "deb name changed" run sed 's/custodio_0\.9\.0-1_amd64\.deb/custodio_0.9.1-1_amd64.deb/'
    control "register --remove after the removal" run python3 -I -c '
import re, sys
t = sys.stdin.read()
m = re.search(r"```console\n(\$ custodio register --remove\n(?:(?!```).)*)```\n", t, re.S)
blk = m.group(0)
t = t.replace(blk, "")
i = t.index("$ sudo apt-get remove custodio")
j = t.rindex("```console", 0, i)
sys.stdout.write(t[:j] + t[j:].replace("```\n", "```\n\n" + blk, 1))'
    for i in "${!pids[@]}"; do
        if wait "${pids[$i]}"; then echo "control ok: ${names[$i]}"; else bad "control '${names[$i]}' passed on a broken guide"; fi
    done
fi
echo "a person's: enrolling a finger, exporting the .p12 from Firefox, restarting Firefox and signing in (prose)"
if [ "$fail" != 0 ]; then echo "test-docs-guide: FAILED" >&2; exit 1; fi
echo "test-docs-guide: ok"
