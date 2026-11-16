#!/usr/bin/env bash
# Test of README.md (F185). It runs every `console` block of the README as written, on the real `custodio` built from the tree:
# `import`, `list` and `delete` against the test-only server of test-docs-api.sh (the real service type on a private bus with a
# scripted polkit), `register` and `register --remove` on a temporary HOME with a Firefox profile, a snap profile and a stub
# `modutil` first on PATH. Then it checks the effect of register and remove, the block kinds and every relative link, and that
# the README links the threat model and SECURITY.md. Negative controls: broken copies of the README must fail.
# `custodio register` without --module uses /usr/lib/custodio/libcustodio_pkcs11.so, which is not here: the commands run in a user
# and mount namespace where an overlay puts an empty module file there, and then in a nested user namespace mapped to the
# invoking uid (register refuses root). Nothing on the host changes. Without `unshare` the test fails; it does not skip.
# Usage: scripts/test-docs-readme.sh   (DOC overrides the README; CHECK_ONLY=1 skips the controls)
# The single-quoted strings are scripts for another shell or markdown with literal `$`, which must not expand here.
# shellcheck disable=SC2016
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
DOC=${DOC:-README.md}
LIB=scripts/lib/docs_check.py
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail=0
bad() { echo "test-docs-readme: $*" >&2; fail=1; }

SERVER=${DOCS_API_SERVER:-$ROOT/target/debug/examples/docs_api_server}
CLI=$ROOT/target/debug/custodio-cli
timeout 900 cargo build --quiet --locked -p custodio-cli || { echo "test-docs-readme: cannot build custodio-cli" >&2; exit 1; }
timeout 900 cargo build --quiet --locked -p custodio-it --example docs_api_server || { echo "test-docs-readme: cannot build the test server" >&2; exit 1; }

# The shared helper: the same files and the same default paths as the threat-model test.
REQUIRED=(docs/threat-model.md SECURITY.md docs/install.md docs/fingerprint.md)

# shellcheck source=scripts/lib/docs-register-fixture.sh
. scripts/lib/docs-register-fixture.sh

# run_readme DOC DIR: the console blocks of DOC on a fresh bus, server, HOME and overlay; the status of the runner and the checks.
run_readme() {
    local doc=$1 d=$2 bus_pid='' srv_pid='' rc=0
    mkdir -p "$d/ov" "$d/ctl" "$d/state" "$d/work" "$d/home" "$d/stage/custodio"
    chmod 700 "$d/state"
    : > "$d/stage/custodio/libcustodio_pkcs11.so"
    reg_stub "$d/bin"
    reg_check "$d/check.sh"
    cp crates/custodiod/tests/fixtures/p256.p12 "$d/work/ana.p12"
    reg_home "$d"
    cat > "$d/bus.conf" << CONF
<busconfig>
  <type>session</type>
  <listen>unix:path=$d/bus.sock</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
CONF
    dbus-daemon --config-file="$d/bus.conf" --nofork --print-address=3 3> "$d/address" > /dev/null 2>&1 &
    bus_pid=$!
    timeout 20 sh -c 'until [ -s "$1" ]; do sleep 0.1; done' _ "$d/address" || { echo "test-docs-readme: the private bus did not start" >&2; kill "$bus_pid"; return 1; }
    echo approve > "$d/ctl/mode"
    "$SERVER" "$(head -n 1 "$d/address")" "$d/state" "$d/ctl" > "$d/server.out" &
    srv_pid=$!
    timeout 20 sh -c 'until grep -q ready "$1"; do sleep 0.1; done' _ "$d/server.out" || { echo "test-docs-readme: the test server did not start" >&2; kill "$bus_pid" "$srv_pid"; return 1; }

    local uid
    uid=$(id -u)
    [ "$uid" != 0 ] || uid=1000
    # The overlay's directories go on a tmpfs of the namespace, so the result does not depend on TMPDIR or the root filesystem.
    HOME=$d/home PATH=$d/bin:$PATH STUB_LOG=$d/modutil.log CHECK_DIR=$d \
        DBUS_SYSTEM_BUS_ADDRESS=$(head -n 1 "$d/address") \
        DOCS_PASSWORD=test-password DOCS_ANSWER=yes DOCS_HOME_SHOWN=/home/ana DOCS_CHECK=$d/check.sh \
        timeout 300 unshare -rm sh -c '
            mount -t tmpfs tmpfs "$1/ov" && mkdir "$1/ov/up" "$1/ov/wk" &&
            mount -t overlay overlay -o "lowerdir=$1/stage:/usr/lib,upperdir=$1/ov/up,workdir=$1/ov/wk" /usr/lib &&
            exec unshare --user --map-user="$3" --map-group="$3" python3 -I "$4" run "$2" "$1/work"' \
        sh "$d" "$doc" "$uid" "$ROOT/$LIB" 2> "$d/run.err" > "$d/run.out" || rc=$?
    kill "$srv_pid" "$bus_pid" 2> /dev/null || true
    wait "$srv_pid" "$bus_pid" 2> /dev/null || true
    # Both effects must have been checked: a README without the register or the remove command proves nothing.
    for want in registered removed; do
        grep -qx "$want" "$d/checked" 2> /dev/null || { echo "the effect '$want' was never checked: the README lacks the command" >&2; rc=1; }
    done
    sed -n 's/^/    /p' "$d/run.out" "$d/run.err" | tail -n 30 >&2
    return "$rc"
}
NAME=test-docs-readme reg_probe "$TMP/probe" || exit 1

[ -s "$DOC" ] || { echo "test-docs-readme: $DOC is missing or empty" >&2; exit 1; }

# static DOC: block kinds and links.
static() {
    python3 -I "$LIB" kinds "$1" && python3 -I "$LIB" links "$1" "${REQUIRED[@]}"
}
static "$DOC" || fail=1
run_readme "$DOC" "$TMP/real" || fail=1

if [ -z "${CHECK_ONLY:-}" ] && [ "$fail" = 0 ]; then
    pids=() names=()
    # control NAME KIND COMMAND...: COMMAND reads the README on stdin and writes a broken copy; it must differ and must fail.
    control() {
        local name=$1 kind=$2 n=${#names[@]} copy
        shift 2
        copy=$TMP/copy$n.md
        "$@" < "$DOC" > "$copy"
        if cmp -s "$copy" "$DOC"; then bad "control '$name' did not change the README"; return; fi
        if [ "$kind" = static ]; then
            if static "$copy" > /dev/null 2>&1; then bad "control '$name' passed on a broken README"; else echo "control ok: $name"; fi
            return
        fi
        (run_readme "$copy" "$TMP/ctl$n" > /dev/null 2>&1 && exit 1 || exit 0) &
        pids+=($!)
        names+=("$name")
    }
    control "link to the threat model removed" static sed 's#(docs/threat-model\.md[^)]*)#(docs/install.md)#g'
    control "link to SECURITY.md removed" static sed 's#(SECURITY\.md[^)]*)#(docs/install.md)#g'
    control "command altered" run sed '0,/^\$ custodio list$/s//$ custodio lst/'
    control "output altered" run sed '0,/^ana  ecdsa-p256  encrypted-host  /s//ana  ecdsa-p256  tpm  /'
    control "remove command replaced by refresh-only" run sed 's/^\$ custodio register --remove$/$ custodio register --refresh-only/'
    for i in "${!pids[@]}"; do
        if wait "${pids[$i]}"; then echo "control ok: ${names[$i]}"; else bad "control '${names[$i]}' passed on a broken README"; fi
    done
fi
if [ "$fail" != 0 ]; then echo "test-docs-readme: FAILED" >&2; exit 1; fi
echo "test-docs-readme: ok"
