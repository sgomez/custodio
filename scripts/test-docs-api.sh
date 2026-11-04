#!/usr/bin/env bash
# Test of docs/api.md (F98). It checks what the document must state (scripts/docs_api_run.py static) and runs every `console`
# example of the document, as written, against the real service type on a private bus with a scripted polkit (the test-only server
# crates/custodio-it/examples/docs_api_server.rs; custodiod itself is wired to the system bus, the real polkit and the journal).
# Negative controls: copies of the document with a claim broken must fail and must differ from the real one.
# Usage: scripts/test-docs-api.sh   (DOC overrides the document; CHECK_ONLY=1 skips the controls)
# The single-quoted sed expressions hold literal backticks of the markdown, which must not expand.
# shellcheck disable=SC2016
set -euo pipefail
cd "$(dirname "$0")/.."
DOC=${DOC:-docs/api.md}
RUN=scripts/docs_api_run.py
TMP=$(mktemp -d)
BUS_PID=
cleanup() { [ -z "$BUS_PID" ] || kill "$BUS_PID" 2> /dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

fail=0
bad() { echo "test-docs-api: $*" >&2; fail=1; }

SERVER=${DOCS_API_SERVER:-target/debug/examples/docs_api_server}
if [ -z "${DOCS_API_SERVER:-}" ]; then
    timeout 900 cargo build --quiet -p custodio-it --example docs_api_server --locked || { echo "test-docs-api: cannot build the test server" >&2; exit 1; }
fi

# A private bus that lets any user own names and call them: the same bus in every run.
start_bus() { # start_bus DIR -> sets ADDRESS and BUS_PID
    mkdir -p "$1"
    cat > "$1/bus.conf" << CONF
<busconfig>
  <type>session</type>
  <listen>unix:path=$1/bus.sock</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
CONF
    dbus-daemon --config-file="$1/bus.conf" --nofork --print-address=3 3> "$1/address" > /dev/null 2>&1 &
    BUS_PID=$!
    timeout 20 sh -c 'until [ -s "$1" ]; do sleep 0.1; done' _ "$1/address" || { echo "test-docs-api: the private bus did not start" >&2; exit 1; }
    ADDRESS=$(head -n 1 "$1/address")
}

# run_doc FILE: the examples of FILE on a fresh bus; exit status of the runner.
run_doc() {
    local dir=$TMP/run.$RANDOM rc=0
    start_bus "$dir"
    python3 -I "$RUN" run "$1" "$ADDRESS" "$dir" "$SERVER" || rc=$?
    kill "$BUS_PID" 2> /dev/null || true
    wait "$BUS_PID" 2> /dev/null || true
    BUS_PID=
    return "$rc"
}

[ -s "$DOC" ] || { echo "test-docs-api: $DOC is missing or empty" >&2; exit 1; }
python3 -I "$RUN" static "$DOC" || fail=1
grep -qF 'docs/api.md' README.md || bad "README.md does not link docs/api.md"
[ -f docs/api.md ] || bad "the link target docs/api.md does not exist"
run_doc "$DOC" || fail=1

if [ -z "${CHECK_ONLY:-}" ] && [ "$fail" = 0 ]; then
    # control NAME CHECK(static|run) SED_OR_PY_EXPRESSION...: a broken copy must fail, and must differ from the real document.
    control() { # control NAME KIND COMMAND...: COMMAND reads the document on stdin and writes the broken copy
        local name=$1 kind=$2 copy=$TMP/copy.md rc=0
        shift 2
        "$@" < "$DOC" > "$copy"
        if cmp -s "$copy" "$DOC"; then bad "control '$name' did not change the document"; return; fi
        if [ "$kind" = static ]; then
            python3 -I "$RUN" static "$copy" > /dev/null 2>&1 || rc=$?
        else
            run_doc "$copy" > /dev/null 2>&1 || rc=$?
        fi
        if [ "$rc" = 0 ]; then bad "control '$name' passed on a broken document"; else echo "control ok: $name"; fi
    }
    # drop_blocks ATTR: the console blocks whose info string holds ATTR
    drop_blocks() {
        awk -v a="$1" '
            inblk && /^```$/ { inblk = 0; next }
            inblk { next }
            /^```console/ && index($0, a) { inblk = 1; next }
            { print }'
    }
    control "flag removed" static sed 's/--system-talk-name=com\.rfirma\.Custodio1/--system-talk-name=com.rfirma.Other/'
    control "error without explanation" static sed 's/^- error `com.rfirma.Custodio1.Error.UnsupportedKeyType`:.*$/- error `com.rfirma.Custodio1.Error.UnsupportedKeyType`: Message `unsupported key type`./'
    control "dialog row changed" static sed 's/| dialog on every call |/| no dialog |/'
    control "invented audit field" static sed 's/`CUSTODIO_APP_ID_STATE`/`CUSTODIO_INVENTED`/'
    control "compatibility link removed" static sed 's/audit.md#compatibility-rule/audit.md/'
    control "example action changed" run sed '0,/action=com.rfirma.custodio.sign/s//action=com.rfirma.custodio.delete-certificate/'
    control "documented result changed" run sed '0,/^s "ecdsa-p256"$/s//s "rsa2048"/'
    control "two error messages swapped" static sed 's/Message `not authorized`/Message `@@`/; s/Message `no such key`/Message `not authorized`/; s/Message `@@`/Message `no such key`/'
    control "error name altered" run sed '0,/error=PolkitDenied/s//error=NoSuchKey/'
    control "example removed for one operation" run drop_blocks 'op=ReplaceCertificate'
    control "command broken" run sed '0,/ ListKeys$/s// ListKeyz/'
fi
if [ "$fail" != 0 ]; then echo "test-docs-api: FAILED" >&2; exit 1; fi
echo "test-docs-api: ok"
