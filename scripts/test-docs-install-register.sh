#!/usr/bin/env bash
# Test of the registration parts of docs/install.md (F186). It runs the `console` blocks of the page on the real `custodio`
# (`register`, `register --remove`; the fixtures of F185: a temporary HOME, a stub `modutil` first on PATH, an overlay that
# supplies /usr/lib/custodio/libcustodio_pkcs11.so) and checks their effect. The manual fallback is in `bash` blocks, which the
# runner never runs, so this script runs them itself: `<profile directory>` is a placeholder of the page, and the script
# substitutes a fixture profile directory for it (nothing else is substituted); they run against the real /usr/bin/modutil in an
# NSS database of that profile and the real built module, and their options are compared with what `custodio setup browsers enable` passed to
# the stub (the page leaves out `-force`, which stops modutil's confirmation question; docs/install.md says so). The
# `register --remove` block must come before the block that removes the package. Links resolve; `bash` blocks are counted.
# Negative controls: broken copies of the page must fail. Prose is a person's (acceptance 20).
# Usage: scripts/test-docs-install-register.sh   (DOC overrides the page; CHECK_ONLY=1 skips the controls)
# shellcheck disable=SC2016,SC2034,SC1091
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
DOC=${DOC:-docs/install.md}
LIB=scripts/lib/docs_check.py
CHK=scripts/lib/docs_install_check.py
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
CLI=$ROOT/target/debug/custodio-cli
NAME=test-docs-install-register
fail=0
bad() { echo "$NAME: $*" >&2; fail=1; }
for tool in python3 unshare modutil; do
    command -v "$tool" > /dev/null 2>&1 || { echo "$NAME: $tool is not installed" >&2; exit 127; }
done
timeout 900 cargo build --quiet --locked -p custodio-cli -p custodio-pkcs11 || { echo "$NAME: cannot build custodio-cli and the module" >&2; exit 1; }
MODULE=$ROOT/target/debug/libcustodio_pkcs11.so
[ -f "$MODULE" ] || { echo "$NAME: $MODULE is missing" >&2; exit 1; }
. scripts/lib/docs-register-fixture.sh
reg_probe "$TMP/probe" || exit 1

# real_modutil DIR: the page's two fallback commands on the real modutil in an NSS database of a fresh profile; the module
# is at /usr/lib/custodio in an overlay. After the add it is listed with that library, after the delete it is not.
real_modutil() {
    local d=$1
    mkdir -p "$d/stage/custodio" "$d/ov" "$d/profile"
    cp "$MODULE" "$d/stage/custodio/libcustodio_pkcs11.so"
    unshare -rm sh -c '
        d=$1
        mount -t tmpfs tmpfs "$d/ov" && mkdir "$d/ov/up" "$d/ov/wk" &&
        mount -t overlay overlay -o "lowerdir=$d/stage:/usr/lib,upperdir=$d/ov/up,workdir=$d/ov/wk" /usr/lib || exit 1
        modutil -create -dbdir "sql:$d/profile" -force < /dev/null > /dev/null 2>&1 || { echo "modutil -create failed" >&2; exit 1; }
        sh "$d/add.sh" < /dev/null > /dev/null 2>&1 || { echo "the page'"'"'s modutil -add failed" >&2; exit 1; }
        modutil -dbdir "sql:$d/profile" -list < /dev/null 2> /dev/null | grep -q "library name: /usr/lib/custodio/libcustodio_pkcs11.so" || { echo "the module is not listed after -add" >&2; exit 1; }
        sh "$d/del.sh" < /dev/null > /dev/null 2>&1 || { echo "the page'"'"'s modutil -delete failed" >&2; exit 1; }
        ! modutil -dbdir "sql:$d/profile" -list < /dev/null 2> /dev/null | grep -q "library name: /usr/lib/custodio" || { echo "the module is still listed after -delete" >&2; exit 1; }
    ' sh "$d"
}

# check_doc DOC DIR: everything about one copy of the page; the status is non-zero when anything fails.
check_doc() {
    local doc=$1 d=$2 rc=0
    mkdir -p "$d"
    [ -s "$doc" ] || { echo "$doc is missing or empty" >&2; return 1; }
    python3 -I "$LIB" kinds "$doc" || rc=1
    python3 -I "$LIB" links "$doc" || rc=1
    python3 -I "$CHK" order "$doc" || rc=1
    reg_run "$doc" "$d/reg" registered removed || rc=1
    mkdir -p "$d/fb"
    PROFILE=$d/fb/profile python3 -I "$CHK" fallback "$doc" "$d/reg/modutil.log" "$d/fb" || return 1
    real_modutil "$d/fb" || rc=1
    return "$rc"
}

check_doc "$DOC" "$TMP/real" || fail=1

if [ -z "${CHECK_ONLY:-}" ] && [ "$fail" = 0 ]; then
    pids=() names=()
    # control NAME COMMAND...: COMMAND reads the page on stdin and writes a broken copy; it must differ and must fail.
    control() {
        local name=$1 n=${#names[@]} copy
        shift 1
        copy=$TMP/copy$n.md
        "$@" < "$DOC" > "$copy"
        if cmp -s "$copy" "$DOC"; then bad "control '$name' did not change the page"; return; fi
        (check_doc "$copy" "$TMP/ctl$n" > /dev/null 2>&1 && exit 1 || exit 0) &
        pids+=($!)
        names+=("$name")
    }
    control "register command altered" sed '0,/^\$ custodio setup browsers enable$/s//$ custodio setup browsers enabel/'
    control "an output line altered" sed '0,/module copy: placed$/s//module copy: kept/'
    control "remove replaced by refresh-only" sed 's/^\$ custodio setup browsers disable$/$ custodio setup browsers refresh/'
    control "the -libfile path of the fallback altered" sed '0,/^modutil .* -add .*libcustodio_pkcs11\.so$/s//&.old/'
    control "the fallback -add block removed" sed '/^modutil .* -add /d'
    control "the fallback -delete block removed" sed '/^modutil .* -delete /d'
    control "the fallback database option altered" sed '0,/^modutil -dbdir sql:/s//modutil -dbdir dbm:/'
    control "a broken link" sed '$a [x](no-such-file.md)'
    # the removal block before the unregister block: swap the two blocks of the section
    swap() {
        python3 -I -c '
import re, sys
t = sys.stdin.read()
a = t.index("## Removing and purging")
con = re.search(r"```console\n\$ custodio setup browsers disable\n.*?```\n", t[a:], re.S)
rem = re.search(r"```bash\nsudo apt-get remove custodio\n.*?```\n", t[a:], re.S)
c, r = con.group(0), rem.group(0)
sys.stdout.write(t[:a] + t[a:].replace(c, "@@C@@").replace(r, "@@R@@").replace("@@C@@", r).replace("@@R@@", c))'
    }
    control "the removal block before the unregister block" swap
    for i in "${!pids[@]}"; do
        if wait "${pids[$i]}"; then echo "control ok: ${names[$i]}"; else bad "control '${names[$i]}' passed on a broken page"; fi
    done
fi
if [ "$fail" != 0 ]; then echo "$NAME: FAILED" >&2; exit 1; fi
echo "$NAME: ok"
