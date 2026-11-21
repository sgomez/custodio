#!/usr/bin/env bash
# Test of sections 26 onward of docs/manual-acceptance.md (F208, acceptance 16 for the M7 manual steps). It cuts the page at section 26 and
# runs every `console` block there as written, in one fixture system, with the stand-ins of test-docs-guide.sh (the real dpkg installs,
# removes and purges the .deb; the real custodio on private buses with a fake fprintd), so the install notice and every output the page
# shows are compared. Then it runs the page's own final-checks script (the `bash` block of the page) on the fixture root: clean after the
# documented way back; on a fixture left dirty, each check must say NOT CLEAN by itself (one control per check). The kept paths come from
# that block, not from this script. A person's (listed below): the .p12 exported from Firefox, every touch of the reader, pkexec with a
# finger, the real site, Tab at the shell, the reviews of sections 27 and 28. Negative controls: broken copies of the page must fail.
# Usage: scripts/test-docs-manual-m7.sh   (DOC overrides the page; CHECK_ONLY=1 skips the controls)
# shellcheck disable=SC2016
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

# The hook the guide script runs after the way back (AFTER_RUN): the final checks on the fixture root.
if [ -n "${M7_MODE:-}" ]; then
    d=$1
    R=$d/droot
    mkdir -p "$R/etc/pam.d"
    [ ! -d "$d/root/etc/pam.d" ] || cp -a "$d/root/etc/pam.d/." "$R/etc/pam.d/"
    prof=$(compgen -G "$d/home/.mozilla/firefox/*/pkcs11.txt" | head -n 1)
    case $M7_MODE in
        clean) ;;
        pam) echo '#PAM' > "$R/etc/pam.d/polkit-1" ;;
        profile) echo 'library=libcustodio_pkcs11.so' >> "$prof" ;;
        copy) mkdir -p "$d/home/snap/firefox/common"; : > "$d/home/snap/firefox/common/libcustodio_pkcs11.so" ;;
        extra) : > "$R/etc/custodio-leftover.conf" ;;
    esac
    rc=0
    out=$(R=$R HOME=$d/home bash "$M7_CHECKS") || rc=$?
    echo "$out" > "$(dirname "$M7_CHECKS")/final.out"
    if [ "$M7_MODE" = clean ]; then
        [ "$rc" = 0 ] && [ "$(grep -c '^clean: ' "$(dirname "$M7_CHECKS")/final.out")" = 4 ] || { echo "the final checks are not clean after the way back:" >&2; echo "$out" >&2; exit 1; }
    else
        # the check for that dirt reports NOT CLEAN by itself, and the exit status says so
        case $M7_MODE in pam) want='polkit-1' ;; profile) want='Firefox profiles' ;; copy) want='copy of the module' ;; extra) want='nothing left' ;; esac
        if [ "$rc" != 1 ] || ! grep -q "^NOT CLEAN: .*$want" "$(dirname "$M7_CHECKS")/final.out"; then echo "the final checks did not catch '$M7_MODE':" >&2; echo "$out" >&2; exit 1; fi
    fi
    exit 0
fi

DOC=${DOC:-docs/manual-acceptance.md}
LIB=scripts/lib/docs_check.py
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; jobs -p | xargs -r kill 2> /dev/null || true' EXIT
NAME=test-docs-manual-m7
fail=0
bad() { echo "$NAME: $*" >&2; fail=1; }
[ -s "$DOC" ] || { echo "$NAME: $DOC is missing or empty" >&2; exit 1; }

# prepare PAGE DIR: the sections from 26 on in DIR/tree/docs/m7.md (links resolve as in the real tree); the page's `bash` block in DIR/checks.sh,
# and the cut without it (the guide script runs only `console` blocks).
prepare() {
    local page=$1 dir=$2 e
    mkdir -p "$dir/tree"
    for e in "$ROOT"/*; do [ "$(basename "$e")" = docs ] || ln -sfn "$e" "$dir/tree/$(basename "$e")"; done
    [ -d "$dir/tree/docs" ] || cp -rs "$ROOT/docs" "$dir/tree/docs"
    awk '/^## 26\. /{f=1} f' "$page" > "$dir/cut.md"
    # the bash block that holds the final checks (it defines check()); the other kinds stay for the kind rule
    python3 -I -c '
import re, sys
t = open(sys.argv[1]).read()
blocks = [m for m in re.finditer(r"```bash\n(.*?)```\n", t, re.S) if "check() {" in m.group(1)]
if blocks:
    open(sys.argv[2], "w").write(blocks[0].group(1))
    t = t.replace(blocks[0].group(0), "")
open(sys.argv[3], "w").write(t)' "$dir/cut.md" "$dir/checks.sh" "$dir/tree/docs/m7.md"
    touch "$dir/checks.sh"
    [ -s "$dir/checks.sh" ] || { echo "the page has no bash block with the final checks from section 26 on" >&2; return 1; }
    grep -q '^## 26\. ' "$dir/cut.md" || { echo "the page has no section 26" >&2; return 1; }
}
# run_page PAGE DIR MODE: the guide script's run of the cut, with the final checks as its after-run hook.
run_page() {
    prepare "$1" "$2" || return 1
    M7_MODE=$3 M7_CHECKS=$2/checks.sh AFTER_RUN=$ROOT/scripts/test-docs-manual-m7.sh DOC=$2/tree/docs/m7.md CHECK_ONLY=1 \
        timeout 600 scripts/test-docs-guide.sh > "$2/out" 2>&1 || { tail -n 25 "$2/out" >&2; return 1; }
}
static() { # static DIR: block kinds of the cut (console and text only) and the links of the real page
    python3 -I "$LIB" kinds --only-console "$1/tree/docs/m7.md" && python3 -I "$LIB" links "$DOC"
}

prepare "$DOC" "$TMP/real" || exit 1
static "$TMP/real" || fail=1
run_page "$DOC" "$TMP/real" clean || fail=1
[ "$(grep -c "^clean: " "$TMP/real/final.out" 2>/dev/null)" = 4 ] || { bad "the final checks did not run"; }
echo "the commands that ran, with their handlers:"; grep -A40 'every command and the handler' "$TMP/real/out" | head -n 30 || true

if [ -z "${CHECK_ONLY:-}" ] && [ "$fail" = 0 ]; then
    pids=() names=()
    # control NAME KIND COMMAND...: COMMAND reads the page on stdin and writes a broken copy; it must differ and fail.
    control() {
        local name=$1 kind=$2 n=${#names[@]} copy
        copy=$TMP/copy$n.md
        shift 2
        "$@" < "$DOC" > "$copy"
        if cmp -s "$copy" "$DOC"; then bad "control '$name' did not change the page"; return; fi
        if [ "$kind" = static ]; then
            prepare "$copy" "$TMP/c$n" > /dev/null 2>&1 || { echo "control ok: $name"; return; }
            if static "$TMP/c$n" > /dev/null 2>&1; then bad "control '$name' passed on a broken page"; else echo "control ok: $name"; fi
            return
        fi
        (run_page "$copy" "$TMP/c$n" clean > /dev/null 2>&1 && exit 1 || exit 0) &
        pids+=($!)
        names+=("$name")
    }
    control "a bash block where a console is required" static python3 -I -c '
import sys
t = sys.stdin.read()
sys.stdout.write(t.replace("```console\n$ custodio list\n", "```bash\n$ custodio list\n", 1))'
    control "a custodio command with a wrong flag" run sed '0,/^\$ custodio import --id ana ana.p12$/s//$ custodio import --idd ana ana.p12/'
    control "an output line changed" run sed '0,/^warn  ana  /s//warn  anx  /'
    control "an extra console command whose output then differs" run python3 -I -c '
import re, sys
t = sys.stdin.read()
m = re.search(r"(```console\n\$ custodio delete ana\n)", t)
sys.stdout.write(t.replace(m.group(1), m.group(1) + "$ custodio list\n", 1))'
    control "setup browsers disable missing from the way back" run python3 -I -c '
import re, sys
t = sys.stdin.read()
m = re.search(r"```console\n\$ custodio setup browsers disable\n(?:(?!```).)*```\n", t, re.S)
sys.stdout.write(t.replace(m.group(0), ""))'
    # the final checks on a fixture left dirty: each check reports NOT CLEAN by itself
    for mode in pam profile copy extra; do
        (run_page "$DOC" "$TMP/d$mode" "$mode" > /dev/null 2>&1 && exit 0 || exit 1) &
        pids+=($!)
        names+=("final check catches a dirty fixture: $mode")
    done
    for i in "${!pids[@]}"; do
        if wait "${pids[$i]}"; then echo "control ok: ${names[$i]}"; else bad "control '${names[$i]}' failed (or passed on a broken page)"; fi
    done
fi
echo "a person's: exporting the .p12 from Firefox and the certificate imported from it, every touch of the reader, pkexec and sudo with a finger, the real site, Tab at the shell, the reviews of sections 27 and 28"
if [ "$fail" != 0 ]; then echo "$NAME: FAILED" >&2; exit 1; fi
echo "$NAME: ok"
