#!/usr/bin/env bash
# Test of docs/fingerprint.md (F207, acceptance 16). It runs every `console` block of the page as written, on the real
# `custodio` built with the test-only `fixture-root` feature, against a fixture root and a fake fprintd on a private bus
# (scripts/lib/docs-fprint-fixture.sh). Then it checks the effect of each block: `enable` wrote the file the page shows (compared
# byte for byte), `disable` removed it and the tree is as before, a refusal changed nothing, and `gsettings` was called with the
# argv fixed here from SPEC Design 5. The page holds only `console` and `text` blocks, and its links resolve.
# Prose (the limits, the lock screen, the other systems) is a person's. Negative controls: broken copies of the page must fail.
# Usage: scripts/test-docs-fingerprint.sh   (DOC overrides the page; CHECK_ONLY=1 skips the controls)
# The single-quoted strings are scripts for another shell or markdown with literal `$`, which must not expand here.
# shellcheck disable=SC2016
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
DOC=${DOC:-docs/fingerprint.md}
LIB=scripts/lib/docs_check.py
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; jobs -p | xargs -r kill 2> /dev/null || true' EXIT
fail=0
bad() { echo "test-docs-fingerprint: $*" >&2; fail=1; }

# shellcheck source=scripts/lib/docs-fprint-fixture.sh
. scripts/lib/docs-fprint-fixture.sh
fp_build test-docs-fingerprint || exit 1
[ -s "$DOC" ] || { echo "test-docs-fingerprint: $DOC is missing or empty" >&2; exit 1; }

# run_doc DOC DIR [KIND]: the console blocks of DOC on a fresh fixture root and bus; the status of the runner and the effect checks.
# KIND is `fingerprint` (the default: the effects of enable, disable, the refusals and gsettings are checked), `doctor` (the
# names of the checks `custodio doctor` printed are compared with the page's sections) or `install` (the blocks only).
run_doc() {
    local doc=$1 d=$2 kind=${3:-fingerprint} rc=0 want src=$DOC
    [ "$kind" != fingerprint ] || src=$doc
    mkdir -p "$d/work" "$d/bin"
    fp_wrappers "$d/bin"
    fp_root "$d/root" debian
    fp_tree "$d/root" > "$d/tree.before"
    # The file the page shows: the first `text` block that starts with the PAM header, as the bytes `enable` must have written.
    python3 -I - "$src" > "$d/shown.pam" << 'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
for m in re.finditer(r"^```text\n(.*?)^```", text, re.S | re.M):
    if m.group(1).startswith("#%PAM-1.0"):
        sys.stdout.write(m.group(1))
        break
PY
    cat > "$d/setup.sh" << SETUP
#!/bin/bash
set -e
ROOT=$ROOT
. $ROOT/scripts/lib/docs-fprint-fixture.sh
fp_doc_setup $d/root $d/bus "\$1"
fp_tree $d/root > $d/tree.fixture
SETUP
    cat > "$d/check.sh" << CHECK
#!/bin/bash
set -u
d=$d
pam=$d/root/etc/pam.d/polkit-1
ROOT=$ROOT
. $ROOT/scripts/lib/docs-fprint-fixture.sh
case \$1 in
    "sudo custodio setup fingerprint enable")
        cmp -s "\$pam" "\$d/shown.pam" || { echo "the file written differs from the file the page shows" >&2; exit 1; }
        echo enabled >> "\$d/checked" ;;
    "sudo custodio setup fingerprint disable")
        [ ! -e "\$pam" ] || { echo "the file is still there after disable" >&2; exit 1; }
        [ "\$(fp_tree $d/root)" = "\$(cat \$d/tree.before)" ] || { echo "the tree differs from before enable" >&2; exit 1; }
        echo disabled >> "\$d/checked" ;;
    *"fingerprint enable 2>&1" | *"fingerprint disable 2>&1")
        [ "\$(fp_tree $d/root)" = "\$(cat \$d/tree.fixture)" ] || { echo "a refused enable changed the tree" >&2; exit 1; }
        echo refused >> "\$d/checked" ;;
    "custodio doctor"*)
        custodio doctor 2> /dev/null | sed -E -n 's/^  (ok|FAIL|warn|\?) +([^ ]+( [^ ]+)*)  .*/\2/p' >> "\$d/names" ;;
    "gsettings set org.gnome.login-screen enable-fingerprint-authentication false")
        # The argv is fixed here (SPEC Design 5), not read from the page.
        [ "\$(cat \$d/gs.log)" = "set org.gnome.login-screen enable-fingerprint-authentication false" ] || { echo "gsettings was called with other arguments" >&2; exit 1; }
        echo gsettings >> "\$d/checked" ;;
esac
CHECK
    chmod +x "$d/setup.sh" "$d/check.sh"
    fp_bus "$d/bus" 1 list || { echo "test-docs-fingerprint: the fake fprintd did not start" >&2; fp_bus_stop; return 1; }
    HOME=$d/work PATH=$d/bin:$PATH CUSTODIO_FIXTURE_ROOT=$d/root CUSTODIO_FIXTURE_EUID=1000 GS_LOG=$d/gs.log \
        DOCS_FOR=fingerprint DOCS_SETUP=$d/setup.sh DOCS_CHECK=$d/check.sh timeout 300 python3 -I "$ROOT/$LIB" run "$doc" "$d/work" \
        2> "$d/run.err" > "$d/run.out" || rc=$?
    fp_bus_stop
    if [ "$kind" = fingerprint ]; then
        for want in enabled disabled refused gsettings; do
            grep -qx "$want" "$d/checked" 2> /dev/null || { echo "the effect '$want' was never checked: the page lacks the command" >&2; rc=1; }
        done
        [ "$(grep -cx refused "$d/checked" 2> /dev/null || true)" -ge 14 ] || { echo "fewer than fourteen refusals ran" >&2; rc=1; }
    elif [ "$kind" = doctor ]; then
        # Every check of the CLI has its section, and every section is a check of the CLI.
        python3 -I - "$doc" "$d/names" << 'PY' || rc=1
import re, sys
doc = open(sys.argv[1], encoding="utf-8").read()
try:
    cli = set(open(sys.argv[2], encoding="utf-8").read().split("\n")) - {""}
except OSError:
    cli = set()
doc = re.sub(r"^```.*?^```", "", doc, flags=re.S | re.M)
heads = set(re.findall(r"^### (.+?)\s*$", doc, re.M))
if len(cli) < 6 or cli != heads:
    print(f"the checks of the CLI {sorted(cli)} and the sections of the page {sorted(heads)} differ", file=sys.stderr)
    sys.exit(1)
PY
    fi
    sed -n 's/^/    /p' "$d/run.out" "$d/run.err" | tail -n 30 >&2
    return "$rc"
}

# static DOC: only console and text blocks, and links.
static() {
    local req=docs/threat-model.md
    [ "$#" -lt 2 ] || req=$2
    python3 -I "$LIB" kinds --only-console "$1" && python3 -I "$LIB" links "$1" ${req:+"$req"}
}
DOCTOR=${DOCTOR:-docs/doctor.md}
INSTALL=${INSTALL:-docs/install.md}
static "$DOC" || fail=1
static "$DOCTOR" "" || fail=1
# The new parts of docs/install.md (the sections `Fingerprint for polkit dialogs` and `Checking the system`) are console blocks and are
# run here; its bash blocks stay with test-docs-install.sh. A page where those sections are missing runs nothing and fails.
install_sections() {
    python3 -I - "$1" "$2" << 'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
parts = re.split(r"(?m)^(?=## )", text)
keep = [p for p in parts if re.match(r"## (Fingerprint for polkit dialogs|Checking the system)\n", p)]
body = "\n".join(keep)
if "custodio setup fingerprint enable" not in body or "$ custodio doctor" not in body:
    sys.exit("docs/install.md: its fingerprint and doctor sections do not run `custodio setup fingerprint enable` and `custodio doctor`")
open(sys.argv[2], "w", encoding="utf-8").write(body)
PY
}
install_sections "$INSTALL" "$TMP/install-new.md" || fail=1
python3 -I "$LIB" kinds --only-console "$TMP/install-new.md" || fail=1
run_doc "$DOC" "$TMP/real" || fail=1
run_doc "$DOCTOR" "$TMP/doctor" doctor || fail=1
run_doc "$TMP/install-new.md" "$TMP/install" install || fail=1

if [ -z "${CHECK_ONLY:-}" ] && [ "$fail" = 0 ]; then
    pids=() names=()
    # control NAME KIND COMMAND...: COMMAND reads the page on stdin and writes a broken copy; it must differ and must fail.
    control() {
        local name=$1 kind=$2 n=${#names[@]} copy orig=$DOC
        shift 2
        [ "$kind" != doctor ] || orig=$DOCTOR
        copy=$TMP/copy$n.md
        "$@" < "$orig" > "$copy"
        if cmp -s "$copy" "$orig"; then bad "control '$name' did not change the page"; return; fi
        if [ "$kind" = static ]; then
            if static "$copy" > /dev/null 2>&1; then bad "control '$name' passed on a broken page"; else echo "control ok: $name"; fi
            return
        fi
        (run_doc "$copy" "$TMP/ctl$n" "$([ "$kind" = doctor ] && echo doctor || echo fingerprint)" > /dev/null 2>&1 && exit 1 || exit 0) &
        pids+=($!)
        names+=("$name")
    }
    control "shown file differs by one character" run sed 's/max-tries=3 timeout=30$/max-tries=2 timeout=30/'
    control "setup command with an option the binary rejects" run sed '0,/^\$ sudo custodio setup fingerprint enable$/s//$ sudo custodio setup fingerprint enable --nonsense/'
    control "output line changed" run sed '0,/^      Undo: sudo custodio setup fingerprint disable$/s//      Undo: sudo custodio setup fingerprint off/'
    control "Debian package name under the Fedora heading" run sed '0,/^Install fprintd-pam and fprintd/s//Install libpam-fprintd and fprintd/'
    control "gsettings key changed" run sed 's/^\$ gsettings set org.gnome.login-screen enable-fingerprint-authentication false$/$ gsettings set org.gnome.login-screen enable-fingerprint false/'
    control "a refusal block removed" run python3 -I -c '
import re, sys
t = sys.stdin.read()
sys.stdout.write(re.sub(r"```console fails=yes fixture=omarchy\n.*?```\n", "", t, count=1, flags=re.S))'
    control "a doctor check's section removed" doctor python3 -I -c '
import re, sys
sys.stdout.write(re.sub(r"### journal\n.*?(?=### key storage)", "", sys.stdin.read(), count=1, flags=re.S))'
    control "doctor fix differs from the CLI's" doctor sed '0,/Fix: sudo custodio setup fingerprint enable/s//Fix: sudo custodio setup fingerprint on/'
    control "command moved into a bash block" static sed 's/^```console$/```bash/'
    control "command in a text block" static sed '0,/^```text$/s//```text\n$ rm -rf \/etc/'
    control "broken link" static sed 's#(threat-model\.md)#(no-such-file.md)#'
    control "unknown fence kind" static sed '0,/^```console$/s//```sh/'
    # The sections of docs/install.md renamed: nothing would run, and that must fail.
    sed 's/^## Checking the system$/## Checking things/' "$INSTALL" > "$TMP/install-renamed.md"
    if install_sections "$TMP/install-renamed.md" "$TMP/x.md" > /dev/null 2>&1; then bad "control 'install.md section renamed' passed"; else echo "control ok: install.md section renamed"; fi
    for i in "${!pids[@]}"; do
        if wait "${pids[$i]}"; then echo "control ok: ${names[$i]}"; else bad "control '${names[$i]}' passed on a broken page"; fi
    done
fi
echo "a person's: enrolling a finger, touching the reader, the lock screen and the Firefox restart (prose)"
if [ "$fail" != 0 ]; then echo "test-docs-fingerprint: FAILED" >&2; exit 1; fi
echo "test-docs-fingerprint: ok"
