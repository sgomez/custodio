#!/usr/bin/env bash
# Test of the release notes (F186). The systems the notes name as supported equal the targets of e2e/targets, the README links
# the notes, every relative link resolves, the block-kind rule holds, the `console` blocks run as written (`custodio register` on
# the real CLI, the fixtures of F185), and the notes carry the version of their file name (title and every vX.Y.Z).
# The notes' version is not compared with Cargo.toml. Prose is a person's
# (SPEC acceptance 20). Negative controls: broken copies of the notes, the README or the targets must fail.
# Usage: scripts/test-docs-release-notes.sh   (DOC, README_DOC, TARGETS override the real files; CHECK_ONLY=1 skips the controls)
# shellcheck disable=SC2016,SC2034,SC1091,SC2086,SC2116
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
DOC=${DOC:-docs/release-notes-v0.9.0.md}
README_DOC=${README_DOC:-README.md}
TARGETS=${TARGETS:-e2e/targets}
LIB=scripts/lib/docs_check.py
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
CLI=$ROOT/target/debug/custodio-cli
NAME=test-docs-release-notes
fail=0
bad() { echo "$NAME: $*" >&2; fail=1; }
timeout 900 cargo build --quiet --locked -p custodio-cli || { echo "$NAME: cannot build custodio-cli" >&2; exit 1; }
# shellcheck source=scripts/lib/docs-register-fixture.sh
. scripts/lib/docs-register-fixture.sh
reg_probe "$TMP/probe" || exit 1

# The system name of each e2e target; an unknown directory fails, as test-docs-install.sh does.
declare -A SYSTEM=([debian13]='Debian 13' [ubuntu2604]='Ubuntu 26.04' [fedora44]='Fedora 44' [alma10]='RHEL/Alma 10' [arch]='Arch')

# systems DOC TARGETS: the supported systems of the notes (the items of the section "Supported systems", the name up to " — ")
# equal the targets' systems.
systems() {
    local doc=$1 targets=$2 t want have
    want=$(for t in "$targets"/*/; do
        t=$(basename "$t")
        [ -n "${SYSTEM[$t]:-}" ] || { echo "unknown target directory $t: add it to the table of $NAME" >&2; echo "?$t"; continue; }
        echo "${SYSTEM[$t]}"
    done | sort)
    case $want in *'?'*) return 1 ;; esac
    have=$(awk '
        /^```/ { fence = !fence }
        !fence && /^#+ / { on = ($0 ~ /^## Supported systems[[:space:]]*$/); next }
        on && /^[-*] / { sub(/^[-*] +/, ""); sub(/ — .*$/, ""); sub(/[[:space:]]+$/, ""); print }
    ' "$doc" | sort)
    [ -n "$have" ] || { echo "$doc: no list under the heading '## Supported systems'" >&2; return 1; }
    [ "$have" = "$want" ] || { echo "$doc: the supported systems differ from $targets: notes [$(echo $have)] targets [$(echo $want)]" >&2; return 1; }
}

# version DOC: the version of the notes is the one in the file name (release-notes-vX.Y.Z.md); the title and every vX.Y.Z of the text equal it.
version() {
    local want have
    want=$(basename "$1" | sed -n 's/^release-notes-\(v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)\.md$/\1/p')
    [ -n "$want" ] || { echo "$1: the file name is not release-notes-vX.Y.Z.md" >&2; return 1; }
    # a link target is a path (the previous notes' file name), not a version the notes name
    have=$(sed 's/\](\([^)]*\))/]()/g' "$1" | grep -o 'v[0-9]\+\.[0-9]\+\.[0-9]\+' | sort -u | tr '\n' ' ')
    [ "$have" = "$want " ] || { echo "$1 names the versions [$have], the file name says $want" >&2; return 1; }
    head -n 1 "$1" | grep -q -- "$want" || { echo "$1: the first line (the title) does not carry $want" >&2; return 1; }
}

# static DOC README TARGETS (README only for the links check the caller makes)
static() {
    local rc=0
    [ -s "$1" ] || { echo "$1 is missing or empty" >&2; return 1; }
    python3 -I "$LIB" kinds --only-console "$1" || rc=1
    python3 -I "$LIB" links "$1" || rc=1
    systems "$1" "$3" || rc=1
    version "$1" || rc=1
    return "$rc"
}
# the README must link the notes at their real path (the control copies are other files)
readme_links() { python3 -I "$LIB" links "$README_DOC" "$DOC"; }

run_notes() { # run_notes DOC DIR
    local want=()
    ! grep -q '^\$ custodio register$' "$1" || want=(registered)
    reg_run "$1" "$2" "${want[@]}"
}

static "$DOC" "$README_DOC" "$TARGETS" || fail=1
readme_links || fail=1
run_notes "$DOC" "$TMP/real" || fail=1

if [ -z "${CHECK_ONLY:-}" ] && [ "$fail" = 0 ]; then
    pids=() names=()
    # control NAME KIND FILE COMMAND...: COMMAND reads FILE (notes, readme) on stdin and writes a broken copy; it must differ and fail.
    control() {
        local name=$1 kind=$2 src=$3 n=${#names[@]} copy
        shift 3
        copy=$TMP/copy$n.md
        "$@" < "$src" > "$copy"
        if cmp -s "$copy" "$src"; then bad "control '$name' did not change $src"; return; fi
        case $kind in
            static) if static "$copy" "$README_DOC" "$TARGETS" > /dev/null 2>&1; then bad "control '$name' passed on a broken copy"; else echo "control ok: $name"; fi; return ;;
            readme) if python3 -I "$LIB" links "$copy" "$DOC" > /dev/null 2>&1; then bad "control '$name' passed on a broken README"; else echo "control ok: $name"; fi; return ;;
        esac
        (run_notes "$copy" "$TMP/ctl$n" > /dev/null 2>&1 && exit 1 || exit 0) &
        pids+=($!)
        names+=("$name")
    }
    control "a system dropped from the notes" static "$DOC" sed '/^- Arch\b/d'
    control "a system with no target added" static "$DOC" sed '0,/^- Arch\b/s//- Gentoo\n- Arch/'
    control "README without the link to the notes" readme "$README_DOC" sed "s#(${DOC}[^)]*)#(docs/install.md)#g; s#(${DOC#docs/}[^)]*)#(docs/install.md)#g"
    control "a broken link in the notes" static "$DOC" sed '$a [x](no-such-file.md)'
    VER=$(basename "$DOC" .md); VER=${VER#release-notes-}
    control "version v1.0.0" static "$DOC" sed "s/${VER//./\\.}/v1.0.0/g"
    control "title with another version" static "$DOC" sed "1s/${VER//./\\.}/v0.0.1/"
    control "a bash block in the notes" static "$DOC" sed '$a \n```bash\ntrue\n```'
    control "a console command that fails" run "$DOC" sed 's/^\$ custodio register$/$ custodio register --nonsense/'
    # an unknown directory in a copy of e2e/targets
    mkdir -p "$TMP/targets"
    cp -r "$TARGETS"/. "$TMP/targets/"
    mkdir "$TMP/targets/slackware"
    if systems "$DOC" "$TMP/targets" > /dev/null 2>&1; then bad "control 'unknown target directory' passed"; else echo "control ok: unknown target directory"; fi
    for i in "${!pids[@]}"; do
        if wait "${pids[$i]}"; then echo "control ok: ${names[$i]}"; else bad "control '${names[$i]}' passed on a broken copy"; fi
    done
fi
if [ "$fail" != 0 ]; then echo "$NAME: FAILED" >&2; exit 1; fi
echo "$NAME: ok"
