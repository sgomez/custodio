#!/usr/bin/env bash
# Test of docs/threat-model.md and SECURITY.md (F185). Every relative link of both resolves to a file and a #anchor to a heading,
# SECURITY.md links the threat model, every fenced block has a known info string, and every `console` block runs as written
# (the threat model has none today: then nothing is built and no service starts). The rules of the shared helper
# (scripts/lib/docs_check.py) are proven here once, with negative controls on fixture documents; the README test does not
# repeat them. Usage: scripts/test-docs-threat-model.sh
# The single-quoted strings are scripts for another shell or markdown with literal `$`, which must not expand here.
# shellcheck disable=SC2016
set -euo pipefail
cd "$(dirname "$0")/.."
LIB=scripts/lib/docs_check.py
THREAT=${THREAT:-docs/threat-model.md}
SECURITY=${SECURITY:-SECURITY.md}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fail=0
bad() { echo "test-docs-threat-model: $*" >&2; fail=1; }

# check_doc DOC REQUIRED...: block kinds, links, and the console blocks (run only when there are some).
check_doc() {
    local doc=$1
    shift
    python3 -I "$LIB" kinds "$doc" || return 1
    python3 -I "$LIB" links "$doc" "$@" || return 1
    if grep -q '^```console' "$doc"; then
        timeout 900 cargo build --quiet --locked -p custodio-cli || return 1
        mkdir -p "$TMP/bin" "$TMP/cwd"
        ln -sf "$PWD/target/debug/custodio-cli" "$TMP/bin/custodio"
        PATH=$TMP/bin:$PATH python3 -I "$LIB" run "$doc" "$TMP/cwd" || return 1
    fi
}

[ -s "$THREAT" ] || { echo "test-docs-threat-model: $THREAT is missing or empty" >&2; exit 1; }
check_doc "$THREAT" || fail=1
check_doc "$SECURITY" "$THREAT" || fail=1

# Controls: each must fail.
control() { # control NAME DOC REQUIRED...
    local name=$1 doc=$2
    shift 2
    if check_doc "$doc" "$@" > /dev/null 2>&1; then bad "control '$name' passed"; else echo "control ok: $name"; fi
}
if [ "$fail" = 0 ]; then
    mkdir -p "$TMP/c"
    printf '# Other\n\n## A heading\n' > "$TMP/c/other.md"
    printf '# T\n\nSee [other](other.md#a-heading) and [here](#t).\n' > "$TMP/c/good.md"
    check_doc "$TMP/c/good.md" "$TMP/c/other.md" > /dev/null 2>&1 || bad "the good fixture fails"
    sed 's#(other\.md\#a-heading)#(nothing.md)#' "$TMP/c/good.md" > "$TMP/c/missing-file.md"
    sed 's#a-heading#no-such-heading#' "$TMP/c/good.md" > "$TMP/c/missing-anchor.md"
    printf '# T\n\n```\n$ true\n```\n' > "$TMP/c/no-info.md"
    printf '# T\n\n```sh\n$ true\n```\n' > "$TMP/c/other-info.md"
    printf '# T\n\n```console\n$ false\n```\n' > "$TMP/c/exit.md"
    printf '# T\n\n```console\n$ echo hi\nbye\n```\n' > "$TMP/c/output.md"
    printf '# T\n\nNo link.\n' > "$TMP/c/no-link.md"
    control "link to a missing file" "$TMP/c/missing-file.md"
    control "link to a missing heading" "$TMP/c/missing-anchor.md"
    control "a block with no info string" "$TMP/c/no-info.md"
    control "a block with an unknown info string" "$TMP/c/other-info.md"
    control "a console command that fails" "$TMP/c/exit.md"
    control "a console output that differs" "$TMP/c/output.md"
    control "a required link that is missing" "$TMP/c/no-link.md" "$TMP/c/other.md"
    # The real SECURITY.md with its threat-model link pointing at another file that exists: only the required link is missing.
    mkdir -p "$TMP/s"
    : > "$TMP/s/README.md"
    sed 's#(docs/threat-model\.md)#(README.md)#g' "$SECURITY" > "$TMP/s/SECURITY.md"
    if cmp -s "$TMP/s/SECURITY.md" "$SECURITY"; then bad "the SECURITY.md control did not change the file"; fi
    control "SECURITY.md without the threat-model link" "$TMP/s/SECURITY.md" "$THREAT"
fi
if [ "$fail" != 0 ]; then echo "test-docs-threat-model: FAILED" >&2; exit 1; fi
echo "test-docs-threat-model: ok"
