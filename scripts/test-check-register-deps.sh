#!/usr/bin/env bash
# Tests of scripts/check-register-deps.sh on fixture nfpm files (derived from packaging/nfpm.yaml by scripts/lib/nfpm_edit.py;
# no nfpm run, no package build): every control fails naming the format and the package.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-register-deps.sh
EDIT=$ROOT/scripts/lib/nfpm_edit.py
tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT
fail=0
bad() { echo "test-check-register-deps: $*" >&2; fail=1; }

"$GATE" "$ROOT/packaging/nfpm.yaml" > "$tmp/out" 2>&1 || bad "the real nfpm.yaml fails: $(cat "$tmp/out")"

# case NAME WORD... -- OP [ARG...]: a fixture from an edit of the real file; the gate must fail and name every WORD.
case_fail() {
    local name=$1 words=() word
    shift
    while [ "$1" != -- ]; do words+=("$1"); shift; done
    shift
    python3 -I "$EDIT" "$ROOT/packaging/nfpm.yaml" "$tmp/$name.yaml" "$@"
    if "$GATE" "$tmp/$name.yaml" > "$tmp/out" 2>&1; then bad "$name: the gate passed"; return; fi
    for word in "${words[@]}"; do
        grep -qF -- "$word" "$tmp/out" || bad "$name: output lacks '$word': $(cat "$tmp/out")"
    done
}

case_fail missing-deb deb: libnss3-tools -- dep-del deb libnss3-tools
case_fail other-format-rpm rpm: nss-tools libnss3-tools -- dep-set rpm nss-tools libnss3-tools
case_fail versioned-deb deb: libnss3-tools version -- dep-set deb libnss3-tools 'libnss3-tools (>= 3.0)'
# An nss package the table does not list.
case_fail extra-nss rpm: nss-util "does not list" -- dep-add rpm nss-util
exit "$fail"
