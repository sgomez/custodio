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
case_fail missing-rpm rpm: nss-tools -- dep-del rpm nss-tools
case_fail missing-arch arch: nss -- dep-del archlinux nss
case_fail wrong-name-deb deb: libnss3-tools nss-tools -- dep-set deb libnss3-tools nss-tools
case_fail other-format-rpm rpm: nss-tools libnss3-tools -- dep-set rpm nss-tools libnss3-tools
case_fail other-format-arch arch: nss nss-tools -- dep-set archlinux nss nss-tools
case_fail misspelled-arch arch: nss nssl -- dep-set archlinux nss nssl
case_fail versioned-deb deb: libnss3-tools version -- dep-set deb libnss3-tools 'libnss3-tools (>= 3.0)'
case_fail versioned-rpm rpm: nss-tools version -- dep-set rpm nss-tools 'nss-tools >= 3'
# In another section than that format's depends: Pre-Depends does not count.
case_fail predepends-deb deb: libnss3-tools -- dep-del deb libnss3-tools
python3 -I "$EDIT" "$tmp/predepends-deb.yaml" "$tmp/predepends-deb2.yaml" predep-add libnss3-tools
"$GATE" "$tmp/predepends-deb2.yaml" > "$tmp/out" 2>&1 && bad "predepends-deb2: a Pre-Depends entry passed" || grep -qF "deb: the modutil package 'libnss3-tools'" "$tmp/out" || bad "predepends-deb2: wrong output: $(cat "$tmp/out")"
# In the recommends list, and only in a comment.
python3 -I "$EDIT" "$tmp/missing-rpm.yaml" "$tmp/rec-rpm.yaml" recommends-add rpm nss-tools
"$GATE" "$tmp/rec-rpm.yaml" > "$tmp/out" 2>&1 && bad "rec-rpm: a Recommends entry passed" || grep -qF "rpm: the modutil package 'nss-tools'" "$tmp/out" || bad "rec-rpm: wrong output: $(cat "$tmp/out")"
sed 's/^      - nss # .*/      # nss/' "$ROOT/packaging/nfpm.yaml" > "$tmp/comment.yaml"
cmp -s "$tmp/comment.yaml" "$ROOT/packaging/nfpm.yaml" && bad "comment: the edit changed nothing"
if "$GATE" "$tmp/comment.yaml" > "$tmp/out" 2>&1; then bad "comment: a name in a comment passed"; else grep -qF "arch: the modutil package 'nss'" "$tmp/out" || bad "comment: wrong output: $(cat "$tmp/out")"; fi
# An nss package the table does not list.
case_fail extra-nss rpm: nss-util "does not list" -- dep-add rpm nss-util
# Input errors.
"$GATE" "$tmp/none.yaml" > "$tmp/out" 2>&1 && bad "missing file passed"
exit "$fail"
