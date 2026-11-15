#!/usr/bin/env bash
# Test of scripts/check-test-label.sh (F175) on copies of the shipped files with one fault each: the gate passes the copy and fails, naming the
# fault, when the test-only source (the test-seam feature) is turned on in a shipped file or as a normal dependency feature.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-test-label.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-check-test-label: $*" >&2; fail=1; }

fresh() { # NAME: a copy of data/, packaging/ and the manifests under $tmp/NAME
    local f
    rm -rf "${tmp:?}/$1"
    mkdir -p "$tmp/$1"
    cp -r "$ROOT/data" "$ROOT/packaging" "$tmp/$1/"
    while IFS= read -r f; do
        mkdir -p "$tmp/$1/$(dirname "${f#"$ROOT"/}")"
        cp "$f" "$tmp/$1/${f#"$ROOT"/}"
    done < <(find "$ROOT" -name Cargo.toml -not -path '*/target/*' -not -path '*/.git/*')
}
fresh ok
"$GATE" "$tmp/ok" > /dev/null 2>&1 || bad "the copy of the shipped tree fails"

expect_fail() { # LABEL FILE SED-EXPRESSION WORD
    local out
    fresh case
    sed -i "$3" "$tmp/case/$2"
    if cmp -s "$ROOT/$2" "$tmp/case/$2"; then bad "$1: the fixture changed nothing"; return; fi
    if out=$("$GATE" "$tmp/case" 2>&1); then bad "$1: the gate passed"; return; fi
    grep -q -- "$4" <<< "$out" || bad "$1: the message does not hold '$4': $out"
}
append() { # LABEL FILE LINE WORD
    expect_fail "$1" "$2" "\$a\\
$3" "$4"
}
U=data/custodio.service
C=crates/custodiod/Cargo.toml
append "feature in an Environment= of the unit" $U 'Environment=CUSTODIOD_FEATURES=test-seam' 'must not ship'
# Cargo.toml: the dev-dependency and the definition are the only places.
expect_fail "normal dependency feature" $C 's|^zeroize = "1.9.1"|zeroize = "1.9.1"\ncustodiod-x = { path = ".", features = ["test-seam"] }|' 'outside \[dev-dependencies\]'
exit "$fail"
