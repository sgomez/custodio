#!/usr/bin/env bash
# Tests of scripts/check-test-label.sh (F175) on copies of the shipped files with one fault each: the gate passes the shipped tree, and fails,
# with a message that names the fault, when the test-only source (the test-seam feature) is turned on in a unit file, in nfpm.yaml, in a packaging
# script, in any other file of data/, as a normal dependency feature, as another feature's member or as a default feature.
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
"$GATE" > /dev/null 2>&1 || bad "the shipped tree fails"
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
add_file() { # LABEL FILE CONTENT WORD: a new file
    local out
    fresh case
    mkdir -p "$tmp/case/$(dirname "$2")"
    printf '%s\n' "$3" > "$tmp/case/$2"
    if out=$("$GATE" "$tmp/case" 2>&1); then bad "$1: the gate passed"; return; fi
    grep -q -- "$4" <<< "$out" || bad "$1: the message does not hold '$4': $out"
}

U=data/custodio.service
N=packaging/nfpm.yaml
C=crates/custodiod/Cargo.toml
append "feature in an Environment= of the unit" $U 'Environment=CUSTODIOD_FEATURES=test-seam' 'must not ship'
append "feature in a socket unit" data/custodio-firefox.socket '# --features test-seam' 'must not ship'
append "feature in nfpm.yaml" $N '# build with --features test-seam' 'must not ship'
add_file "feature in a packaging script" packaging/postinst 'cargo build --features test-seam' 'must not ship'
add_file "feature in a data/ file" data/extra.conf 'test-seam' 'must not ship'
add_file "feature in a nested data/ file" data/tmpfiles.d/other.conf 'x test-seam y' 'must not ship'
# Cargo.toml: the dev-dependency and the definition are the only places.
expect_fail "normal dependency feature" $C 's|^zeroize = "1.9.1"|zeroize = "1.9.1"\ncustodiod-x = { path = ".", features = ["test-seam"] }|' 'outside \[dev-dependencies\]'
expect_fail "build dependency feature" $C 's|^\[dev-dependencies\]|[build-dependencies]\ncustodiod-x = { path = ".", features = ["test-seam"] }\n\n[dev-dependencies]|' 'outside \[dev-dependencies\]'
expect_fail "default feature in the features section" $C 's|^test-seam = \[\]|test-seam = []\ndefault = ["test-seam"]|' 'outside \[dev-dependencies\]'
expect_fail "another feature turns it on" $C 's|^test-seam = \[\]|test-seam = []\nshipped = ["test-seam"]|' 'outside \[dev-dependencies\]'
expect_fail "another crate's normal dependency" crates/custodio-cli/Cargo.toml 's|^\[dependencies\]|[dependencies]\ncustodiod = { path = "../custodiod", features = ["test-seam"] }|' 'outside \[dev-dependencies\]'
# The fuzz crate may name it on its one dependency line, and on no other.
fresh case
"$GATE" "$tmp/case" > /dev/null 2>&1 || bad "the fuzz crate's dependency line fails"
expect_fail "fuzz crate: another dependency with the feature" crates/custodiod/fuzz/Cargo.toml 's|^tempfile = "3.27.0"|tempfile = "3.27.0"\ncustodiod-x = { path = "..", features = ["test-seam"] }|' 'outside \[dev-dependencies\]'
# A dev-dependency that turns it on and a comment that names it are fine.
fresh case
printf '# test-seam is only a dev-dependency feature\n' >> "$tmp/case/$C"
"$GATE" "$tmp/case" > /dev/null 2>&1 || bad "a comment naming the feature fails"
exit "$fail"
