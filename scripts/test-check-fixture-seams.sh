#!/usr/bin/env bash
# Test of scripts/check-fixture-seams.sh (F197): it passes clean binaries and the shipped tree, and fails, naming the fault, for a binary
# that holds a variable of the seam, a shipped file that names the feature, and a manifest that turns the feature on outside
# [dev-dependencies] (a normal dependency, the default features). Fixture binaries are small files: nothing is built here.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-fixture-seams.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-check-fixture-seams: $*" >&2; fail=1; }

# ---- binaries
head -c 4096 /dev/urandom > "$tmp/clean"
printf 'CUSTODIO_HOME\0SUDO_USER\0' >> "$tmp/clean"
"$GATE" "$tmp/clean" > /dev/null 2>&1 || bad "a binary without the seam fails"
for v in CUSTODIO_FIXTURE_ROOT CUSTODIO_FIXTURE_EUID CUSTODIO_FIXTURE_FAIL; do
    { cat "$tmp/clean"; printf '\0%s\0' "$v"; head -c 64 /dev/urandom; } > "$tmp/seam"
    if out=$("$GATE" "$tmp/seam" 2>&1); then bad "a binary with $v passed"; elif ! grep -q "$v" <<< "$out"; then bad "the message for $v does not name it: $out"; fi
done

# ---- trees
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
C=crates/custodio-cli/Cargo.toml
append "variable named in a shipped file" data/custodio.service 'Environment=CUSTODIO_FIXTURE_ROOT=/tmp' 'must not ship'
append "feature named in a packaging file" packaging/nfpm.yaml '# cargo build --features fixture-root' 'must not ship'
expect_fail "normal dependency feature" $C 's|^zeroize = "1.9.1"|zeroize = "1.9.1"\ncustodio-x = { path = ".", features = ["fixture-root"] }|' 'outside \[dev-dependencies\]'
expect_fail "default feature" $C 's|^\[dependencies\]|[features]\ndefault = ["fixture-root"]\n\n[dependencies]|' 'outside \[dev-dependencies\]'
exit "$fail"
