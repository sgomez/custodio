#!/usr/bin/env bash
# Tests of scripts/check-test-socket-dir.sh (F178) on copies of the tree with one fault each: the gate passes the shipped files and fails, naming the
# fault, when the feature is in default, in a [dependencies] (also as `features = [...]` of another crate), in another crate's [features], in a recipe,
# when the variable is read elsewhere, and when the module is declared without the cfg.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-test-socket-dir.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-check-test-socket-dir: $*" >&2; fail=1; }

FILES=(Cargo.toml justfile crates/custodio-pkcs11/Cargo.toml crates/custodio-it/Cargo.toml crates/custodio-cli/Cargo.toml
    crates/custodio-pkcs11/src/backend.rs crates/custodio-pkcs11/src/backend/socket.rs crates/custodio-pkcs11/src/backend/test_dir.rs)
fresh() {
    local f
    rm -rf "${tmp:?}/case"
    for f in "${FILES[@]}"; do mkdir -p "$tmp/case/$(dirname "$f")"; cp "$ROOT/$f" "$tmp/case/$f"; done
}
fresh
"$GATE" "$tmp/case" >/dev/null 2>&1 || bad "the shipped files fail"

expect_fail() { # LABEL FILE SED-EXPRESSION WORD
    local out
    fresh
    sed -i "$3" "$tmp/case/$2"
    if cmp -s "$ROOT/$2" "$tmp/case/$2"; then bad "$1: the fixture changed nothing"; return; fi
    if out=$("$GATE" "$tmp/case" 2>&1); then bad "$1: the gate passed"; return; fi
    grep -q -- "$4" <<< "$out" || bad "$1: the message does not hold '$4': $out"
}
P=crates/custodio-pkcs11/Cargo.toml
expect_fail "feature in default" $P 's/^fuzzing = \[\]/fuzzing = []\ndefault = ["test-socket-dir"]/' 'in default'
expect_fail "feature as a dependency feature of another crate" crates/custodio-cli/Cargo.toml '0,/^\[dependencies\]/s//[dependencies]\ncustodio-pkcs11 = { path = "..\/custodio-pkcs11", features = ["test-socket-dir"] }/' 'under \[dependencies\]'
# shellcheck disable=SC2016
expect_fail "feature in another crate's features" crates/custodio-cli/Cargo.toml '$a\
[features]\
tests = ["custodio-pkcs11/test-socket-dir"]' 'under \[features\]'
# shellcheck disable=SC2016
expect_fail "feature in a recipe" justfile '$a\
bad:\
    cargo build -p custodio-pkcs11 --features test-socket-dir' 'recipe'
# shellcheck disable=SC2016
expect_fail "variable read elsewhere" crates/custodio-pkcs11/src/backend/socket.rs '$a\
const X: \&str = "CUSTODIO_TEST_SOCKET_BASE_DIR";' 'read outside'
expect_fail "module declared without the cfg" crates/custodio-pkcs11/src/backend.rs '/^#\[cfg(feature = "test-socket-dir")\]$/d' 'not directly behind'
exit "$fail"
