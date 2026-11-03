#!/usr/bin/env bash
# Tests of scripts/check-tpm-install-sync.sh (F104): it passes on the tree and fails, naming the problem, when a package is gone from
# the Containerfile or from a cargo job, when a new job has no install, and when the comment above an install is gone.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-tpm-install-sync.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-tpm-install-sync: $*" >&2; fail=1; }

fresh() {
    rm -rf "$tmp/tree"
    mkdir -p "$tmp/tree/harness" "$tmp/tree/.github"
    cp "$ROOT/harness/Containerfile" "$tmp/tree/harness/"
    cp -r "$ROOT/.github/workflows" "$tmp/tree/.github/"
}
gate() { "$GATE" "$tmp/tree" > "$tmp/out" 2>&1; }
expect_fail() { # LABEL PATTERN
    if gate; then bad "$1: the check passed"; return; fi
    grep -Eq "$2" "$tmp/out" || bad "$1: the output does not name the problem ($2): $(cat "$tmp/out")"
}

"$GATE" > /dev/null 2>&1 || bad "the check fails on the tree"
fresh
gate || bad "the check fails on a copy of the tree: $(cat "$tmp/out")"

fresh
sed -i 's/swtpm-tools //' "$tmp/tree/harness/Containerfile"
expect_fail "Containerfile without swtpm-tools" 'Containerfile: package swtpm-tools'
fresh
sed -i 's/ libtss2-dev//' "$tmp/tree/harness/Containerfile"
expect_fail "Containerfile without libtss2-dev" 'Containerfile: package libtss2-dev'
fresh
sed -i '/^# swtpm (a software TPM)/d' "$tmp/tree/harness/Containerfile"
expect_fail "Containerfile without its comment" 'Containerfile: .*comment'
fresh
sed -i '/^# swtpm (a software TPM)/d; /swtpm swtpm-tools/d' "$tmp/tree/harness/Containerfile"
expect_fail "Containerfile without the install" 'Containerfile: .*no apt install'

fresh
sed -i '0,/ tpm2-tools libtss2-dev/s// libtss2-dev/' "$tmp/tree/.github/workflows/ci.yml"
expect_fail "a ci.yml job without tpm2-tools" 'ci.yml job [a-z]+: package tpm2-tools'
fresh
sed -i '/^      # tss-esapi builds against/d' "$tmp/tree/.github/workflows/mutants.yml"
expect_fail "mutants.yml without the comment" 'mutants.yml job full: .*comment'
fresh
cat >> "$tmp/tree/.github/workflows/ci.yml" <<'YML'

  newjob:
    runs-on: ubuntu-26.04
    steps:
      - run: cargo build
YML
expect_fail "a new cargo job without the install" 'ci.yml job newjob: .*no apt install'
fresh
sed -i 's/^  report:/  reportx:/' "$tmp/tree/.github/workflows/mutants.yml"
expect_fail "an exempt job that is gone" 'exempt job mutants.yml:report'

exit "$fail"
