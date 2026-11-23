#!/usr/bin/env bash
# Test of scripts/check-shell-install-sync.sh (F192): it passes on a copy of the tree and fails, naming the problem, when a package or
# the reason in the comment is gone, when a test job (also of another workflow) lacks the install, when a new job is neither checked
# nor exempt, and when an exempt job is gone.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-shell-install-sync.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-shell-install-sync: $*" >&2; fail=1; }

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

fresh
gate || bad "the check fails on a copy of the tree: $(cat "$tmp/out")"

fresh
sed -i 's/ fish / /' "$tmp/tree/harness/Containerfile"
expect_fail "Containerfile without fish" 'Containerfile: package fish'
fresh # the comment stays but says something unrelated: the reason is what is required
sed -i '/bash-completion/,/^RUN/{/^#/s/.*/# Small utilities./}' "$tmp/tree/harness/Containerfile"
expect_fail "Containerfile with an unrelated comment" 'Containerfile: .*comment'
fresh
sed -i '/zsh/{/apt-get/s/ zsh / /}' "$tmp/tree/.github/workflows/ci.yml"
expect_fail "ci.yml job without zsh" 'ci.yml job [a-z]+: package zsh'
fresh
sed -i '/bash-completion/d' "$tmp/tree/.github/workflows/mutants-diff.yml"
expect_fail "mutants-diff.yml job without the install" 'mutants-diff.yml job mutants: .*no apt install'
fresh
cat >> "$tmp/tree/.github/workflows/ci.yml" <<'YML'

  newjob:
    runs-on: ubuntu-26.04
    steps:
      - run: cargo test
YML
expect_fail "a new job that is neither checked nor exempt" 'ci.yml job newjob: .*no apt install'
fresh
sed -i 's/^  report:/  reportx:/' "$tmp/tree/.github/workflows/mutants.yml"
expect_fail "an exempt job that is gone" 'exempt job mutants.yml:report'

exit "$fail"
