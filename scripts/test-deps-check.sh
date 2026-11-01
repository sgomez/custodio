#!/usr/bin/env bash
# Test of `just deps-check` (scripts/deps_check.py): on the fixture workspace in scripts/fixtures/deps-check/edges it fails for a
# normal, a build, a dev and a transitive edge from a client to the service, naming the whole path and the kind; the clean
# fixture passes; a patched copy of the checker that does not follow dev edges misses the dev edge (so the dev case of the real
# checker is what catches it); `lint` runs `deps-check`. The fixtures have no registry dependencies and a committed Cargo.lock,
# so nothing needs the network.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CHECK="$ROOT/scripts/deps_check.py"
FIX="$ROOT/scripts/fixtures/deps-check"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { echo "test-deps-check: $*" >&2; exit 1; }

run() { # checker, workspace, clients; prints stderr+stdout, returns the exit code
    python3 -I "$1" --manifest-path "$FIX/$2/Cargo.toml" --service service --clients "$3" 2>&1
}

expect_hit() { # client, expected text
    local out rc=0
    out=$(run "$CHECK" edges "$1") || rc=$?
    [ "$rc" -ne 0 ] || fail "$1: expected a failure, got exit 0"
    grep -qF -- "$2" <<< "$out" || fail "$1: output lacks '$2': $out"
}

expect_hit client-normal "client-normal -[normal]-> service"
expect_hit client-build "client-build -[build]-> service"
expect_hit client-dev "client-dev -[dev]-> service"
expect_hit client-transitive "client-transitive -[normal]-> mid -[normal]-> service"

# Every client that reaches the service is reported.
out=$(run "$CHECK" edges client-normal,client-dev) && fail "two clients: expected a failure"
[ "$(grep -c 'reaches' <<< "$out")" -eq 2 ] || fail "two clients: expected two paths: $out"

run "$CHECK" clean client > /dev/null || fail "the clean fixture must pass"
# A name that does not exist is an error, not a pass.
run "$CHECK" clean no-such-client > /dev/null && fail "an unknown client must fail"

# Negative control: the same checker without its dev handling misses the dev edge.
patched="$tmp/deps_check_nodev.py"
sed 's/^KINDS = ("normal", "build", "dev")$/KINDS = ("normal", "build")/' "$CHECK" > "$patched"
! cmp -s "$CHECK" "$patched" || fail "the patched checker does not differ from the real one"
run "$patched" edges client-dev > /dev/null || fail "the checker without dev edges should miss the dev fixture"
run "$patched" edges client-normal > /dev/null && fail "the patched checker must still catch a normal edge"

# `lint` runs the recipe: look at the recipe, not at comments. `deps-check` must run the checker.
lint=$(cd "$ROOT" && just --show lint | grep -v '^[[:space:]]*#')
grep -Eq '^[[:space:]]+just deps-check[[:space:]]*$' <<< "$lint" || fail "just lint does not run deps-check"
body=$(cd "$ROOT" && just --show deps-check | grep -v '^[[:space:]]*#')
grep -q 'scripts/deps_check.py' <<< "$body" || fail "deps-check does not run scripts/deps_check.py"
echo "test-deps-check: ok"
