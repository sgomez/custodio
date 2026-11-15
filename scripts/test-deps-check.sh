#!/usr/bin/env bash
# Test of `just deps-check` (scripts/deps_check.py): on the fixture workspace in scripts/fixtures/deps-check/edges it fails for a
# normal, a build, a dev and a transitive edge from a client to the service, naming the whole path and the kind; the clean
# fixture passes. The fixtures have no registry dependencies and a committed Cargo.lock, so nothing needs the network.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CHECK="$ROOT/scripts/deps_check.py"
FIX="$ROOT/scripts/fixtures/deps-check"
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

run "$CHECK" clean client > /dev/null || fail "the clean fixture must pass"
# A name that does not exist is an error, not a pass.
run "$CHECK" clean no-such-client > /dev/null && fail "an unknown client must fail"

echo "test-deps-check: ok"
