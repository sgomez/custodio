#!/usr/bin/env bash
# scripts/changed_checks.py picks the checks a change can break; its plans (--dry-run) on known file sets.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail=0
bad() { echo "test-changed-checks: $*" >&2; fail=1; }
# This test names the paths it plans for, so it is in every plan; leave it out.
plan() { "$ROOT/scripts/changed_checks.py" --dry-run "$@" | sed 's/^changed-checks: //' | grep -vxF scripts/test-changed-checks.sh; }
has() { grep -qxF -- "$2" <<< "$1" || bad "$3: missing '$2'"; }
hasnt() { if grep -qF -- "$2" <<< "$1"; then bad "$3: unexpected '$2'"; fi; }

p=$(plan --files mise.toml)
[ "$p" = "just check" ] || bad "a tool version change does not run just check: $p"

p=$(plan --files crates/crap/src/lib.rs)
has "$p" "cargo test -p crap --locked" "crap source"
hasnt "$p" "custodiod" "crap source"
hasnt "$p" "scripts/test-" "crap source"

p=$(plan --files crates/custodiod/src/main.rs)
has "$p" "cargo test -p custodio-cli -p custodio-pkcs11 -p custodiod --locked" "custodiod source (and its dependents)"
has "$p" "cargo test -p custodio-pkcs11 --features fuzzing --lib --locked" "custodiod source"

p=$(plan --files data/com.rfirma.custodio.policy)
has "$p" "just system-gates" "policy file"
grep -q '^cargo test .*-p custodiod' <<< "$p" || bad "policy file: the crate whose tests read it is not tested"

p=$(plan --files Cargo.lock)
has "$p" "cargo deny check" "lockfile"
grep -q '^cargo test -p crap -p custodio-cli -p custodio-pkcs11 -p custodiod' <<< "$p" || bad "lockfile: not every crate"

p=$(plan --files PROGRESS.md)
hasnt "$p" "cargo" "Markdown only"
hasnt "$p" "scripts/test-" "Markdown only"

# A test names other tests in comments; only its own change runs it.
p=$(plan --files scripts/test-rpm-lifecycle.sh)
has "$p" "scripts/test-rpm-lifecycle.sh" "a test script"
[ "$(grep -c '^scripts/test-' <<< "$p")" = 1 ] || bad "a test script pulled in other tests: $p"

# A helper runs the tests that use it, through the files that use it.
p=$(plan --files scripts/package_lint.py)
has "$p" "scripts/test-package-lint.sh" "package_lint.py (through package-lint.sh)"
hasnt "$p" "cargo" "package_lint.py"

p=$(plan --lint-only --files crates/crap/src/lib.rs)
has "$p" "cargo clippy -p crap --all-targets --locked -- -D warnings" "lint only"
hasnt "$p" "cargo test" "lint only"

exit "$fail"
