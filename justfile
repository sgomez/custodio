# Entry point for every task. `just` lists the recipes.

set shell := ["bash", "-euo", "pipefail", "-c"]

shell_scripts := "git ls-files '*.sh'"

default:
    @just --list

# Format Rust and TOML in place.
fmt:
    cargo fmt --all
    taplo fmt

# Every linter, without modifying files.
lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    taplo fmt --check
    typos
    {{shell_scripts}} | xargs -r shellcheck

# Unit tests.
test:
    cargo test --workspace --locked

# Fast checks: fmt, clippy, unit tests, taplo, typos, shellcheck.
check: lint test

# Slow checks (later features add to it).
check-slow: check
