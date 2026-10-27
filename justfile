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
    actionlint
    zizmor --offline .github/workflows
    cargo deny check
    cargo machete

# Unit tests.
test:
    cargo test --workspace --locked

# Fast checks: fmt, clippy, unit tests, taplo, typos, shellcheck, actionlint, zizmor, cargo-deny, cargo-machete.
check: lint test

# Slow checks (later features add to it): everything in `check` plus the fuzz targets building.
check-slow: check fuzz-build

# Build every fuzz target (needs nightly and cargo-fuzz). Does not run them.
fuzz-build:
    #!/usr/bin/env bash
    set -euo pipefail
    host=$(rustc +nightly -vV | sed -n 's/^host: //p')
    found=0
    while IFS= read -r manifest; do
        found=1
        (cd "$(dirname "$manifest")/.." && cargo +nightly fuzz build --target "$host")
    done < <(find . -name Cargo.toml -path '*/fuzz/Cargo.toml' -not -path '*/target/*')
    if [ "$found" = 0 ]; then echo "no fuzz targets found" >&2; exit 1; fi
