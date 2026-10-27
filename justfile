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
    cargo clippy -p custodio-pkcs11 --features fuzzing --all-targets --locked -- -D warnings
    cd crates/custodio-pkcs11/fuzz && cargo clippy --all-targets -- -D warnings
    ! cargo build -p custodio-pkcs11 --features fuzzing --release --locked 2>/dev/null
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

# Integration tests against a private dbus-daemon with a fake polkit authority (needs `dbus-daemon`).
# The PKCS#11 test builds the module itself and loads it through the `cryptoki` crate.
test-integration:
    cargo test -p custodiod --locked --test dbus --test polkit
    cargo test -p custodio-pkcs11 --locked --test cryptoki

# The FFI layer of the PKCS#11 module under Miri (needs nightly with the miri component). The tests
# use a fake service, because Miri cannot talk to a bus.
miri:
    cargo +nightly miri test -p custodio-pkcs11 --lib --locked

# The tests of the PKCS#11 module under AddressSanitizer (needs nightly).
asan:
    #!/usr/bin/env bash
    set -euo pipefail
    host=$(rustc +nightly -vV | sed -n 's/^host: //p')
    RUSTFLAGS="-Zsanitizer=address" cargo +nightly test -p custodio-pkcs11 --lib --locked \
        --target "$host" --target-dir target/asan

# Slow checks (later features add to it): everything in `check`, the integration tests, Miri, ASan and the fuzz targets building.
check-slow: check test-integration miri asan fuzz-build

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
