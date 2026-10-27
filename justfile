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

# Fast checks: fmt, clippy, unit tests, service hardening score, taplo, typos, shellcheck, actionlint, zizmor, cargo-deny, cargo-machete.
check: lint test security-score

# Service hardening gate: fails when the exposure of custodio.service is above the threshold (tenths of the 0-10 score, so 10 is 1.0; lower is
# safer; 1.0 is the edge of SAFE). A bare unit must fail, so the gate itself is checked too.
security-score threshold="10":
    #!/usr/bin/env bash
    set -euo pipefail
    systemd-analyze security --offline=yes --no-pager --threshold={{threshold}} data/custodio.service | tail -n 1
    bare=$(mktemp -d)
    trap 'rm -rf "$bare"' EXIT
    printf '[Service]\nExecStart=/bin/true\n' > "$bare/bare.service"
    if systemd-analyze security --offline=yes --no-pager --threshold={{threshold}} "$bare/bare.service" >/dev/null; then
        echo "security-score: a bare unit passed the gate" >&2
        exit 1
    fi

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

# Mutation testing of the authorization path (polkit, D-Bus service) and the key store. A surviving mutant fails.
mutants:
    cargo mutants -p custodiod --file crates/custodiod/src/polkit.rs --file crates/custodiod/src/dbus.rs --file crates/custodiod/src/store.rs --no-shuffle --colors never --output target/mutants

# Coverage report of every test (unit and integration; needs `dbus-daemon` and cargo-llvm-cov): a summary on
# stdout, an HTML report in target/coverage/html and the JSON export `just crap` reads. Not a target.
coverage:
    cargo llvm-cov --workspace --locked --no-report
    cargo llvm-cov report --summary-only
    cargo llvm-cov report --html --output-dir target/coverage
    cargo llvm-cov report --json --output-path target/coverage/coverage.json

# CRAP gate: fails when a function's CRAP score (complexity² × (1 − coverage)³ + complexity) is above
# the threshold. Reads the export of `just coverage`.
crap threshold="30":
    cargo run --quiet --locked -p crap -- target/coverage/coverage.json {{threshold}} crates/custodiod crates/custodio-pkcs11 crates/custodio-cli crates/crap --exclude crates/custodio-pkcs11/src/ffi/fuzzing.rs

# Slow checks (later features add to it): everything in `check`, the integration tests, Miri, ASan, the fuzz targets building, mutation testing, coverage and the CRAP gate.
check-slow: check test-integration miri asan fuzz-build mutants coverage crap

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
