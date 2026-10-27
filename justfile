# Entry point for every task. `just` lists the recipes.

set shell := ["bash", "-euo", "pipefail", "-c"]

shell_scripts := "git ls-files '*.sh'"

default:
    @just --list

# One-time setup of a development machine: the pinned tools in mise.toml, the nightly toolchain
# for Miri, ASan and fuzzing, commitlint and the git hooks. Needs mise and rustup.
setup:
    mise trust
    mise install
    rustup toolchain install nightly --profile minimal --component miri --component rust-src
    rustup component add llvm-tools-preview
    npm ci --no-audit --no-fund
    lefthook install

# Format Rust and TOML in place.
fmt:
    cargo fmt --all
    taplo fmt

# Every linter, without modifying files.
lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo clippy -p custodio-pkcs11 --features fuzzing --all-targets --locked -- -D warnings
    taplo fmt --check
    typos
    {{shell_scripts}} | xargs -r shellcheck
    actionlint
    zizmor --offline .github/workflows
    cargo deny check
    cargo machete

# Lints of the fuzz workspace, and the `fuzzing` feature refusing to build in release. Each compiles the dependencies in
# another configuration, so they run with the nightly checks, not in `check`.
lint-fuzz:
    cd crates/custodio-pkcs11/fuzz && cargo clippy --all-targets -- -D warnings
    ! cargo build -p custodio-pkcs11 --features fuzzing --release --locked 2>/dev/null

# Unit tests.
test:
    cargo test --workspace --locked

# Fast checks: fmt, clippy, unit tests, service hardening score, taplo, typos, shellcheck, actionlint, zizmor, cargo-deny, cargo-machete.
check: lint test system-gates

# The systemd unit, sysusers file and D-Bus policy gates; no Rust build.
system-gates: security-score unit-verify bus-policy

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

# The unit parses cleanly: `systemd-analyze verify` exits 0 on unknown or invalid settings, so any output fails. ExecStart is
# replaced by a stub because the binary is installed by packaging.
unit-verify:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    sed 's#^ExecStart=.*#ExecStart=/bin/true#' data/custodio.service > "$dir/custodio.service"
    out=$(systemd-analyze verify "$dir/custodio.service" 2>&1) || { echo "$out" >&2; exit 1; }
    if [ -n "$out" ]; then echo "unit-verify: $out" >&2; exit 1; fi
    # Absolute: systemd < 256 looks a relative name up in the sysusers.d directories.
    out=$(systemd-sysusers --dry-run "$PWD/data/sysusers.d/custodio.conf" 2>&1) || { echo "$out" >&2; exit 1; }

# The bus policy really grants the name to the service user and to nobody else: a private dbus-daemon includes the policy file
# (with `custodio` replaced by the current user, or by a different user for the negative case) and we try to own the name.
bus-policy:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    me=$(id -un)
    try_own() { # $1 = user named in the policy; prints the RequestName outcome
        sed "s#user=\"custodio\"#user=\"$1\"#" data/com.rfirma.Custodio1.conf > "$dir/policy.conf"
        {
            echo '<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"'
            echo ' "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">'
            echo '<busconfig><type>system</type>'
            echo "<listen>unix:path=$dir/bus</listen><auth>EXTERNAL</auth>"
            echo '<policy context="default"><allow user="*"/><allow send_destination="*"/><allow own="*"/><allow receive_sender="*"/></policy>'
            echo "<include>$dir/policy.conf</include></busconfig>"
        } > "$dir/bus.conf"
        dbus-daemon --config-file="$dir/bus.conf" --nofork --nopidfile & daemon=$!
        trap 'kill "$daemon" 2>/dev/null || true' EXIT # the subshell of $(try_own) owns the daemon
        for _ in $(seq 50); do [ -S "$dir/bus" ] && break; sleep 0.1; done
        busctl --address="unix:path=$dir/bus" call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus RequestName su com.rfirma.Custodio1 0 2>&1 || true
        kill "$daemon"; wait "$daemon" 2>/dev/null || true
        rm -f "$dir/bus"
    }
    granted=$(try_own "$me")
    [ "$granted" = "u 1" ] || { echo "bus-policy: the policy user could not own the name: $granted" >&2; exit 1; }
    denied=$(try_own "nobody")
    case "$denied" in
        "u 1"*) echo "bus-policy: another user owned the name" >&2; exit 1 ;;
        *"AccessDenied"*|*"not allowed"*|*"denied"*) ;;
        *) echo "bus-policy: unexpected result for another user: $denied" >&2; exit 1 ;;
    esac

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
# Extra arguments go to cargo-mutants, e.g. `--in-diff <file>` or `--shard 0/4`.
[positional-arguments]
mutants *args:
    mkdir -p target # cargo-mutants does not create the parent of --output, missing on a fresh checkout
    cargo mutants -p custodiod --file crates/custodiod/src/polkit.rs --file crates/custodiod/src/dbus.rs --file crates/custodiod/src/store.rs --no-shuffle --colors never --output target/mutants "$@"

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

# One .deb in target/debian with the binaries, the unit, the sysusers file, the D-Bus policy and activation file, the polkit action and
# the p11-kit module (needs cargo-deb).
package:
    cargo build --release --locked -p custodiod -p custodio-cli -p custodio-pkcs11
    cargo deb --locked --no-build -p custodiod

# End-to-end tests: boots a systemd container (podman or docker, privileged), installs the .deb with the real polkit, and signs with
# pkcs11-tool and NSS (modutil, certutil) while a test authentication agent approves or denies. Not part of `check-slow`: it needs a
# container engine that can run systemd, which the dev container does not have.
e2e: package
    bash e2e/run.sh

# Slow checks (later features add to it): everything in `check`, the nightly checks, mutation testing, and coverage with the CRAP
# gate. The integration tests run under coverage. CI runs each of these as its own job.
check-slow: check nightly mutants coverage-gate

# Miri, ASan, the fuzz targets building and their lints.
nightly: miri asan fuzz-build lint-fuzz

# Coverage of every test (unit and integration) and the CRAP gate on it.
coverage-gate: coverage crap

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

# Regenerate CHANGELOG.md from the Conventional Commits history (git-cliff, cliff.toml).
changelog:
    git cliff -o CHANGELOG.md

# Build loop. `just status` says where it is and what to run next; harness/README.md has the details.

# Where the harness is and the next command to run.
status:
    harness/status.sh

# Milestone lifecycle: list, open, close, approve spec|features, pass <manual feature id>.
milestone action="list" *args:
    harness/milestone.sh {{action}} {{args}}

# The agents: run, try (at most 3 Claude sessions), stop, resume, unblock.
harness action="run":
    harness/harness.sh {{action}}

# Next version from the commits (git-cliff), CHANGELOG.md, release commit, tag and push.
release:
    harness/release.sh
