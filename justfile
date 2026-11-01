# Entry point for every task. `just` lists the recipes.

set shell := ["bash", "-euo", "pipefail", "-c"]

shell_scripts := "scripts/list-shell-scripts.sh"
# Pinned so CI can cache the nightly builds; bump by hand.
nightly_toolchain := "nightly-2026-10-26"

default:
    @just --list

# One-time setup of a development machine: the pinned tools in mise.toml, the nightly toolchain
# for Miri, ASan and fuzzing, commitlint and the git hooks. Needs mise and rustup.
setup:
    @{ command -v rpm && command -v bsdtar && command -v zstd && python3 -c 'import yaml'; } >/dev/null 2>&1 \
        || { echo "Missing system packages for the package tests; on Debian/Ubuntu: sudo apt install rpm libarchive-tools zstd python3-yaml" >&2; exit 1; }
    mise trust
    mise install
    rustup toolchain install {{nightly_toolchain}} --profile minimal --component miri --component rust-src
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
    {{shell_scripts}} | xargs -r shellcheck
    actionlint
    zizmor --offline .github/workflows
    cargo deny check
    cargo machete
    just deps-check
    scripts/check-files.sh

# Fails, naming the path, when custodio-cli or custodio-pkcs11 reaches the custodiod crate in any dependency kind (normal, build, dev).
deps-check:
    scripts/deps_check.py

# Lints of the fuzz workspace, and the `fuzzing` feature refusing to build in release. Each compiles the dependencies in
# another configuration, so they run with the nightly checks, not in `check`.
lint-fuzz:
    #!/usr/bin/env bash
    set -euo pipefail
    (cd crates/custodio-pkcs11/fuzz && cargo clippy --all-targets -- -D warnings)
    # Only the guard's compile_error may fail this check; a bare `!` would accept any other error too.
    if out=$(cargo check -p custodio-pkcs11 --features fuzzing --release --locked 2>&1); then
        echo "lint-fuzz: the fuzzing feature built in release" >&2
        exit 1
    fi
    grep -q "must not be built outside fuzz or debug builds" <<< "$out" || { echo "$out" >&2; exit 1; }

# The client document docs/api.md against the live service, the error type and the policy file (also part of `test`).
api-contract:
    cargo test -p custodiod --test api_contract --locked

# Unit tests.
test:
    cargo test --workspace --locked
    cargo test -p custodio-pkcs11 --features fuzzing --lib --locked

# The gate of every feature: lints and every Rust test (unit and integration). The package, install and e2e
# script tests run in `just check`, at the checkpoints and the release. A pass stamps the tree in
# target/quick-ok, and that tree is skipped; QUICK_FORCE=1 runs it.
quick:
    #!/usr/bin/env bash
    set -euo pipefail
    tree=$(scripts/tree-hash.sh)
    if [ -z "${QUICK_FORCE:-}" ] && [ "$(cat target/quick-ok 2> /dev/null)" = "$tree" ]; then
        echo "quick: this tree already passed (target/quick-ok)"
        exit 0
    fi
    rm -f target/quick-ok
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo clippy -p custodio-pkcs11 --features fuzzing --all-targets --locked -- -D warnings
    taplo fmt --check
    {{shell_scripts}} | xargs -r shellcheck
    just deps-check
    scripts/check-files.sh
    just test
    if [ "$(scripts/tree-hash.sh)" = "$tree" ]; then mkdir -p target && echo "$tree" > target/quick-ok; fi

# Every fast check: fmt, clippy, unit tests, service hardening score, package gate tests (incl. parity and glibc ceiling), the install-time
# ProcessFD check (test-scripts), taplo, shellcheck, actionlint, zizmor, cargo-deny, cargo-machete,
# file size and tests out of the code.
# A pass stamps the tree (scripts/tree-hash.sh) in target/check-ok, and that tree is skipped; CHECK_FORCE=1 runs it.
check:
    #!/usr/bin/env bash
    set -euo pipefail
    tree=$(scripts/tree-hash.sh)
    if [ -z "${CHECK_FORCE:-}" ] && [ "$(cat target/check-ok 2> /dev/null)" = "$tree" ]; then
        echo "check: this tree already passed (target/check-ok)"
        exit 0
    fi
    rm -f target/check-ok
    just lint test system-gates script-tests
    if [ "$(scripts/tree-hash.sh)" = "$tree" ]; then mkdir -p target && echo "$tree" > target/check-ok; fi

# package-gate-test, shell-scripts-test and test-scripts in parallel (JOBS=1: one at a time).
script-tests:
    scripts/run-script-tests.sh package-gate-test shell-scripts-test test-scripts

# The systemd unit, sysusers file and D-Bus policy gates; no Rust build.
system-gates: security-score unit-hardening unit-verify bus-policy

# The tests of the package gates and of the lifecycle scripts, on small fixture packages built with nfpm (needs nfpm, rpm, bsdtar, zstd, gcc).
package-gate-test:
    scripts/test-package-scripts.sh
    scripts/test-check-packages.sh
    scripts/test-check-packages-deps.sh
    scripts/test-check-parity.sh
    scripts/test-glibc-ceiling.sh
    scripts/test-package-lint.sh
    scripts/test-package-lint-lists.sh

# The install-time scripts. F58: the same for the six install-script functions and the restart hook of the Arch package (stubbed, static, and the
# real pacman in the Arch image, which needs a container engine like the F42 case). F44: the same for the four scriptlets of the .rpm (stubbed, static, and under the real rpm in a user-namespace root).
# F43: the account text in the deb preinst equals the sysusers file, every maintainer script and action of the
# .deb runs in a stubbed root, and the real dpkg installs, upgrades, removes and purges. F42: the copies in the pre-install scripts equal the source, the check
# against a private dbus-daemon, a stub bus without ProcessFD and no bus (as the source and as the scripts extracted from fixture
# packages, with dash and bash), and the real dpkg, rpm and pacman refusing, installing or warning. The pacman cases run in the Arch
# image of the namcap lint and need a container engine; CUSTODIO_SKIP_ARCH_INSTALL=1 skips them with a message.
test-scripts:
    scripts/check-bus-check-sync.sh
    scripts/check-sysusers-sync.sh
    scripts/test-bus-check-sync.sh
    scripts/test-sysusers-sync.sh
    scripts/test-bus-check.sh
    scripts/test-deps-check.sh
    scripts/test-docs-install.sh
    scripts/test-docs-manual.sh
    scripts/test-install-real.sh
    scripts/test-deb-scripts-static.sh
    scripts/test-deb-lifecycle.sh
    scripts/test-deb-lifecycle-real.sh
    scripts/test-rpm-scripts-static.sh
    scripts/test-rpm-lifecycle.sh
    scripts/test-rpm-lifecycle-real.sh
    scripts/test-arch-scripts-static.sh
    scripts/test-arch-lifecycle.sh
    scripts/test-arch-lifecycle-real.sh
    scripts/test-e2e-skips.sh
    scripts/test-e2e-select.sh
    scripts/test-e2e-select-host.sh
    scripts/test-e2e-catalog.sh
    scripts/test-e2e-host.sh
    scripts/test-e2e-host-oldpath.sh
    scripts/test-e2e-targets.sh
    scripts/test-e2e-upgrade.sh
    scripts/test-e2e-lifecycle.sh
    scripts/test-e2e-refusal.sh
    scripts/test-e2e-oldpath.sh
    scripts/test-relabel.sh

# The shellcheck file list covers scripts by extension or shebang.
shell-scripts-test:
    scripts/test-shell-scripts.sh
    scripts/test-check-unit-hardening.sh
    scripts/test-tree-hash.sh

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

# The unit keeps ProtectProc=invisible, ProcSubset=pid and PrivateUsers=yes (each once) and the security-score threshold stays 10, so the
# pidfd cross-check is not paid for by loosening the unit.
unit-hardening:
    scripts/check-unit-hardening.sh

# The unit parses cleanly: `systemd-analyze verify` exits 0 on unknown or invalid settings, so any output fails. ExecStart is
# replaced by a stub because the binary is installed by packaging.
unit-verify:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    sed 's#^ExecStart=.*#ExecStart=/bin/true#' data/custodio.service > "$dir/custodio.service"
    # Only our unit: the host's own units warn too (ubuntu 26.04's on the removed CPUAccounting=).
    out=$(systemd-analyze verify --recursive-errors=no "$dir/custodio.service" 2>&1) || { echo "$out" >&2; exit 1; }
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

# The FFI layer of the PKCS#11 module under Miri (needs nightly with the miri component). The tests
# use a fake service, because Miri cannot talk to a bus. Only `ffi::` tests: the other modules forbid
# `unsafe` (`unsupported.rs` allows it but only returns an error and has no tests), and their pure-Rust
# crypto tests take tens of minutes under Miri. See docs/decisions.md.
miri:
    cargo +{{nightly_toolchain}} miri test -p custodio-pkcs11 --lib --locked ffi::

# The tests of the PKCS#11 module under AddressSanitizer (needs nightly).
asan:
    #!/usr/bin/env bash
    set -euo pipefail
    host=$(rustc +{{nightly_toolchain}} -vV | sed -n 's/^host: //p')
    RUSTFLAGS="-Zsanitizer=address" cargo +{{nightly_toolchain}} test -p custodio-pkcs11 --lib --locked \
        --target "$host" --target-dir target/asan

# Mutation testing of the authorization path (polkit, D-Bus service), the audit path and the key store in custodiod, and of the
# PKCS#11 module's mechanism mapping, hashing and DigestInfo construction in custodio-pkcs11 (a second cargo-mutants run, output in
# target/mutants-pkcs11). A surviving mutant fails; both runs always happen and the recipe fails at the end if either failed.
# Extra arguments go to both runs, e.g. `--in-diff <file>` or `--shard 0/4`.
[positional-arguments]
mutants *args:
    #!/usr/bin/env bash
    set -uo pipefail
    mkdir -p target # cargo-mutants does not create the parent of --output, missing on a fresh checkout
    status=0
    cargo mutants -p custodiod --file crates/custodiod/src/polkit.rs --file crates/custodiod/src/dbus.rs --file crates/custodiod/src/store.rs --file crates/custodiod/src/audit.rs --file crates/custodiod/src/audit/wire.rs --file crates/custodiod/src/audit/journal.rs --file crates/custodiod/src/audit/memory.rs --file crates/custodiod/src/credentials.rs --file crates/custodiod/src/offload.rs --file crates/custodiod/src/error.rs --no-shuffle --colors never --output target/mutants "$@" || status=1
    cargo mutants -p custodio-pkcs11 --file crates/custodio-pkcs11/src/composed.rs --file crates/custodio-pkcs11/src/module/mechanism.rs --file crates/custodio-pkcs11/src/backend.rs --no-shuffle --colors never --output target/mutants-pkcs11 "$@" || status=1
    exit "$status"

# `just mutants` on the lines changed since feature <id> started (the base commit the loop keeps in .harness/state),
# working tree included. A feature's `verify` gate; CI sweeps every mutant weekly. Extra arguments go to `just mutants`.
[positional-arguments]
mutants-diff id *args:
    #!/usr/bin/env bash
    set -euo pipefail
    id=$1; shift
    base_file=".harness/state/$id.base"
    [ -f "$base_file" ] || { echo "no $base_file: the loop has not started $id" >&2; exit 1; }
    mkdir -p target
    git diff "$(cat "$base_file")" > "target/mutants-$id.diff"
    just mutants --in-diff "target/mutants-$id.diff" "$@"

# Coverage report of every test (unit and integration; needs `dbus-daemon` and cargo-llvm-cov): a summary on
# stdout, an HTML report in target/coverage/html and the JSON export `just crap` reads. Not a target.
coverage:
    cargo llvm-cov --workspace --locked --no-report
    cargo llvm-cov --package custodio-pkcs11 --features fuzzing --lib --locked --no-report # the fuzz harness tests need the feature
    cargo llvm-cov report --summary-only
    cargo llvm-cov report --html --output-dir target/coverage
    cargo llvm-cov report --json --output-path target/coverage/coverage.json

# CRAP gate: fails when a function's CRAP score (complexity² × (1 − coverage)³ + complexity) is above
# the threshold. Reads the export of `just coverage`.
crap threshold="30":
    cargo run --quiet --locked -p crap -- target/coverage/coverage.json {{threshold}} crates/custodiod crates/custodio-pkcs11 crates/custodio-cli crates/crap --exclude crates/custodio-pkcs11/src/ffi/fuzzing.rs --exclude crates/custodio-pkcs11/src/ffi/fuzzing/ops.rs

# One .deb, one .rpm and one .pkg.tar.zst in target/packages from packaging/nfpm.yaml, then the gate scripts/check-packages.sh.
# `just package version=0.1.1` or `just package 0.2.0-rc.1` overrides the workspace version without touching Cargo.toml (needs nfpm and the
# tools of the gate).
package version="":
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release --locked -p custodiod -p custodio-cli -p custodio-pkcs11
    v='{{version}}'
    v=${v#version=}
    [ -n "$v" ] || v=$(cargo metadata --locked --no-deps --format-version 1 | python3 -I -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "custodiod"))')
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "package: bad version '$v'" >&2; exit 1; }
    base=${v%%-*}
    pre=""
    [ "$v" = "$base" ] || pre=${v#*-}
    rm -rf target/packages target/man
    mkdir -p target/packages target/man
    gzip -9n < packaging/custodio.1 > target/man/custodio.1.gz
    # The unit of each format from the one source: the ExecStart follows the daemon path of the format (F61).
    scripts/derive-units.sh data/custodio.service target/units
    mkdir -p target/doc
    sed "s/@VERSION@/${base}${pre:+~$pre}-1/" packaging/changelog.Debian | gzip -9n > target/doc/changelog.Debian.gz
    # rustc leaves a .comment section in the binaries (lintian: binary-has-unneeded-section).
    strip --remove-section=.comment target/release/custodiod target/release/custodio-cli target/release/libcustodio_pkcs11.so
    NFPM_VERSION=$base NFPM_PRERELEASE=$pre nfpm package -f packaging/nfpm.yaml -p deb -t target/packages >/dev/null
    NFPM_VERSION=$base NFPM_PRERELEASE=$pre nfpm package -f packaging/nfpm.yaml -p rpm -t target/packages >/dev/null
    # Arch forbids "-" in pkgver and nfpm drops the prerelease there: the pre-release goes into the version with "_".
    NFPM_VERSION=${base}${pre:+_$pre} NFPM_PRERELEASE= nfpm package -f packaging/nfpm.yaml -p archlinux -t target/packages >/dev/null
    scripts/check-packages.sh target/packages packaging/nfpm.yaml

# The gates on the packages: `just package` (which checks their contents), then the same files, modes and owners in all three
# (packaging/parity-exceptions.txt lists accepted differences), no glibc symbol version above the ceiling, and the linters on the packages. Later package gates join here.
package-gates: package package-parity glibc-ceiling package-lint

# Fails on any lintian finding on the .deb, rpmlint finding on the .rpm or namcap finding on the Arch package in target/packages that is not in
# the list of packaging/lint/<linter>.txt with a reason, and on a list entry that matches nothing. A linter runs on the host when it has the
# pinned version of packaging/lint/pins.txt and otherwise in a container of the target distribution (podman or docker).
# PACKAGE_LINT_FORCE_CONTAINER=1 always uses the container.
package-lint:
    scripts/package-lint.sh

# Fails when the .deb, .rpm and Arch package in target/packages differ in installed paths, modes, owners or symlink targets.
package-parity:
    scripts/check-parity.sh

# Fails when an ELF file in a package in target/packages needs a glibc symbol version above the ceiling of packaging/glibc-ceiling.txt.
glibc-ceiling:
    scripts/check-glibc-ceiling.sh

# End-to-end tests of one target (a directory of e2e/targets/) or all of them (default): boots a privileged systemd container (podman or docker)
# with the distribution's real polkit and default bus daemon, installs the package with the target's own tool, and signs with pkcs11-tool and NSS
# (modutil, certutil) while a test authentication agent approves or denies. Prints and saves the record (bus daemon, polkit version) under
# target/e2e/. Also builds package N+1 (the same tree, the patch number raised) into target/packages-next for the upgrade case. Also builds the old-path fixture (the .deb and the .rpm with the daemon at /usr/lib/custodio, from this tree) into target/packages-oldpath and upgrades from it on the targets that run the upgrade cases. Not part of `check-slow`: it needs a container engine that can run systemd, which the dev container may not have.
e2e target="all": e2e-packages
    bash e2e/run.sh {{target}}

# The packages the end-to-end tests install: package N, package N+1 and the old-path fixture. The one build that `e2e` and `e2e-cases` share.
e2e-packages: package
    scripts/package-next.sh
    scripts/package-oldpath.sh

# Like `just e2e TARGET` for one target (not `all`), but runs the shared setup (install, service, users, key import) and only the cases whose ids equal one of the
# given names or match one as a shell glob, e.g. `just e2e-cases debian13 pkcs11-tool-approve-rsa 'nss-*'` (quote the glob). The accounting then requires each selected
# case exactly once and no other. A name that matches no case of the target is refused before any container starts.
e2e-cases target +names: e2e-packages
    bash e2e/run.sh {{target}} --cases {{quote(names)}}

# Slow checks (later features add to it): everything in `check`, the nightly checks, mutation testing, coverage with the CRAP
# gate, and the package gates. The integration tests run under coverage. CI runs each of these as its own job.
check-slow: check nightly mutants coverage-gate package-gates

# Miri, ASan, the fuzz targets building and their lints.
nightly: miri asan fuzz-build lint-fuzz

# Coverage of every test (unit and integration) and the CRAP gate on it.
coverage-gate: coverage crap

# Build every fuzz target (needs nightly and cargo-fuzz). Does not run them.
fuzz-build:
    #!/usr/bin/env bash
    set -euo pipefail
    host=$(rustc +{{nightly_toolchain}} -vV | sed -n 's/^host: //p')
    found=0
    while IFS= read -r manifest; do
        found=1
        (cd "$(dirname "$manifest")/.." && cargo +{{nightly_toolchain}} fuzz build --target "$host")
    done < <(find . -name Cargo.toml -path '*/fuzz/Cargo.toml' -not -path '*/target/*')
    if [ "$found" = 0 ]; then echo "no fuzz targets found" >&2; exit 1; fi

# Regenerate CHANGELOG.md from the Conventional Commits history (git-cliff, cliff.toml).
changelog:
    git cliff -o CHANGELOG.md

# Build loop. `just status` says where it is and what to run next; harness/README.md has the details.

# Where the harness is and the next command to run.
status:
    harness/status.sh

# Follow the agent session running in the dev container.
log:
    harness/log.sh

# Milestone lifecycle: list, open, close, approve spec|features, pass <manual feature id>.
milestone action="list" *args:
    harness/milestone.sh {{action}} {{args}}

# The agents: run, try (at most 3 Claude sessions), stop, resume, unblock ["<answer>"], fix <id>.
[positional-arguments]
harness action="run" *args:
    harness/harness.sh "$@"

# Next version from the commits (git-cliff), CHANGELOG.md, release commit, tag and push.
release:
    harness/release.sh
