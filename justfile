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

# Runs a command against a fresh software TPM (swtpm, socket mode, state in a new temporary directory, TPM2_Startup done,
# TPM2TOOLS_TCTI exported); stops it and removes the state whatever the outcome; exits with the command's status.
[positional-arguments]
with-swtpm *cmd:
    scripts/with-swtpm.sh "$@"

# Fails, naming the path, when custodio-cli or custodio-pkcs11 reaches the custodiod crate in any dependency kind (normal, build, dev).
deps-check:
    scripts/deps_check.py

# Lints of the fuzz workspace, and the `fuzzing` feature refusing to build in release. Each compiles the dependencies in
# another configuration, so they run with the memory-safety checks, not in `check`.
lint-fuzz:
    #!/usr/bin/env bash
    set -euo pipefail
    (cd crates/custodio-pkcs11/fuzz && cargo clippy --all-targets -- -D warnings)
    (cd crates/custodiod/fuzz && cargo clippy --all-targets -- -D warnings)
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

# What the VM target needs on this machine: KVM the user can open, QEMU, OVMF, swtpm, the seed tool, gpgv and the Ubuntu keyring.
# It fails naming each missing one and never offers software emulation (docs/findings/F150.md).
vm-host-check:
    scripts/vm-host-check.sh

# Downloads the pinned Ubuntu 26.04 minimal cloud image into a per-user cache outside the repository, verifies Ubuntu's signature
# on SHA256SUMS (gpgv) and the image against it, and prints its path, serial and SHA-256. A cached image is verified again.
vm-image:
    e2e/vm/image.sh

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
    scripts/check-tpm-install-sync.sh
    scripts/test-tpm-install-sync.sh
    scripts/test-with-swtpm.sh
    scripts/test-vm-credread.sh
    scripts/test-vm-host-check.sh
    scripts/test-vm-image.sh
    scripts/test-vm-launch.sh
    scripts/test-vm-modes.sh
    scripts/test-bus-check.sh
    scripts/test-deps-check.sh
    scripts/test-docs-api.sh
    scripts/test-docs-install.sh
    scripts/test-docs-manual.sh
    scripts/test-docs-manual-m3.sh
    scripts/test-docs-manual-m4.sh
    scripts/test-docs-manual-m5.sh
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
    scripts/test-ci-e2e-vm.sh
    scripts/test-e2e-vm-cases.sh
    scripts/test-vm-gap-map.sh
    scripts/test-e2e-vm-host.sh
    scripts/test-e2e-vm-kinds.sh
    scripts/test-e2e-vm-silent.sh
    scripts/test-e2e-select.sh
    scripts/test-e2e-owner.sh
    scripts/test-e2e-ops.sh
    scripts/test-e2e-rd.sh
    scripts/test-e2e-jo.sh
    scripts/test-e2e-journal.sh
    scripts/test-e2e-appid.sh
    scripts/test-e2e-cli.sh
    scripts/test-e2e-select-host.sh
    scripts/test-e2e-catalog.sh
    scripts/test-e2e-host.sh
    scripts/test-e2e-host-oldpath.sh
    scripts/test-ci-e2e.sh
    scripts/test-e2e-tpm-host.sh
    scripts/test-e2e-tpm-kind.sh
    scripts/test-e2e-sign.sh
    scripts/test-e2e-noplain.sh
    scripts/test-e2e-tpmdup.sh
    scripts/test-e2e-pcr.sh
    scripts/test-e2e-fallback.sh
    scripts/test-e2e-tpmfail.sh
    scripts/test-e2e-tpmclear.sh
    scripts/test-e2e-tpmslots.sh
    scripts/test-e2e-journalkind.sh
    scripts/test-e2e-upgradekinds.sh
    scripts/test-e2e-m3.sh
    scripts/test-e2e-m3-judge.sh
    scripts/test-e2e-m3-run.sh
    scripts/test-e2e-jobs-host.sh
    scripts/test-check-budgets.sh
    scripts/test-e2e-targets.sh
    scripts/test-e2e-upgrade.sh
    scripts/test-e2e-lifecycle.sh
    scripts/test-e2e-oldpath.sh
    scripts/test-e2e-import.sh
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

# The unit keeps ProtectProc=invisible, ProcSubset=pid, PrivateUsers=yes, PrivateDevices=yes and the F109 TPM access (each once, no raw TPM node, no TCTI override) and the security-score threshold stays 10, so the
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
    export NEXTEST_PROFILE=mutants # .config/nextest.toml
    # A wedged cargo build otherwise hangs the run: the test timeout does not cover builds.
    extra=(--build-timeout 600)
    # MUTANTS_ITERATE=1 skips mutants a previous run caught or found unviable; valid while src/ is unchanged.
    [ "${MUTANTS_ITERATE:-}" = 1 ] && extra+=(--iterate)
    status=0
    cargo mutants -p custodiod --file crates/custodiod/src/app_id.rs --file crates/custodiod/src/app_id_source.rs --file crates/custodiod/src/app_id_source/bounded.rs --file crates/custodiod/src/app_id_source/guarded.rs --file crates/custodiod/src/app_id_source/limiter.rs --file crates/custodiod/src/app_id_source/scan.rs --file crates/custodiod/src/polkit.rs --file crates/custodiod/src/dbus.rs --file crates/custodiod/src/dbus/import.rs --file crates/custodiod/src/import.rs --file crates/custodiod/src/import/choice.rs --file crates/custodiod/src/import/protect.rs --file crates/custodiod/src/dbus/delete.rs --file crates/custodiod/src/dbus/delete_state.rs --file crates/custodiod/src/dbus/replace.rs --file crates/custodiod/src/dbus/sign_kind.rs --file crates/custodiod/src/store.rs --file crates/custodiod/src/store/error.rs --file crates/custodiod/src/store/files.rs --file crates/custodiod/src/store/kind.rs --file crates/custodiod/src/store/legacy.rs --file crates/custodiod/src/store/record.rs --file crates/custodiod/src/audit.rs --file crates/custodiod/src/audit/wire.rs --file crates/custodiod/src/audit/journal.rs --file crates/custodiod/src/audit/memory.rs --file crates/custodiod/src/audit/operation.rs --file crates/custodiod/src/audit/cause.rs --file crates/custodiod/src/credentials.rs --file crates/custodiod/src/creds.rs --file crates/custodiod/src/creds/systemd.rs --file crates/custodiod/src/creds/header.rs --file crates/custodiod/src/offload.rs --file crates/custodiod/src/startup.rs --file crates/custodiod/src/error.rs --file crates/custodiod/src/tpm.rs --file crates/custodiod/src/tpm/blob.rs --file crates/custodiod/src/tpm/classify.rs --file crates/custodiod/src/tpm/esys.rs --file crates/custodiod/src/tpm/esys/primary.rs --file crates/custodiod/src/tpm/import.rs --file crates/custodiod/src/tpm/sign.rs --file crates/custodiod/src/tpm/sign/block.rs --file crates/custodiod/src/tpm/sign/check.rs --file crates/custodiod/src/tpm/esys/signing.rs --file crates/custodiod/src/tpm/key.rs --file crates/custodiod/src/tpm/list.rs --file crates/custodiod/src/tpm/open.rs --file crates/custodiod/src/tpm/wrap.rs --no-shuffle --colors never --output target/mutants "${extra[@]}" "$@" || status=1
    cargo mutants -p custodio-pkcs11 --file crates/custodio-pkcs11/src/composed.rs --file crates/custodio-pkcs11/src/module/mechanism.rs --file crates/custodio-pkcs11/src/backend.rs --no-shuffle --colors never --output target/mutants-pkcs11 "${extra[@]}" "$@" || status=1
    cargo mutants -p custodio-client --file crates/custodio-client/src/kind.rs --no-shuffle --colors never --output target/mutants-client "${extra[@]}" "$@" || status=1
    # A build that ran out of disk counts as "unviable", which passes: void the run instead.
    for out in target/mutants target/mutants-pkcs11 target/mutants-client; do
        if grep -rqs 'No space left on device' "$out/mutants.out/log"; then
            echo "$out: a mutant ran out of disk space; free space and run again" >&2; status=1
        fi
    done
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
    # New files too, without `git add -N`: intent-to-add entries break the loop's `git stash`.
    git ls-files -z --others --exclude-standard | while IFS= read -r -d '' f; do
        git diff --no-index -- /dev/null "$f" >> "target/mutants-$id.diff" || [ $? = 1 ]
    done
    # 3 jobs: a full F115-sized diff (about 200 mutants) takes 18 min serially.
    just mutants --in-diff "target/mutants-$id.diff" --jobs 3 "$@"

# Gates: `ci` (ci.yml's jobs but commitlint, in the dev container), `mutants` (the mutants diff against main). Instead
# of `git push`: nothing is pushed or signed unless every gate passes on HEAD. E.g. `just signoff ci mutants`.
# Runs CI checks locally on HEAD, then pushes it and signs it off (gh-signoff); CI skips them.
[positional-arguments]
signoff +gates:
    #!/usr/bin/env bash
    set -euo pipefail
    clean() { [ -z "$(git status --porcelain)" ]; }
    clean || { echo "signoff: commit or remove every change first; the signoff is for HEAD" >&2; exit 1; }
    gh signoff --help >/dev/null 2>&1 || { echo "signoff: needs gh extension install basecamp/gh-signoff" >&2; exit 1; }
    sha=$(git rev-parse HEAD)
    git fetch -q origin main
    in_box() { if [ -e /run/.containerenv ]; then just "$@"; else harness/run.sh just "$@"; fi; }
    workflows=()
    for gate in "$@"; do
        case $gate in
            ci) in_box lint system-gates package-gate-test shell-scripts-test test package package-parity glibc-ceiling package-lint \
                    coverage-gate memory-safety
                workflows+=(ci.yml) ;;
            mutants) mkdir -p target
                git diff "$(git merge-base origin/main HEAD)" HEAD > target/signoff.diff
                in_box mutants --in-diff target/signoff.diff --jobs 3
                workflows+=(mutants-diff.yml) ;;
            *) echo "signoff: unknown gate $gate: ci or mutants" >&2; exit 1 ;;
        esac
    done
    if [ "$(git rev-parse HEAD)" != "$sha" ] || ! clean; then
        echo "signoff: HEAD or the tree changed during the run" >&2; exit 1
    fi
    git push -q -u origin HEAD
    gh signoff "$@"
    # A PR's runs started at the push, before the signoff: re-run them so they skip the signed-off checks.
    sleep 10
    for wf in "${workflows[@]}"; do
        run=$(gh run list -w "$wf" -c "$sha" -L 1 --json databaseId -q '.[0].databaseId // empty')
        [ -n "$run" ] || continue
        gh run cancel "$run" >/dev/null 2>&1 && gh run watch "$run" >/dev/null 2>&1 || true
        gh run rerun "$run"
    done

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

# F131: `E2E_TPM` (swtpm, the default; none; lacking) says what TPM the service sees in `e2e` and `e2e-cases`; `just e2e` with it unset runs every target with swtpm and with none.
# The program that makes a TPM lack an algorithm (an example of custodio-it), which only the lacking mode mounts into the containers; built only for it.
e2e-tpm-filter:
    [ "${E2E_TPM:-swtpm}" != lacking ] || cargo build --locked -p custodio-it --example tpm-filter --release

# The packages the end-to-end tests install: package N, package N+1, the old-path fixture and the M3 build of the tag v0.5.0 (target/packages-m3, kept between runs). The one build that `e2e` and `e2e-cases` share.
e2e-packages: package
    scripts/package-next.sh
    scripts/package-oldpath.sh
    scripts/package-m3.sh
    just e2e-tpm-filter

# Like `just e2e TARGET` for one target (not `all`), but runs the shared setup (install, service, users, key import) and only the cases whose ids equal one of the
# given names or match one as a shell glob, e.g. `just e2e-cases debian13 pkcs11-tool-approve-rsa 'nss-*'` (quote the glob). The accounting then requires each selected
# case exactly once and no other. A name that matches no case of the target is refused before any container starts.
e2e-cases target +names: e2e-packages
    bash e2e/run.sh {{target}} --cases {{quote(names)}}

# F160: one run of the e2e cases in a VM (Ubuntu 26.04 under QEMU/KVM, a virtual TPM): `just e2e-vm full` or `lacking` (the TPM mode, e2e/vm/vm.sh). The package is built and installed with apt
# `--no-install-recommends`, the shared setup and every case of e2e/vm/cases.list run in the guest, and the record goes to target/e2e/vm.<mode>.record. The mode is checked before a package is built.
e2e-vm mode: (e2e-vm-check mode) e2e-packages
    bash e2e/vm/run.sh {{mode}}

# Like `e2e-vm` for the cases whose ids equal a name or match it as a glob (e.g. `just e2e-vm-cases full 'sign-*'`); a name that matches no case of e2e/vm/cases.list is refused before anything starts.
e2e-vm-cases mode +names: (e2e-vm-check mode quote(names)) e2e-packages
    bash e2e/vm/run.sh {{mode}} {{quote(names)}}

# The checks that come before anything is built or started (the mode, the names)
e2e-vm-check mode names='':
    bash e2e/vm/run.sh --check {{mode}} {{names}}

# Slow checks (later features add to it): everything in `check`, the memory-safety checks, mutation testing, coverage with the CRAP
# gate, and the package gates. The integration tests run under coverage. CI runs each of these as its own job.
check-slow: check memory-safety mutants coverage-gate package-gates

# Miri, ASan, the fuzz targets building and their lints (on the nightly toolchain).
memory-safety: miri asan fuzz-build lint-fuzz

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

# Run every fuzz target for a fixed number of runs with a fixed seed (a smoke test, not fuzzing). Fails on a crash, on an
# expected target that `cargo fuzz list` does not report, and when no target ran. Corpus and artifacts go to a temporary
# directory, so the local corpus is neither read nor changed. `cargo fuzz run` builds first, so the binary is never stale.
# `expected` is overridable for the negative control: `just fuzz-smoke "a b c"`.
fuzz-smoke expected="delete_args replace_cert_args app_id dbus_args p12_parse pkcs11_args tpm_blob cred_frame record_decode tpm_sign_input":
    #!/usr/bin/env bash
    set -euo pipefail
    runs=2000
    seed=1
    host=$(rustc +{{nightly_toolchain}} -vV | sed -n 's/^host: //p')
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    ran=" "
    while IFS= read -r manifest; do
        dir=$(dirname "$manifest")/..
        listed=$(cd "$dir" && cargo +{{nightly_toolchain}} fuzz list)
        for target in $listed; do
            mkdir -p "$tmp/corpus/$target" "$tmp/artifacts/$target"
            echo "fuzz-smoke: $target -runs=$runs -seed=$seed"
            (cd "$dir" && cargo +{{nightly_toolchain}} fuzz run --target "$host" "$target" "$tmp/corpus/$target" -- \
                -runs=$runs -seed=$seed "-artifact_prefix=$tmp/artifacts/$target/") >"$tmp/log" 2>&1 \
                || { tail -30 "$tmp/log" >&2; echo "fuzz-smoke: $target failed" >&2; exit 1; }
            tail -2 "$tmp/log"
            ran="$ran$target "
        done
    done < <(find . -name Cargo.toml -path '*/fuzz/Cargo.toml' -not -path '*/target/*')
    for target in {{expected}}; do
        case "$ran" in
            *" $target "*) ;;
            *) echo "fuzz-smoke: target $target is missing or did not run" >&2; exit 1 ;;
        esac
    done
    if [ "$ran" = " " ]; then echo "fuzz-smoke: no fuzz targets found" >&2; exit 1; fi

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

# Milestone lifecycle: list, open, close, approve spec|features|budgets, pass <manual feature id>.
milestone action="list" *args:
    harness/milestone.sh {{action}} {{args}}

# The agents: run, try (at most 3 Claude sessions), stop, resume, unblock ["<answer>"], fix <id>.
[positional-arguments]
harness action="run" *args:
    harness/harness.sh "$@"

# Release of the closed milestone, from its branch: CHANGELOG.md, check-slow, signoffs, PR, merge and version tag.
release:
    harness/release.sh
