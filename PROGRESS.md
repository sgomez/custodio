# Progress

Each session appends one entry at the bottom. Keep entries short: the next session reads them
with an empty context.

## Template

```
### <date> — <feature id> — <attempt n>
- Done:
- Decisions (also in docs/decisions.md if lasting):
- Not done / known issues:
- Next session should:
```

## Sessions

### 2026-10-27 — F01 — 1
- Done: workspace with `custodiod` (lib+bin), `custodio-pkcs11` (cdylib+rlib), `custodio-cli` (bin) under `crates/`; `rust-toolchain.toml` pinned to 1.99.1; `Cargo.lock` committed; `forbid(unsafe_code)` everywhere except pkcs11; pedantic denied workspace-wide, plus unwrap/expect/panic/indexing_slicing in `custodiod`. verify passes.
- Decisions: Cargo cannot mix `lints.workspace = true` with extra lints, so `custodiod` repeats pedantic locally (see docs/decisions.md).
- Not done / known issues: no `justfile` yet.
- Next session should: build the next feature; new crates must set `[lints] workspace = true`.

### 2026-10-27 — F02 — 1
- Done: `justfile` (`fmt`, `lint`, `test`, `check`, `check-slow`), `lefthook.yml` (pre-commit: `just check`; pre-push: `just check-slow`), `.taplo.toml`, `_typos.toml`. shellcheck runs over git-tracked `*.sh`. verify passes.
- Decisions: tests use `cargo test` (nextest not installed). `check-slow` currently just depends on `check`.
- Not done / known issues: none.
- Next session should: add slow steps to `check-slow` as features land.

### 2026-10-27 — F03 — 1
- Done: `.github/workflows/ci.yml` (jobs `check`, `check-slow`, aggregate `ci`); SHA-pinned actions, minimal permissions, no persisted credentials. `just lint` now runs `actionlint` and `zizmor --offline .github/workflows`. verify passes.
- Decisions: see docs/decisions.md (CI workflow shape). Branch protection must require the `ci` check; this is a GitHub setting a human must apply.
- Not done / known issues: tool installs in CI use taiki-e/install-action (not exercised locally); no cargo cache.
- Next session should: nothing specific.

### 2026-10-27 — F04 — 1
- Done: `deny.toml` (advisories, licences, bans incl. duplicates/wildcards/openssl, sources); `cargo deny check` and `cargo machete` added to `just lint`; CI installs both tools. verify passes.
- Decisions: see docs/decisions.md (supply chain policy).
- Not done / known issues: `cargo deny` fetches the advisory DB, so it needs network. Warnings about unused licence allowances are expected until dependencies exist.
- Next session should: when adding dependencies, fix any deny failures with justified entries, not by loosening policy.

### 2026-10-27 — F05 — 1
- Done: `custodiod::store::KeyStore` (`open`, `put`, `get`, `list`), keys as `SecretSlice<u8>`, read buffer `Zeroizing`. Tests cover 0700/0600, loose-mode rejection, no overwrite, no temp leftovers, bad ids, and `Debug` of keys/store/errors. New deps: secrecy, zeroize, tempfile (dev). verify passes.
- Decisions: see docs/decisions.md (key store layout). Systemd unit must set `StateDirectoryMode=0700`.
- Not done / known issues: no ownership (uid) check yet; no key-type metadata or delete; mutation testing not set up.
- Next session should: nothing specific.

### 2026-10-27 — F05 — 2
- Done: fixed all NEXT_FINDINGS. Umask test now runs in a child process with umask 0o277 (fails if the chmod is removed; verified). Owner checks (`BadOwner`) in `open` and `get` with a test. `get` uses `O_NOFOLLOW` (symlink test). Exactly-sized zeroizing read buffer. `SyncFailed` variant for dir-fsync failure after link. `open` removes stale `.tmp-*`. Debug test asserts exact `[REDACTED]` and covers `Io`. New dep: rustix (fs, process). verify passes.
- Decisions: see docs/decisions.md (Key store hardening).
- Not done / known issues: NEXT_FINDINGS.md left in place for the loop to clear; mutation testing not set up.
- Next session should: nothing specific.

### 2026-10-27 — F05 — 3
- Done: fixed all NEXT_FINDINGS. `open` delegates to `open_as(dir, uid)`; tests for `BadOwner` in `open`, `BadFileType` (symlink to a 0700 dir, regular file), FIFO key file (`O_NONBLOCK|O_NOCTTY`, no hang). `open` now chmods a freshly created dir to exactly 0700 (child-process umask 0o277 test covers it).
- Decisions: none new.
- Not done / known issues: `SyncFailed` is never produced by any test (needs fault injection); note for mutation-testing setup. NEXT_FINDINGS.md left for the loop to clear.
- Next session should: nothing specific.

### 2026-10-27 — F06 — 1
- Done: `custodiod::import` (`parse_p12`, `import_p12`, `ImportError`, `KeyKind`); tests in `crates/custodiod/tests/import.rs` with fixtures from `tests/fixtures/gen.sh` (RSA 2048/3072, P-256/P-384, Ed25519, legacy PBE; no-cert, two-key and no-key files are built in-test). Fuzz target `p12_parse` in `crates/custodiod/fuzz` (10 s smoke run clean); `just fuzz-build` added and wired into `check-slow` and CI. verify passes.
- Decisions: see docs/decisions.md (`.p12` import). Duplicate `syn` skipped in deny.toml.
- Not done / known issues: key↔certificate public-key match not checked; `p12-keystore` holds an unzeroized copy of the key during parsing; no CLI wiring yet; CI changes (nightly, cargo-fuzz) not exercised locally.
- Next session should: nothing specific.

### 2026-10-27 — F06 — 2
- Done: fixed all NEXT_FINDINGS. Certificate must match the key's public key (`ImportError::CertificateMismatch`; RSA n/e, P-256 point computed with `p256`); keys counted via `Pkcs12Archive` (single key without `localKeyId` accepted, extra key without it now `MultipleKeys`); `import_p12` checks both ids are free before writing; `just fuzz-build` uses `find` and fails when no fuzz crate exists. New tests (23 total) incl. RSA/P-256/cross-type mismatch, no-`localKeyId` cases (via `check_archive`), no orphan certificate. New fixtures `p256-other`, `p256-nokid`. New deps: p256, sec1, x509-cert. verify passes.
- Decisions: see docs/decisions.md (`.p12` import).
- Not done / known issues: `p12-keystore` keeps an unzeroized copy of the key while parsing; no CLI wiring yet; CI fuzz changes not exercised locally.
- Next session should: nothing specific.

### 2026-10-27 — F07 — 1
- Done: `custodiod::sign::sign(key, Mechanism, data)` for `CKM_RSA_PKCS` (data signed as is, caller supplies DigestInfo), `CKM_RSA_PKCS_PSS` (SHA-256/384/512 digest, MGF1 same hash, explicit salt length) and `CKM_ECDSA` (raw r||s, RFC 6979). Tests in `crates/custodiod/tests/sign.rs`: OpenSSL known answer for RSA, RFC 6979 A.2.5 vectors for ECDSA, verify round trips with independent public-key ops, length/mismatch/garbage-key errors, no panic for any ECDSA input length (empty input panicked in `rfc6979`; now `BadData`). New deps: rsa (=0.10.0-rc.19), sha2, rand, p256 features. verify passes.
- Decisions: see docs/decisions.md (Signing primitives). `deny.toml` now ignores RUSTSEC-2023-0071 (Marvin) with a justification; no fixed `rsa` exists.
- Not done / known issues: polkit is not called here (the D-Bus layer must authorize before `sign`); no CLI/D-Bus wiring; no SHA-1 PSS; MGF hash is forced equal to the PSS hash; `rsa` is a prerelease.
- Next session should: call `sign` only after a polkit check.

### 2026-10-27 — F08 — 1
- Done: `custodiod::polkit` (`Authorizer` trait, `PolkitAuthorizer` over zbus, `AuthError`, `ACTION_ID`). Calls `CheckAuthorization` with a `system-bus-name` subject and `AllowUserInteraction`; only `is_authorized` passes, challenge/denial/bus error/no polkit are refusals; non-unique senders are rejected first. `data/com.rfirma.custodio.policy` with `auth_self` for any/inactive/active. Tests: `tests/polkit.rs` (private `dbus-daemon` + fake authority: request shape, approve, deny, challenge, error, no polkit, asks every time), `tests/policy.rs` (defaults, no `_keep` even outside comments, one action), unit tests for request building. New dep: zbus (comms, proxy, default-rt; `service` in dev). verify passes.
- Decisions: see docs/decisions.md (polkit authorization).
- Not done / known issues: integration tests need `dbus-daemon` installed (present on CI runners); no cancellation id; the D-Bus service that calls `authorize` before `sign` and the policy install path are for later features; the real polkit was not available here, so wire format is checked only against the fake.
- Next session should: call `Authorizer::authorize(sender)` before every `sign`.

### 2026-10-27 — F09 — 1
- Done: `custodiod::dbus::Custodio<A: Authorizer>` serving `com.rfirma.Custodio1` at `/com/rfirma/Custodio1` (`ListKeys`, `ListCertificates`, `ImportP12`, `Sign`); `main` serves it on the system bus with `PolkitAuthorizer`. `Sign` validates arguments, calls polkit for the sender on every call, then signs; denial/unavailable gives `AccessDenied` and no signature. Integration tests `tests/dbus.rs` (private `dbus-daemon`, fake polkit): import/list/approved sign verified against the certificate, deny, polkit missing, two signatures ask twice, bad arguments rejected before polkit, import errors. Fuzz target `dbus_args` (10 s run clean). `just test-integration` added to `check-slow`. verify passes. `zbus` `service` feature moved to normal deps.
- Decisions: see docs/decisions.md (D-Bus service): `CKM_*` numbers on the wire, `-cert` ids reserved, size caps.
- Not done / known issues: D-Bus bus policy file and unit/packaging not written; `ImportP12` is not polkit-guarded; blocking crypto/IO runs on the executor; `main` is untested against a real system bus/polkit.
- Next session should: nothing specific; the PKCS#11 client can use the `Sign` signature above.

### 2026-10-27 — F10 — 1
- Done: `custodio-cli` library + bin: `parse_args`, `run_import` (traits `PasswordPrompt`, `Importer`), `tty::Terminal` (`/dev/tty`, echo off), `bus::DbusImporter` (`ImportP12` on the system bus). Prints the delete-the-original reminder after success only. Tests `crates/custodio-cli/tests/cli.rs` (11): argv rules (no password option), password only from the prompt, reminder, failure paths, round trip against the real service on a private `dbus-daemon`. verify passes.
- Decisions: see docs/decisions.md (Import CLI). `custodiod` path dependency needed an explicit `version` for `cargo deny` wildcard ban.
- Not done / known issues: `tty::Terminal` is not tested (no tty in CI); the round-trip test needs `dbus-daemon` (runs in `just test`); no `list` subcommand; ImportP12 is still not polkit-guarded.
- Next session should: nothing specific.

### 2026-10-27 — F11 — 1
- Done: `custodio-pkcs11` module. `ffi` (unsafe, pointer checks, panic guard, `pthread_atfork`), `module` (pointer-free logic over a `Backend` trait; unit tests with a fake), `token` (cert → attributes), `backend` (D-Bus client, connection per call), `unsupported` (generated stubs). `data/custodio.module` for p11-kit. `tests/cryptoki.rs` loads the built `.so` through `cryptoki` against a private `dbus-daemon`, fake polkit and the real service, in a child process with `DBUS_SYSTEM_BUS_ADDRESS` set: list/find/sign (RSA PKCS, PSS, ECDSA, compared with the service's own deterministic signatures), denial (each attempt asks), unsupported functions, no service, 8 threads, `fork` while another thread uses the module. `just test-integration` runs it; the test builds the cdylib itself. verify passes.
- Decisions: see docs/decisions.md (PKCS#11 module). Library file is `libcustodio_pkcs11.so` (Cargo forbids hyphens).
- Not done / known issues: no fuzz target for PKCS#11 arguments and no Miri/ASAN run of the FFI layer yet (SPEC asks for both); tested with `cryptoki` only, not yet with `pkcs11-tool`/NSS/p11-kit; slot ids are indexes, so they can shift if keys are added between `C_GetSlotList` calls; `C_GetSlotList` ignores `tokenPresent` and `C_WaitForSlotEvent` is unsupported.
- Next session should: nothing specific; a later feature can add the FFI fuzz target and Miri run.

### 2026-10-27 — F12 — 1
- Done: `just miri` (nightly Miri on `custodio-pkcs11 --lib`), `just asan` (same tests under `-Zsanitizer=address`), both in `check-slow`; CI installs the miri and rust-src components. New `ffi::tests` (9) call every implemented C function through the function list with NULLs, lying-small buffers, absurd lengths, misaligned PSS parameters, and check guard bytes stay untouched. For this the global module's backend is an alias: `DbusBackend` normally, `fake::FakeBackend` under `cfg(test)` or feature `fuzzing`. Fuzz target `pkcs11_args` in `crates/custodio-pkcs11/fuzz` (scripts of calls via `fuzzing::run`; 40 s run clean, ~400k execs); built by `just fuzz-build`. verify passes; `just check` and `just test-integration` green.
- Decisions: see docs/decisions.md (FFI safety).
- Not done / known issues: Miri/ASan do not cover the `.so` integration tests (need a bus and `dlopen`); the real `DbusBackend` path is not under Miri; the fuzz harness never passes pointers with sizes larger than the buffers (UB by contract).
- Next session should: nothing specific.

### 2026-10-27 — F12 — 2
- Done: fixed NEXT_FINDINGS. Clippy errors in the fuzz harness fixed; `just lint` now also runs clippy with `--features fuzzing` and on the fuzz crate. `compile_error!` in `lib.rs` when `fuzzing` is on in a build without debug assertions and without `--cfg fuzzing`; `just lint` asserts a release build with the feature fails; recorded in docs/decisions.md. Harness moved to `ffi/fuzzing.rs` (re-exported as `custodio_pkcs11::fuzzing`). Fixed the `maybe` doc comment; the fuzzer now passes a nonzero count with a NULL template/attribute list. `check`, miri, asan, fuzz-build green; 20 s fuzz run clean.
- Not done / known issues: as in attempt 1.
- Next session should: nothing specific.

### 2026-10-27 — F13 — 1
- Done: `just mutants` runs `cargo-mutants` on `polkit.rs`, `dbus.rs` and `store.rs` (the authorization path and the key store) in `custodiod`; any surviving or timed-out mutant fails. Added to `check-slow`. Final run: 120 mutants, 103 caught, 17 unviable, 0 missed. New unit tests: exact boundaries (id length, sign data, p12/password size, key file size), PSS SHA-256/512, `Display`/`Debug` text, `store_error` mapping, stale-temp cleanup keeps keys, non-NotFound open errors.
- Decisions: three small refactors so no mutant is equivalent instead of excluding anything: `open_as` uses `if` on the error kind; `get` flags use `.union()` (`|` and `^` of disjoint bits are equal); `get` maps open errors in one arm. No mutants are skipped or excluded.
- Not done / known issues: takes ~2 min; `sign.rs` and `import.rs` are not in scope (spec names only authorization path and key store); CI installs `cargo-mutants` but was not exercised locally.
- Next session should: nothing specific.

### 2026-10-27 — F14 — 1
- Done: `just coverage` (cargo-llvm-cov over the whole workspace, summary + HTML + JSON in `target/coverage`, no minimum) and `just crap` (new crate `crates/crap`: syn complexity × llvm-cov region coverage per function; fails above 30; worst now 30.0). Both added to `check-slow`; CI installs `cargo-llvm-cov` and `llvm-tools-preview`. Tests: `crap` unit tests (complexity rules, formula, export parsing, matching, threshold) and `tests/cli.rs` (binary on a fixture crate). To get under the gate: `custodio-cli`'s prompt split into `prompt_on` with pty tests (echo off, restored, closed tty). The cryptoki test now builds the module into its own target dir so it works under llvm-cov. verify passes; `just lint`, `just test`, `just test-integration` green.
- Decisions: see docs/decisions.md (Coverage and CRAP gate): threshold 30; only `ffi/fuzzing.rs` excluded.
- Not done / known issues: CRAP is region-based, not line-based; `just coverage` takes about a minute; CI install of cargo-llvm-cov was not exercised locally.
- Next session should: nothing specific.

### 2026-10-27 — F14 — 2
- Done: fixed NEXT_FINDINGS. `success_tells_the_person_to_delete_the_original` was flaky: it asserted the output does not contain `"pw"`, but the random temp dir name (e.g. `.tmpwtJfq2`) can contain it. It now uses a password that cannot appear in a path. `just coverage && just crap` passes; the CLI tests were run three times in a row green.
- Not done / known issues: as in attempt 1. The worst CRAP score is exactly 30.0 (threshold 30, fails only above).
- Next session should: nothing specific.

### 2026-10-27 — F14 — 3
- Done: fixed NEXT_FINDINGS. `#![forbid(unsafe_code)]` added to `crap` lib and bin roots. `just crap` now lists the crate dirs before `--exclude` for readability. `just lint` clean; `just coverage && just crap` passes.
- Not done / known issues: the worst CRAP score is still exactly 30.0 (`custodiod/src/main.rs` `run`, 0% covered); one more branch there turns `check-slow` red.
- Next session should: nothing specific.

### 2026-10-27 — F15 — 1
- Done: `data/custodio.service` (DynamicUser, StateDirectory=custodio, strict hardening; offline exposure 0.6 SAFE) and `data/com.rfirma.Custodio1.conf` (only user `custodio` may own the bus name; anyone may send). `just security-score` (threshold 10 = 1.0, tenths of the score) runs `systemd-analyze security --offline=yes` on the unit and also asserts a bare unit fails the gate; it is a dependency of `check`. verify passes.
- Decisions: see docs/decisions.md (Service unit and D-Bus policy). `User=custodio` is explicit so the bus policy can name the user.
- Not done / known issues: not run under a real systemd; `PrivateUsers=` and the syscall filter may need loosening in the end-to-end test. Unit and policy are not yet installed by any package (packaging feature).
- Next session should: nothing specific.

### 2026-10-27 — F15 — 2
- Done: fixed NEXT_FINDINGS. Static `custodio` account via `data/sysusers.d/custodio.conf` (the bus policy names it; dbus drops a policy for an unknown user at config load, so the dynamic-only user could never own the name). New `just bus-policy` (private dbus-daemon includes the policy: policy user owns the name, `nobody` is denied; checked that an allow-all policy fails it) and `just unit-verify` (`systemd-analyze verify` with stub ExecStart, any output fails; sysusers dry run); both in `check`. Packaging requirements (binary path, sysusers, policy, activation file) recorded in docs/decisions.md. `just check && just security-score` pass.
- Not done / known issues: the syscall filter and `PrivateUsers=` still have not run under a live systemd (none here); `unit-verify` checks syntax only.
- Next session should: nothing specific.

### 2026-10-27 — F15 — 3
- Done: evaluator passed attempt 2; applied its optional fix. `bus-policy`'s `try_own` now has its own EXIT trap (it runs in a `$(...)` subshell) so the private `dbus-daemon` is killed if it fails partway. `just check && just security-score` pass.
- Not done / known issues: as in attempt 2 (nothing run under a live systemd; end-to-end feature must start the real unit).
- Next session should: nothing specific.

### 2026-10-27 — F16 — 1
- Done: `just package` builds the release binaries and one `.deb` (`target/debian/custodio_0.1.0-1_amd64.deb`) with the daemon, `custodio` CLI, PKCS#11 `.so`, systemd unit, sysusers file, D-Bus policy and activation file, polkit action and p11-kit `.module`; a postinst creates the `custodio` account. Metadata in `crates/custodiod/Cargo.toml`. verify passes; `just lint` clean.
- Decisions: see docs/decisions.md (Debian package).
- Not done / known issues: package not installed on a live system; the service is not enabled on install.
- Next session should: nothing specific.

### 2026-10-27 — F17 — 1
- Done (written, NOT run): `just e2e` (depends on `package`) runs `e2e/run.sh`, which builds `e2e/Containerfile` (Debian trixie, systemd as PID 1, real polkit/logind, pkcs11-tool, NSS tools), boots it privileged with podman or docker, and execs `e2e/guest.sh`: installs the .deb, starts the real `custodio.service`, imports RSA and EC keys through `custodio import` on a pty (`import.py`), then runs `e2e/user.sh` as an ordinary user in a logind session (`su -l`). `user.sh` starts `agent.py` (a real polkit authentication agent for that session; approves via `polkit-agent-helper-1`, or cancels, according to a mode file, and logs each request). Checks: acceptance 1 (the user cannot list/read the key files), pkcs11-tool approve/deny/second-signature-asks-again for RSA and ECDSA, NSS (`modutil -add`, `certutil -C` signs a CSR with the custodied key) approve/deny/ask-again, and the agent request count after each step.
- Not done / known issues: nothing here has run. The dev container has no podman/docker, no systemd as PID 1 and cannot `unshare` (checked), so `just e2e` stops at "neither podman nor docker is installed". Expect first-run fixes: the hardening in the unit (syscall filter, `PrivateUsers=`) against a live systemd, agent registration details, certutil flags, whether the service's RSA_PKCS accepts the 32-byte input. `just e2e` is not in `check-slow` for the same reason. See BLOCKED.md.
- Next session should: run `just e2e` somewhere with a container engine that can run privileged systemd containers, then fix whatever fails.

### 2026-10-27 — F17 — 2 (human-assisted, run on the host)
- Done: unblocked by running `bash e2e/run.sh` on the host with rootless podman (the .deb built in the dev container). All checks pass. Fixes: `custodiod` canonicalizes `STATE_DIRECTORY` (with `DynamicUser=` it is a symlink into `/var/lib/private` and the store rejects symlinks); the polkit action declares `org.freedesktop.policykit.owner` = `unix-user:custodio` (otherwise polkit refuses the service's `CheckAuthorization` for another user's subject); `guest.sh` reloads dbus instead of restarting it (restart dropped logind off the bus) and gives alice the work dir; `user.sh` acceptance-1 listing check follows the symlink, `certutil -C` without `-h all` and with the DER CSR. The unit's hardening ran unchanged under a live systemd.
- Decisions: docs/decisions.md (state dir symlink, polkit action owner).
- Not done / known issues: the loop's dev container still cannot run `just e2e`; a human runs it on the host.
- Next session should: nothing specific.

### 2026-10-27 — F18 — 1
- Done: `docs/findings.md` answers the three open questions, each claim marked verified or inferred: `CKA_ALWAYS_AUTHENTICATE` in NSS, Firefox, LibreOffice, pkcs11-provider and libp11; D-Bus client behaviour with threads and fork in NSS-hosting processes; polkit/bus versions per distribution. verify passes.
- Decisions: keep `CKA_ALWAYS_AUTHENTICATE=false` and authorize inside `C_Sign` (reasons in findings).
- Not done / known issues: source reading only, no live experiment; no real Firefox/LibreOffice run; "default bus" per distro is inferred.
- Next session should: nothing specific.

### 2026-10-27 — F18 — 2
- Done: fixed NEXT_FINDINGS. New test `signing_leaves_no_helper_threads` (cryptoki.rs) counts `/proc/self/task` around `C_Sign`: no thread created, none lingering; findings.md now rests on that measurement (the `blocking`-like string is zbus's `zruntime` pool, unused on our path). Fork section says exactly what the `forks` test covers (not a fork during `C_Sign`). polkit's use of `ProcessFD` confirmed in `polkitsystembusname.c`. Fedora default-bus row marked inferred; open risk added. Decisions added to docs/decisions.md. `just check` passes.
- Not done / known issues: fork during an in-progress `C_Sign` untested; no real Firefox/LibreOffice run.
- Next session should: nothing specific.

### 2026-10-27 — F18 — 3
- Done: fixed NEXT_FINDINGS. findings.md header now says source reading plus the `signing_leaves_no_helper_threads` experiment; the claim is narrowed to "no thread left behind after `C_Sign`" (a thread started and joined inside the call is explicitly not measured); same narrowing in docs/decisions.md and the test's doc comment. The `tasks` mode now returns an error when the count changes. cryptoki tests (10) and `just lint` pass.
- Not done / known issues: no in-call thread sampling; fork during `C_Sign` untested; no real Firefox/LibreOffice run.
- Next session should: nothing specific.
