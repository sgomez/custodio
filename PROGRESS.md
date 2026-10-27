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
