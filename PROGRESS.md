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
