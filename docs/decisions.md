# Decisions

Decisions that `SPEC.md` leaves open, newest last.

<!-- ### YYYY-MM-DD — Title
Decision. Why. Alternatives considered. -->

## 2026-10-27 — Lint config for custodiod
- Decision: `custodiod/Cargo.toml` declares its own `[lints.clippy]` (pedantic + unwrap/expect/panic/indexing) instead of `workspace = true`; edition 2024, toolchain pinned to 1.99.1.
- Why: Cargo forbids extending `workspace.lints` with per-crate additions.
- Alternatives: put all deny lints in the workspace (would also restrict the other crates; less flexible).

## 2026-10-27 — CI workflow shape (F03)
- Decision: `.github/workflows/ci.yml` runs `just check` and `just check-slow` as separate jobs plus an aggregate `ci` job. Actions are pinned by commit SHA with a version comment; the workflow has `permissions: {}` and each job gets only `contents: read`. Branch protection must require the `ci` status check (a repository setting, not expressible in the repo).
- Why: one stable required check name survives job renames; SHA pins resist tag hijacking.
- Alternatives: requiring each job individually (brittle); Dependabot-managed pins (not yet added).

## 2026-10-27 — Supply chain policy (F04)

- Decision: `deny.toml` denies yanked crates, duplicate versions, wildcard requirements, unknown registries and any git source; licence allowlist is permissive licences plus MPL-2.0; `openssl`/`openssl-sys` are banned. `cargo deny check` and `cargo machete` run in `just lint`.
- Why: most conservative reading of SPEC. Duplicates are denied rather than warned; when a real duplicate appears, add a justified `skip` entry.
- Alternatives: warn on duplicates (weaker); allow GPL-family licences (EUPL compatibility is narrower).

## 2026-10-27 — Key store layout (F05)
- Decision: one file per key, named by id (`[A-Za-z0-9_-]{1,64}`), in the state dir. Written to a `.tmp-*` file (`create_new`, 0600, fsync), then `hard_link`ed into place so it is atomic and never overwrites; dir fsynced. An existing state dir or key file whose mode is not exactly 0700/0600 is rejected, not repaired.
- Why: conservative; a loosened mode may mean the key was already exposed, so a human should look. Systemd must create the dir with `StateDirectoryMode=0700`.
- Alternatives: `rename` (silently overwrites); auto-chmod (hides exposure).

## 2026-10-27 — Key store hardening (F05, attempt 2)
- Decision: `open` checks the dir owner and `get` checks the file owner against the effective uid; `get` opens with `O_NOFOLLOW` and rejects symlinks; reads use an exactly-sized `Zeroizing` buffer; `open` deletes stale `.tmp-*` files (single process per state dir); a failed dir fsync after linking returns `SyncFailed` (key is stored) instead of `Io`.
- Why: SPEC requires service-uid ownership; avoids key bytes in freed memory and reading keys via symlinks.
- Alternatives: owner check only in tests (weaker); ignoring dir fsync errors (hides durability loss).

## 2026-10-27 — `.p12` import (F06)
- Decision: `custodiod::import` uses `p12-keystore` (pure Rust; reads both modern PBES2 and legacy 3DES/RC2 files). Accepts exactly one private key, RSA with a 2048-bit modulus or EC on prime256v1, with at least one certificate; input capped at 1 MiB. Key is stored as PKCS#8 DER under `<id>`, leaf certificate under `<id>-cert` (written first, as it is public). The leaf certificate is the one in the file whose public key equals the key's (RSA n/e, or the P-256 point computed from the private scalar with `p256`); `localKeyId` is not trusted, and no match is `CertificateMismatch`. Keys are counted from `Pkcs12Archive`, so bags without `localKeyId` are not ignored. `import_p12` refuses up front if `<id>` or `<id>-cert` exists, so a refused write cannot leave an orphan certificate.
- Why: the spec scopes keys to RSA 2048 and P-256; one key per file keeps import unambiguous. `p12-keystore` keeps its own non-zeroized copy of the key while parsing; no zeroizing pure-Rust alternative exists, so the copy is dropped right after extraction.
- Alternatives: `pkcs12` + `rsa`/`p256` crates directly (more code, more attack surface); OpenSSL (banned). `deny.toml` skips the duplicate build-time-only `syn` 2.
- Fuzzing: `crates/custodiod/fuzz` is its own workspace (nightly, sanitizers); `just fuzz-build` builds every `*/fuzz/Cargo.toml` and is part of `check-slow` (CI installs nightly and cargo-fuzz).

## 2026-10-27 — Signing primitives (F07)
- Decision: `custodiod::sign::sign(key, Mechanism, data)` takes the PKCS#8 DER from the store and signs caller-prepared bytes like PKCS#11: `RsaPkcs` signs `data` as is with PKCS#1 v1.5 padding (caller gives the `DigestInfo`); `RsaPkcsPss` needs a SHA-256/384/512 digest of matching length and uses MGF1 with the same hash (SHA-1 not offered, conservative); `Ecdsa` returns raw `r || s` (64 bytes) with RFC 6979 nonces. A mechanism that does not fit the key type is `MechanismMismatch`. Empty ECDSA input is rejected because the nonce code panics on it.
- Crypto crates: `rsa` 0.10.0-rc.19 (pinned with `=`; only prerelease line with the current `crypto-bigint`) and `p256`/`ecdsa`, `sha2`. RUSTSEC-2023-0071 (Marvin) is ignored in `deny.toml` with a justification: no fix exists, each signature needs a polkit approval so timing samples cannot be gathered at scale, RNG blinding is on, and a same-uid attacker is out of scope.
- Alternatives: OpenSSL (banned); `sad-rsa` (unknown fork, supply chain risk); no RSA (SPEC requires RSA 2048).
- Not done: polkit is not called here; the caller (D-Bus layer) must authorize before `sign`.
