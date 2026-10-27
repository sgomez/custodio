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

## 2026-10-27 — polkit authorization (F08)
- Decision: `custodiod::polkit` has an `Authorizer` trait (`authorize(sender)`, async, `Ok(())` only on approval) and `PolkitAuthorizer` over a `zbus::Connection`. It calls `CheckAuthorization` with subject `("system-bus-name", {name: sender})`, action `com.rfirma.custodio.sign`, no details, flag `AllowUserInteraction` (1), empty cancellation id. Only `is_authorized == true` passes: a challenge, a denial, a bus error, a malformed reply or no polkit on the bus are all refusals (`Denied` / `Unavailable`). Senders that are not unique names (`:1.x`) are rejected before polkit is called. Nothing is cached. `data/com.rfirma.custodio.policy` sets `auth_self` for any, inactive and active; a test fails on any `_keep`.
- Why: SPEC; fail closed. zbus with only `comms`, `proxy`, `default-rt` (no tokio, no tracing). Dev builds also enable `service` to serve the fake authority in tests.
- Alternatives: a sync/blocking trait (would block the D-Bus service's executor); passing pid/uid subjects (racy, SPEC wants the pidfd resolved by polkit).
- Not done: no cancellation id, so a client that disconnects mid-dialog leaves the dialog until timeout; install location of the policy file is for the packaging feature.

## 2026-10-27 — D-Bus service (F09)
- Decision: `custodiod::dbus::Custodio<A: Authorizer>` is served at `/com/rfirma/Custodio1`, interface `com.rfirma.Custodio1`: `ListKeys() -> as`, `ListCertificates() -> a(say)`, `ImportP12(id s, p12 ay, password s) -> s` (key type), `Sign(id s, mechanism u, hash u, salt_len u, data ay) -> ay`. `mechanism` and `hash` use PKCS#11 `CKM_*` numbers (RSA_PKCS 0x1, RSA_PKCS_PSS 0xD, ECDSA 0x1041, SHA256/384/512 0x250/0x260/0x270); `hash` and `salt_len` must be 0 unless PSS. `Sign` checks arguments (no key touched), then calls polkit for the bus sender of that message, then reads the key and signs; denial, challenge, polkit error or missing sender all give `AccessDenied` and no signature. Ids ending in `-cert` are reserved for certificates and refused from clients; max id length is 59 so `<id>-cert` fits the store limit. Data is capped at 1 KiB, passwords at 1 KiB, `.p12` at 1 MiB. Errors sent over the bus never carry paths or secrets. Argument checks are plain functions (`parse_sign_request`, `parse_import_request`) and are the fuzz target `dbus_args`.
- `main` connects to the system bus and uses `$STATE_DIRECTORY` (default `/var/lib/custodio`).
- Why: conservative; fail closed; a testable seam for the fuzzer.
- Alternatives: string mechanism names (more parsing surface); caching an approval per sender (forbidden by SPEC).
- Not done: the D-Bus bus policy file (which users may call the service) belongs with packaging; `Sign` and `ImportP12` run blocking crypto/IO on the executor; import is not itself polkit-guarded (any bus caller allowed by the bus policy can add keys).

## 2026-10-27 — Import CLI (F10)
- Decision: `custodio import [--id <id>] <file.p12>`. The password is read only from `/dev/tty` with echo off (rustix termios, no `unsafe`); there is no option, stdin or environment variable for it, and any unknown option is a usage error. The id defaults to the file stem only if it is already a valid id (never rewritten); otherwise `--id` is required. The delete reminder is printed only after the service accepted the import; the tool never deletes the file itself. Files over 1 MiB are refused before asking for the password.
- Why: secrets in argv/env leak through `/proc` and shell history; failing closed on odd names avoids surprising ids.
- Alternatives: `rpassword` (extra dependency, uses unsafe), reading stdin when piped (invites scripts that put passwords in files).

## 2026-10-27 — PKCS#11 module (F11)
- Decision: `custodio-pkcs11` (cdylib `libcustodio_pkcs11.so`; Cargo rejects hyphens in library names, so packaging installs it under that name and `data/custodio.module` points at `/usr/lib/custodio/libcustodio_pkcs11.so`). It exports only `C_GetFunctionList`; the function list is a 2.40 list in which every unsupported entry is a stub returning `CKR_FUNCTION_NOT_SUPPORTED` (generated from the `cryptoki-sys` types). One token per key that has a certificate (slot id = index in the sorted list fetched by the last `C_GetSlotList`); each token has two objects: the certificate (handle 1) and the private key (handle 2, `CKA_SIGN`, non-extractable, `CKA_ALWAYS_AUTHENTICATE` false because the service asks polkit on every call). Mechanisms: `CKM_RSA_PKCS`, `CKM_RSA_PKCS_PSS` (SHA-256/384/512 with the matching MGF1), `CKM_ECDSA`. Read-only sessions only; no `C_Login` (tokens have no PIN).
- Concurrency and fork: a connection to the system bus is opened per call and dropped after it, so no connection or thread survives a call. The only shared state is one mutex, never held across a D-Bus call; `pthread_atfork` holds it across `fork` so a child never inherits it locked. A forked child may keep using the module; `C_Initialize` in a process other than the initializing one starts afresh instead of failing. Panics are caught at the FFI boundary (`CKR_GENERAL_ERROR`).
- `C_Sign`: the signature length comes from the certificate's key, so a length query or too-small buffer is answered without calling the service (no polkit prompt wasted) and keeps the operation active; any other outcome ends the operation. Denied → `CKR_FUNCTION_FAILED`, rejected data → `CKR_DATA_INVALID`, service/bus unreachable → `CKR_DEVICE_ERROR`. Without the service `C_GetSlotList` returns no slots rather than an error, so consumers keep their other modules.
- The module does not link `custodiod` (it repeats the bus name and path); the integration test checks they agree. The bus is the system bus, found by zbus (`DBUS_SYSTEM_BUS_ADDRESS` honoured, which is how tests redirect it).
- Alternatives: a persistent connection (needs fork/thread repair); `CKR_FUNCTION_CANCELED` for denial (reserved for parallel functions); NULL entries in the function list (crashes consumers that do not check); a `CKF_LOGIN_REQUIRED` token with `CKA_PRIVATE` keys (needs `C_Login`).

## FFI safety (2026-10-27)
- Decision: the global module's backend is a type alias, `DbusBackend` normally and a fixed fake (`fake.rs`) under `cfg(test)` or the `fuzzing` feature. Miri and ASan run the `ffi` tests (`--lib`) through the function list against the fake; the cryptoki integration tests stay out of both because they need a bus and a `.so` loaded via `dlopen`.
- Decision: the fuzz target `pkcs11_args` (`crates/custodio-pkcs11/fuzz`) runs scripts of calls through the function list with arbitrary values but honest buffer sizes; a caller that lies about sizes is UB by contract. The harness is `unsafe` code behind the `fuzzing` feature, which is never enabled in the shipped module.
- Why: the alternative (fuzzing against the real D-Bus backend) is slow, nondeterministic and would test zbus. Cost: the aliasing means test builds do not compile `DbusBackend` into the FFI path; the integration tests cover it.
- Security invariant: the `fuzzing` feature makes the module sign through a fake that never asks polkit, so it must never reach the shipped `.so`. `lib.rs` has a `compile_error!` when it is on in a build with neither debug assertions nor `--cfg fuzzing` (cargo-fuzz sets it); `just lint` checks that a release build with the feature fails, and clippy now also lints the crate with `--features fuzzing` and the fuzz crate. The fuzz harness lives in `ffi/fuzzing.rs`, so `unsafe` stays inside the FFI layer.
