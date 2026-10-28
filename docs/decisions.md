# Decisions

Choices SPEC.md leaves open that a later session might undo without knowing why. An entry goes
here only if all three hold:

1. SPEC.md does not decide it.
2. A reasonable alternative was rejected.
3. Someone could undo it by mistake without this note.

Not here: what a feature builds or how its files are laid out (code and commit), fixes (commit),
research (docs/findings.md), open work (issues). When a decision changes, edit its entry instead
of adding one that contradicts it.

Format: a title and three short bullets, a couple of lines each:

```
## YYYY-MM-DD — Title
- Decision:
- Why:
- Rejected:
```

## 2026-10-27 — Lints declared per crate in custodiod
- Decision: `custodiod/Cargo.toml` has its own `[lints.clippy]` (pedantic plus `unwrap_used`,
  `expect_used`, `panic`, `indexing_slicing`) instead of `workspace = true`.
- Why: Cargo cannot extend `workspace.lints` per crate, and the restriction lints are for the
  service only.
- Rejected: all deny lints in the workspace (would bind every crate).

## 2026-10-27 — Supply chain policy
- Decision: `deny.toml` denies duplicate versions (justified `skip` entries only), yanked crates,
  wildcards, unknown registries and git sources; permissive licences plus MPL-2.0; OpenSSL banned.
- Why: the most conservative reading of SPEC; EUPL-1.2 compatibility.
- Rejected: warning on duplicates; GPL-family licences.

## 2026-10-27 — Key store refuses instead of repairing
- Decision: a state dir or key file whose mode is not exactly 0700/0600, whose owner is not the
  service, or that is a symlink is rejected, not fixed. Keys are written to a temp file and
  `hard_link`ed into place.
- Why: a loosened mode may mean the key was already exposed, so a person should look; `hard_link`
  is atomic and never overwrites.
- Rejected: auto-chmod (hides exposure); `rename` (overwrites silently).

## 2026-10-27 — `.p12` import
- Decision: `p12-keystore` parses the file; the leaf certificate is the one whose public key equals
  the key's, not the one `localKeyId` points to.
- Why: pure Rust (OpenSSL is banned); `localKeyId` is attacker-controlled input.
- Rejected: `pkcs12` with `rsa`/`p256` directly (more code); trusting `localKeyId`.

## 2026-10-27 — RSA crate and RUSTSEC-2023-0071
- Decision: `rsa` pinned to `=0.10.0-rc.19`, and RUSTSEC-2023-0071 (Marvin) ignored in `deny.toml`
  with its justification. PSS offers SHA-256/384/512, not SHA-1.
- Why: no fixed release exists; each signature needs a polkit approval, so timing samples cannot be
  gathered at scale, blinding is on, and a same-uid attacker is out of scope.
- Rejected: OpenSSL (banned); `sad-rsa` (unknown fork); no RSA (SPEC requires it).

## 2026-10-27 — polkit fails closed
- Decision: only `is_authorized == true` signs; a challenge, a denial, a bus error, a malformed
  reply or no polkit are all refusals. The `Authorizer` trait is async.
- Why: fail closed; a blocking trait would stall the D-Bus service's executor.
- Rejected: pid/uid subjects (racy; SPEC wants polkit to resolve the pidfd).

## 2026-10-27 — D-Bus mechanisms as PKCS#11 numbers
- Decision: `Sign` takes `CKM_*` numbers for mechanism and hash, checked before any key is read.
- Why: the module passes them through unchanged, and numbers leave less to parse than names.
- Rejected: string mechanism names.

## 2026-10-27 — Import password only from the terminal
- Decision: `custodio import` reads the password from `/dev/tty` with echo off; no option, stdin or
  environment variable, and no `rpassword`.
- Why: argv and the environment leak through `/proc` and shell history; `rpassword` uses `unsafe`.
- Rejected: reading stdin when piped (invites passwords in files).

## 2026-10-27 — PKCS#11 module: a connection per call
- Decision: each call opens and drops its own system-bus connection; nothing survives a call, and
  the one mutex is never held across D-Bus and is held across `fork`. Unsupported functions are
  stubs returning `CKR_FUNCTION_NOT_SUPPORTED`; denial is `CKR_FUNCTION_FAILED`; without the service
  `C_GetSlotList` returns no slots.
- Why: fork and thread safety inside Firefox and LibreOffice (docs/findings.md); consumers keep
  their other modules when the service is down.
- Rejected: a persistent connection; NULL entries in the function list; `CKR_FUNCTION_CANCELED`.

## 2026-10-27 — `CKA_ALWAYS_AUTHENTICATE` stays false
- Decision: `C_Sign` itself asks polkit on every signature; the attribute stays false.
- Why: NSS logs in per signature only with an application password callback, and Firefox logs in
  with `CKU_USER`, so the attribute cannot force a prompt (docs/findings.md, section 1).
- Rejected: `true` (clients that skip the login still reach `C_Sign`; those that log in prompt
  twice).

## 2026-10-27 — The `fuzzing` feature never ships
- Decision: under the `fuzzing` feature the module signs through a fake that never asks polkit.
  `lib.rs` has a `compile_error!` for a release build with the feature, and `lint-fuzz` checks that
  error fires.
- Why: fuzzing through the function list against the real backend is slow and nondeterministic.
- Rejected: fuzzing against the D-Bus backend.

## 2026-10-27 — Own CRAP scorer
- Decision: `crates/crap` scores functions from the llvm-cov JSON, threshold 30; only the fuzz
  harness `ffi/fuzzing.rs` is excluded. Coverage itself has no minimum.
- Why: no maintained Rust CRAP tool reads llvm-cov output; SPEC wants coverage as a report.
- Rejected: a Python script with a token heuristic; a coverage target.

## 2026-10-27 — Static `custodio` user
- Decision: `data/sysusers.d/custodio.conf` creates a static `custodio` account; the unit keeps
  `DynamicUser=yes`, which reuses it.
- Why: dbus-daemon and dbus-broker resolve `<policy user=…>` when they load, so with a purely
  dynamic user nobody could own the bus name.
- Rejected: a group or `at_console` bus policy (broader).

## 2026-10-27 — Fixes for a live systemd
- Decision: `custodiod` canonicalizes `STATE_DIRECTORY`; the polkit action declares
  `org.freedesktop.policykit.owner` = `unix-user:custodio`; `postinst` ignores reload failures.
- Why: `DynamicUser=` makes the state dir a symlink the store would reject; polkit refuses
  `CheckAuthorization` on another user's subject otherwise; reloads fail in a chroot.
- Rejected: relaxing the store's symlink check; running as root (SPEC forbids).

## 2026-10-28 — CI
- Decision: one required `ci` check; actions pinned by SHA and tools to `mise.toml` versions; jobs
  by build family with caches keyed on toolchain and lockfiles; PRs run lint, test and mutants on
  the diff, main adds coverage and nightly, a weekly job sweeps every mutant. No pre-push hook.
- Why: one serial job took 20 minutes; floating versions and caches broke CI or missed
  without any change in the repository.
- Rejected: a job per recipe (same artifacts rebuilt); every mutant on every push; `check-slow`
  before each push (repeats CI).

## 2026-10-28 — Truncation of SHA-384/512 digests for P-256 happens in the service
- Decision: the module passes the full SHA-384/512 digest for `CKM_ECDSA_SHA384/512`; the
  service's `CKM_ECDSA` truncates it to the leftmost 32 bytes (FIPS 186, SEC 1).
- Why: the service owns the curve and already does it (`ecdsa_long_digest_standard_result`);
  the module stays a thin mapper and the D-Bus interface does not change.
- Rejected: truncating in the module (a second place that must know the P-256 order, and a
  caller of raw `CKM_ECDSA` would still reach the service's truncation).

## 2026-10-28 — Multi-part sign: a conflicting call ends the operation
- Decision: `C_Sign` after `C_SignUpdate`, and a second call on a session while a part is being
  hashed, return `CKR_OPERATION_ACTIVE` and end the operation; later calls give
  `CKR_OPERATION_NOT_INITIALIZED`. The hash state is dropped, never half-used.
- Why: SPEC ends an operation on any failure but a small buffer; a caller racing itself must not
  be able to sign a message it did not intend. SoftHSMv2 returns `CKR_OPERATION_NOT_INITIALIZED`
  for the first case (docs/findings.md); the project keeps the more telling code.
- Rejected: keeping the operation open after the conflict (a retry could sign a different
  message); copying SoftHSMv2's code for the first call.

## 2026-10-28 — Repeated login and reported session state
- Decision: `C_Login` with `CKU_USER` or `CKU_CONTEXT_SPECIFIC` returns `CKR_OK` every time, never
  `CKR_USER_ALREADY_LOGGED_IN`; `C_GetSessionInfo` keeps reporting `CKS_RO_PUBLIC_SESSION` before
  and after any login or logout. `CKU_SO` gives `CKR_SESSION_READ_ONLY_EXISTS` (every session is
  read-only), another user type `CKR_USER_TYPE_INVALID`. Interim: settle it by the manual
  acceptance clients (SPEC open question).
- Why: the most tolerant choice that keeps the M0 tests green; no client sees a login error and
  the reported state is never an error. A login keeps no state, so nothing can go stale.
- Rejected: `CKR_USER_ALREADY_LOGGED_IN` on a repeat (breaks clients that log in per operation);
  reporting `CKS_RO_USER_FUNCTIONS` after a login (needs per-session state and a logout rule).

## 2026-10-28 — Own native-journal writer instead of a crate
- Decision: `audit::JournalSink` writes the Native Journal Protocol itself (about 20 lines of encoding).
- Why: no new dependency to vet under cargo-deny, and no `unsafe` (`UnixDatagram` only).
- Rejected: a journald crate (supply chain, and most use `memfd` or `libsystemd`).

## 2026-10-28 — Oversize audit entry is an error
- Decision: an entry whose encoding exceeds `MAX_DATAGRAM` gives `AuditError::TooLarge`; it is never
  truncated and never sent through `memfd`/`SCM_RIGHTS`.
- Why: a cut entry is a wrong audit record; entries are small by construction (typed fields).
- Rejected: truncation; `memfd` passing for large entries.

## 2026-10-28 — Non-blocking journal send
- Decision: the datagram is sent with a non-blocking socket; a busy journal gives `Io(WouldBlock)`.
- Why: a stuck journal must not hang a signing request; the caller (F25) turns the error into a refused
  signature.
- Rejected: blocking send, or retrying and dropping the entry.

## 2026-10-28 — Audit entries may have no caller
- Decision: `Entry::without_caller` entries omit `CUSTODIO_UID`/`CUSTODIO_PID` and say `uid unknown pid unknown`.
- Why: the bus gave no credentials and nothing may be invented.
- Rejected: uid/pid 0, or refusing without an entry.

## 2026-10-28 — Miri runs only the ffi tests
- Decision: `just miri` runs `ffi::` tests only. `module`, `composed`, `token`, `backend`, `fake` and the
  crate tests all `#![forbid(unsafe_code)]`. `unsupported.rs` allows `unsafe` but its stubs only return
  `CKR_FUNCTION_NOT_SUPPORTED` without touching their pointers, and it has no tests.
- Why: the pure-Rust RSA/ECDSA tests took over 14 minutes under Miri and made `just check-slow` too slow;
  Miri only checks `unsafe` code. Miri no longer covers those safe tests; ASan still runs all of them.
- Rejected: running every test under Miri; skipping Miri. Widen the filter if a module gains `unsafe`.
