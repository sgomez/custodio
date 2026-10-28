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

### 2026-10-28 — F19 — attempt 1
- Done: `custodio-pkcs11::composed` (`Composed` mapping, `DigestHasher` Clone, `digest_info`,
  `sign_input`), tests in `composed/tests.rs` incl. RFC 8017 prefixes, RSA/ECDSA cross-verification
  with `rsa`/`p256` and the openssl CLI (`cross_verify_openssl` ran, not skipped). Added
  `ecdsa_long_digest_standard_result` in `custodiod/tests/sign.rs`.
- Decisions: the service truncates SHA-384/512 for P-256; it already did, so `sign.rs` is
  unchanged. Recorded in `docs/decisions.md`.
- Not done / known issues: none; wiring into the FFI is for later features.
- Next session should: start the next feature; `composed` is ready to call.

### 2026-10-28 — F20 — attempt 1
- Done: `Mechanism::Composed`, per-token lists and `mechanism_info` (moved with `Mechanism` to
  `module/mechanism.rs` to stay under the file-size gate), `Module::sign` hashing outside the state
  lock via `hash_message`, `C_SignInit` parameter check. Unit tests in `module/tests/composed.rs`
  and `ffi/tests/composed.rs`. Integration: the fixture now has a bus monitor that records the
  `Sign` calls the service receives; scenarios in `tests/cryptoki/composed*.rs` (lists, sign and
  verify, 64 MiB, refusals, retry via the raw function list, denied). RSA cert fixture
  `tests/rsa2048-cert.der` (from `rsa2048.p12`). New dev-dependency `libloading`.
- Decisions: none lasting. Two M0 assertions loosened because composed mechanisms are now listed:
  `basic` (`contains` ECDSA) and the list size in `ffi::tests::list_outputs_respect_the_callers_sizes`
  (4 entries).
- Not done / known issues: `just miri` not run (pinned nightly-2026-10-26 is not installed here).
  `scripts/check-files.sh` prints `file: command not found` in this environment (pre-existing).
- Next session should: start F21 (`C_SignUpdate`/`C_SignFinal` stay `unsupported::*` until then).

### 2026-10-28 — F21 — attempt 1
- Done: steps 1-5. `module/signing.rs` (sign_init, sign, sign_update, sign_final; per-session
  hash state with busy/aborted marks and operation serials), `ffi/sign.rs` (moved the four sign
  functions out of `ffi.rs` for the file-size gate, added `C_SignUpdate`/`C_SignFinal`), stubs
  removed. Unit tests `module/tests/multipart.rs`, `ffi/tests/multipart.rs`; integration scenarios
  `tests/cryptoki/multipart*.rs` (equivalence, large, retry, raw, sign-after-update, denied,
  tasks and fds, forks, threads). `just check` and `just test-integration` pass.
- Decisions: none yet; see BLOCKED.md.
- Not done / known issues: BLOCKED. SoftHSMv2 returns `CKR_OPERATION_NOT_INITIALIZED` for a raw
  mechanism in `C_SignUpdate`/`C_SignFinal`, the contract says `CKR_FUNCTION_NOT_SUPPORTED`; the
  contract tells the builder to stop. Step 6 not done. `just miri` not run (nightly missing).
- Next session should: read the answer to BLOCKED.md, adjust the raw-mechanism code and tests if
  needed, do step 6 (decisions.md), delete BLOCKED.md, commit.

### 2026-10-28 — F21 — attempt 2
- Done: BLOCKED answered earlier (raw `C_SignUpdate`/`C_SignFinal` give
  `CKR_OPERATION_NOT_INITIALIZED` and end the operation; code and tests already changed). Step 6:
  decisions.md entry for the conflicting-call rule; the raw-mechanism code stays in findings.md
  only (it follows SoftHSMv2).
- Decisions: see docs/decisions.md.
- Not done / known issues: `just miri` not run (nightly missing).
- Next session should: start the next feature.

### 2026-10-28 — F21 — attempt 3
- Done: fixed the evaluator's findings. FFI argument-error test now asserts the signed input
  (fake records `LAST_INPUT` under `cfg(test)`); literal "abc" answers and `DigestInfo` prefixes
  for all six mechanisms; racer panic no longer maps to `CKR_OK`; busy-init test checks the final.
- Decisions: none. Finding 5 (harness commits) is operator work from the BLOCKED round, not touched.
- Not done / known issues: `just miri` not run (nightly missing).
- Next session should: start the next feature.

### 2026-10-28 — F22 — attempt 1
- Done: `C_Login`/`C_Logout` in `ffi/login.rs` (session check via `Module::check_session`, SO →
  `CKR_SESSION_READ_ONLY_EXISTS`, other types `CKR_USER_TYPE_INVALID`, credential never read),
  stubs removed. Unit tests `ffi/tests/login.rs`, `module/tests/login.rs` (Fake gained a
  `listed` counter). Harness: all-method counter in `parent.rs`; scenarios in
  `tests/cryptoki/login*.rs`. Two expectations changed as the contract names.
- Decisions: repeated login / session state / SO result entry in `docs/decisions.md`.
- Not done / known issues: `just miri` not run (nightly missing). `just check` and
  `just test-integration` pass.
- Next session should: start the next feature.

### 2026-10-28 — F22 — attempt 2
- Done: fixed the evaluator's finding. `ffi::tests::login_leaves_session_unchanged` now calls `C_Login`
  with the sentinel PIN (all user types) and compares session fields (new `cfg(test)`
  `Module::session_fields`, no new field) and `C_GetSessionInfo`; the module-level test was renamed.
- Decisions: none.
- Not done / known issues: `just miri` not run (nightly missing).
- Next session should: start the next feature.
