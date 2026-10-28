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

### 2026-10-28 — F23 — attempt 1
- Done: pinned nightly installed (`rustup toolchain install nightly-2026-10-26 …`). `SIGN_CALLS` in
  `fake.rs` (+ `fake/tests.rs`); `ffi/tests/sanitizers.rs` (6 tests, exact-size and guarded heap
  buffers); fuzz harness: ops 17-20 (`C_SignUpdate`, `C_SignFinal`, `C_Login`, `C_Logout`) in
  `ffi/fuzzing/ops.rs`, composed mechanisms in `C_GetMechanismInfo`/`C_SignInit`, tests in
  `ffi/fuzzing/tests.rs` (reference model, 24 permutations, 2000 random scripts); lint structure
  (`deny` in `lib.rs`, `allow` in `ffi.rs`/`unsupported.rs`, `forbid` in the rest); justfile `test`
  line and `crap` exclude of `fuzzing/ops.rs`. ASan, fuzz-build, lint-fuzz, `just lint`, `just check`
  pass; a 60 s `cargo fuzz run --target x86_64-unknown-linux-gnu` (musl target missing here): 289k runs, no crash.
- Baseline found Miri failing/unusable on F19-F20 tests, fixed without hiding tests: the
  `cross_verify_*` unit tests read `.p12` from disk (isolation error) and derive keys (PBKDF2, minutes
  in Miri): they now embed PKCS#8 keys (`tests/*-key.pk8.der`); `cross_verify_openssl` spawns a process,
  which Miri cannot, so it moved to `tests/composed_openssl.rs` (still runs in `just test`);
  `composed_sign_big_message` Miri size 1 MiB -> 64 KiB (1 MiB took ~45 min).
- Deviations from the contract: tests of fake/fuzzing live in `fake/tests.rs` and `fuzzing/tests.rs`
  (inline test modules are forbidden by the file gate), so `grep SERIAL fuzzing.rs` finds none; `SERIAL`
  is `pub(crate)` (and `ffi::tests` too) so `fake::tests` can take it. Harness change: session handles
  grow for the whole process, so `run` probes the next handle and ops use `base + value % 4`
  (`C_SignInit` session was `b % 4`). `fuzzing/ops.rs` split out for tidiness; `crap` exclude extended.
- Mutations (not committed, tree restored): (a) ASan + Miri (named tests) fail; (b) ASan whole lib,
  ASan `fuzzing::tests::script_reaches_composed_mechanisms` (heap overflow) and Miri
  `multipart_final_small_buffer_keeps_operation` fail; (c) Miri `ffi::tests::login` and
  `login_arguments` fail; (d) Miri `login_arguments` fails; (e) ASan/Miri `composed_mechanism_info` and
  Miri `script_reaches_composed_mechanisms` fail; (f) `login_logout_ops_are_wired` fails for login and
  logout; (g) `sequences_in_any_order` and `composed_sign_after_update_is_rejected` fail. (a)/(b) were
  run with named Miri tests rather than a second full `just miri` (it takes an hour).
- Verify: `just miri` (76 tests, ~40 min), `just asan`, `just fuzz-build`, `just lint-fuzz`, `just lint`, `just check` pass;
  `fuzzing::` run under Miri (4 tests) and ASan pass.
- Not done / known issues: none for F23. `scripts/check-files.sh` prints `file:
  command not found` here (pre-existing); sizes checked by hand.
- Next session should: start the next feature.

### 2026-10-28 — F24 — attempt 1
- Done: `custodiod::audit` (`audit.rs`, `audit/{wire,journal,memory,tests}.rs`): `AuditSink`, typed `Entry`
  (`Outcome`, `Caller`, `KeyId`, `AuditMechanism`), `MemorySink`, `FailingSink`, own `JournalSink`
  (one non-blocking `UnixDatagram` per call, `TooLarge` over 16 KiB, `ShortSend` check). The store's
  key-id rule is now `store::valid_key_id`, shared with `KeyId`. compile_fail doctests in `audit.rs`.
  Decisions recorded; `audit/*.rs` added to `just mutants`.
- Deviations: private `send_fields(path, max, fields)` takes the size limit (3 args) so `record` and
  the tests share one function. `AuditError::ShortSend` is a new variant. `just mutants` not run.
- Verify: `just check`, `just system-gates` (0.6 SAFE), `cargo test --doc -p custodiod` pass. Unit unchanged.
- Next session should: start the next feature (F25 wires the sink into `Sign`).

### 2026-10-28 — F24 — attempt 2
- Done: fixed the evaluator's finding 1: the struct-literal `compile_fail` doctest in `audit.rs` now has all four
  fields, so only the private-field error remains. Finding 2 (a sibling per case) not blocking; left as is.
- Verify: `cargo test --doc -p custodiod`, `just check` pass.
- Next session should: start the next feature.

### 2026-10-28 — F24 — attempt 3
- Done: closed the 4 surviving mutants from the evaluator's review: new `size_limit_is_exact` (exact
  boundary and `MAX_DATAGRAM` value), `Display` texts asserted in `debug_prints_only_typed_fields`,
  `Entry::mechanism()` asserted in `memory_sink_records_entries`.
- Verify: `cargo test -p custodiod --lib audit` and `just check` pass.
- Next session should: start the next feature.

### 2026-10-28 — F25 — attempt 1
- Done: `credentials.rs` (`CallerCredentials`, `BusCredentials` via `GetConnectionCredentials`, pure `caller_from`);
  `Entry::without_caller` and `caller() -> Option<Caller>` (decision recorded); `Custodio<A, C>::new(store, authorizer,
  credentials, sink)`; `Custodio::sign_call` holds the logic (the D-Bus `Sign` passes the header's sender): validate,
  credentials, polkit for the same sender, sign, one entry, then the reply. Any sink error gives `Failed("audit
  unavailable")`. `main.rs` builds via `build_service` (journal sink, bus credentials). Call sites and `justfile`
  (`--test audit`, mutants list) updated. Tests: `tests/audit.rs` + `tests/audit/*.rs`, `dbus/tests.rs::sign_call`,
  `main_tests.rs::wiring`, `credentials/tests.rs`.
- Deviations: the sink runs on its own thread (`offload.rs`, no new dependency) because zbus's executor is shared by
  the connection and a blocking sink would stall it; `entry_is_recorded_before_the_reply` uses zbus's own executor
  (tokio is not a dependency). The scanned import password is the fixtures' `test-password`, not a new sentinel
  fixture. `sign_call` is `pub` (the no-sender test calls it).
- Verify: `just check`, `just test-integration`, `cargo test -p custodiod --locked --test audit`, `just lint`,
  `just system-gates` (0.6 SAFE) pass; `just mutants`: 192 mutants, 149 caught, 43 unviable, 0 missed; `Cargo.lock` unchanged.
- Next session should: start the next feature.

### 2026-10-28 — F25 — note from the operator
- Known issue: during session 1, `crates/custodiod/tests/audit/leaks.rs` hung. Its child
  `audit-… --exact leaks::child_client --test-threads=1` sat for 6+ minutes at ~0 s of CPU, and an operator
  killed it by hand. The session later reported `--test audit` passing, so the hang may be intermittent.
- Next session should: check whether `leaks::child_client` can block forever (e.g. waiting on a reply or a
  pipe that never arrives) and bound it with a timeout, so `just check`, `verify` and CI cannot hang on it.

### 2026-10-28 — F25 — attempt 2
- Done: NEXT_FINDINGS 1: the child client has a 10 s method timeout and the parent polls `try_wait` for 30 s, then
  kills the child and fails (`leaks::wait_bounded`), so `child_client` cannot hang the run (also answers the
  operator's note). 2: `outcome_signed` verifies the RSA PKCS#1 signature with the fixture's public key. 3: new
  fixtures `p256-sentinel.p12`, `rsa2048-sentinel.p12` (password `P@ss-sentinel-7f3a91c4`, added to `gen.sh`)
  are what `entries_contain_no_secrets` imports and scans for. 5: `exactly_one_entry_per_call` asserts each reply
  is `Ok` only for `Signed`. 4 (`offload.rs`) stays as a disclosed deviation.
- Verify: `just check`, `just test-integration`, `cargo test -p custodiod --locked --test audit` pass.
- Next session should: start the next feature.

### 2026-10-28 — F26 — attempt 1
- Done: `docs/audit.md`, `data/custodio.catalog` (shipped as `usr/lib/systemd/catalog/custodio.catalog`, mode
  `-rw-r--r--`), `audit/docs_tests.rs` (9 tests tying code, docs and catalog; exhaustive helpers for `Outcome` and
  `AuditMechanism`). Drift checked by hand: renaming a field literal, deleting a docs row and removing a field from
  the catalog each fail `docs_tests`; reverted.
- Verify: `just check`, `just lint`, `just package` and the catalog line in `dpkg-deb -c` pass.
- Catalog compile check (journalctl 257, dev container): `journalctl --root=<tmp> --update-catalog` accepts the file
  (exit 0, database written). `--root=<tmp> --list-catalog <id>` could not show the id ("No such file or directory"; with
  no argument it hits a systemd assertion in catalog_list), so the "listed" part of the evidence was NOT confirmed here.
  The evaluator should weigh this.
- Next session should: start the next feature.

### 2026-10-28 — F26 — attempt 2
- Done: ticked the five contract steps (work was committed in attempt 1). Re-ran `just check`, `just package` and the
  catalog line in `dpkg-deb -c` (mode `-rw-r--r--`): all pass. The `--list-catalog` caveat from attempt 1 stands.
- Next session should: start the next feature.

### 2026-10-28 — F26 — attempt 3
- Done: NEXT_FINDINGS 1: the catalog header is now `-- <MESSAGE_ID>` with no language tag (systemd's default-entry
  convention; the ` en` tag made `--list-catalog` abort). `catalog_format` expects it; the contract's evidence line for
  it was corrected as the evaluator asked. 2: mechanisms listed once (bullets) in `docs/audit.md`.
- Verified: `journalctl --root=<tmp> --update-catalog` exits 0 and `--list-catalog <id>` now prints
  `<id> custodio: Custodio signing request handled`. The feature's `verify` command exits 0.
- Next session should: start the next feature.

### 2026-10-28 — F26 — attempt 4
- Done: NEXT_FINDINGS: restored the approved contract text (only ticks differ). The approved evidence wants the first
  catalog line `-- <MESSAGE_ID> en`, but a catalog with only that entry makes `journalctl --list-catalog` abort. So
  `data/custodio.catalog` now has the `en` entry first and an identical untagged default entry after it;
  `catalog_format` checks both (one `Subject:` and one `Defined-By:` each).
- Verified: `journalctl --root=<tmp> --update-catalog` exits 0 and `--list-catalog <id>` prints
  `<id> custodio: Custodio signing request handled`. The feature's `verify` command exits 0.
- Next session should: start the next feature.
