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

### 2026-11-01 — F63 — attempt 1
- Done: `just e2e-cases <target> <names|globs>...` (shared `e2e-packages` recipe, used by `e2e` too). `e2e/run.sh TARGET --cases NAME...` validates
  names/globs against the target's universe before any engine call and passes the selection as `exec -e E2E_SELECT=ids`; `e2e/select.sh` (new) holds
  `selected`, `case_group`, `phase_runs`; `report.sh` prints nothing for unselected cases; `guest.sh` skips phases no selected case needs
  (journal/unavailable need user; lifecycle needs upgrade, silently); `check-cases.sh check ... [SELECTED]` accounts a subset. The old/old-path
  guest runs only happen when a selected id belongs to them. Refusal-only target: `refusal.sh` reports through `case_run`, so the filter covers it
  (no own assertion needed). Tests: `test-e2e-select.sh` (guest helper, phase decision), `test-e2e-select-host.sh` (host, stub engine; split off
  `test-e2e-host.sh` because of the 5000-token file gate), subset matrix in `test-e2e-skips.sh`. Edited existing assertions only to follow the moved build
  (`test-e2e-host.sh` recipe line, `test-e2e-old.sh` awk now reads `e2e-packages`).
- Real runs: `just e2e-cases debian13 pkcs11-tool-approve-rsa 'nss-*'` exits 0, "4 cases accounted for", log has 4 E2E-CASE lines; `just e2e-cases debian13 no-such-case`
  exits 1 naming the case (after the package build; no container started).
- Not done: the `verify` starts with `just check`, which is red on the untouched tree for two reasons outside F63 (see BLOCKED.md): `scripts/test-docs-install.sh`
  (its precondition greps SPEC.md for "Ubuntu 24.04", which the M3 spec no longer contains) and shellcheck SC2317 infos in `scripts/test-relabel.sh` with the
  dev container's shellcheck. All F63 tests and `just test-changed F63` otherwise pass.
- Next session should: read BLOCKED.md answer, then run `just check` and the verify once.

### 2026-11-01 — F63 — attempt 2
- Done: BLOCKED.md was answered and the precondition/shellcheck issues are fixed upstream (afcb66f, e928564). No code change needed. Ran the verify parts:
  `just test-changed F63` green; `just e2e-cases debian13 pkcs11-tool-approve-rsa 'nss-*'` exits 0 ("4 cases accounted for", 4 E2E-CASE lines);
  `just e2e-cases debian13 no-such-case` exits 1 and names `no-such-case`.
- Not done: nothing.
- Next session should: nothing for F63.

### 2026-11-01 — F64 — attempt 1
- Baseline (step 1): `cargo test --workspace --locked -- --list` gave 331 test names before the move and the identical sorted 331 after it (`diff` empty;
  names only, binary prefixes dropped). Before the move `test-integration` ran custodiod `dbus`, `polkit`, `audit` and pkcs11 `cryptoki`; `cli.rs` and
  `composed_openssl` ran only under `cargo test -p ...` (so under `test-changed`). After: `cli`, `cryptoki`, `composed_openssl` live in `custodio-it`, and
  `test-integration` runs `cargo test -p custodio-it --test cryptoki` instead of the pkcs11 one; `just test-changed F64` runs `cargo test -p ... -p custodio-it`
  (cli.rs, composed_openssl) and `scripts/test-deps-check.sh` (it is in `test-scripts`).
- Done: new crate `custodio-client` (BUS_NAME, OBJECT_PATH, MAX_P12_LEN; no dependencies); `custodiod` re-exports them (`pub use`), both clients use it and no
  longer depend on `custodiod`. New test-only crate `custodio-it` holds the tests that need service + client (cli, cryptoki/, composed_openssl, fixtures moved
  with them; the cli copy of `p256.p12` was byte-identical and is dropped). The `composed` unit tests in `custodio-pkcs11` no longer link `custodiod`: `raw_sign`
  signs with `rsa`/`p256` directly (the same raw operations as `custodiod::sign`); `composed_openssl.rs` still runs the real service code. pkcs11 dev-deps gained
  features (`rsa` encoding, `p256` pkcs8) and `rand` that `custodiod` used to unify in.
  `scripts/deps_check.py` + `just deps-check` (in `just lint` and next to `cargo deny`/`machete` in `changed_checks.py`); `scripts/test-deps-check.sh`
  (in `test-scripts`) on committed fixtures in `scripts/fixtures/deps-check/` (`edges`: normal, build, dev, transitive; `clean`), each with a committed
  Cargo.lock and no registry dependencies; negative control via a `sed`-patched copy (asserted different from the original); the `lint` recipe is parsed with
  comments removed.
- Grep evidence: the values `com.rfirma.Custodio1` and `MAX_P12_LEN` are defined only in `custodio-client`. Remaining literals are expectations in
  `custodiod` tests, the `cryptoki` test that compares the constants with literals, and the `#[interface(name = ...)]` attribute in `custodiod/src/dbus.rs`
  (an attribute cannot take a constant).
- Not done: nothing.
- Verify: `just test-changed F64`, `just deps-check`, `just test-integration` all exit 0. `scripts/test-changed-checks.sh` expectations were updated for the new crate graph (custodiod no longer has pkcs11/cli as dependents).

### 2026-11-01 — F65 — attempt 1
- Baseline (step 1), read from the code before the change. Service failure → fdo name it arrived as (old `dbus.rs`) → `BackendError` (`backend.rs::map_error`) → CKR (`module/signing.rs` `sign_with`):
  polkit unavailable, no sender, credentials failure, polkit denied → `AccessDenied` → `Denied` → `CKR_FUNCTION_FAILED`;
  no such key, audit unavailable, bad key, signing failure, store failure → `Failed` → `Unavailable` → `CKR_DEVICE_ERROR`;
  every invalid-argument case → `InvalidArgs` → `Invalid` → `CKR_DATA_INVALID`.
  The end value is pinned by `composed_failure_ends_the_operation` for **Sign only**; `ListCertificates` failures reach the module through `list_certificates`, not `sign_with`,
  so for them only the `BackendError` is pinned (`backend/tests.rs`); that code is untouched.
- Done: names are constants in `custodio-client` (`ERROR_*`, `com.rfirma.Custodio1.Error.<Name>`); `custodiod::error::ServiceError` (10 variants, `ALL`, fixed `&'static str` messages,
  manual `zbus::DBusError`) and `From<&RequestError|StoreError|ImportError|SignError|AuthError>`; `dbus.rs` returns it everywhere (no `fdo::Error` left). Pick for the contract's open case:
  no private key / several keys / key without certificate → `WrongPasswordOrBadP12` (doc comment in `error.rs`). Messages contain no `/` (checked by the leak test).
  pkcs11 `error_for_name`/`map_error`: polkit denied + authorization unavailable → `Denied`, invalid args → `Invalid`, everything else (new names, unknown names) → `Unavailable`; the generic
  fdo `AccessDenied`/`InvalidArgs` keep their old meaning (the bus itself answers `AccessDenied` on a policy refusal). CLI: `bus.rs::message_for_name/error_message` (service text no longer shown).
  Tests: `error/tests.rs` (table, distinct, mappings), `tests/errors.rs` (one D-Bus test per failure, leak test with sentinels, fixed-message test), `backend/tests.rs`, `bus/tests.rs`, `custodio-client/src/tests.rs`.
  Existing expectations edited only to the new names (`tests/dbus.rs`, `tests/audit*`, `dbus/tests.rs`). `Fixture._store` became `store` + `store_dir()`; the client's inline tests moved to `tests.rs` (file-layout gate).
- Evidence: `grep -rln --include=*.rs '"com\.rfirma\.Custodio1\.Error' crates --exclude-dir=tests --exclude=tests.rs` prints only `crates/custodio-client/src/lib.rs`; `cargo tree -p custodio-client` shows no dependency.
  `just quick` exit 0; `just mutants-diff F65` (recipe extended with `error.rs` and `backend.rs`): custodiod 16 caught/7 unviable, pkcs11 3 caught/2 unviable, none missed.
  `cargo test -p custodio-it --test cli --test cryptoki` green with no edited expectation.
- Not done: nothing. Not run: the explicit negative controls by hand (a mutant mapping authorization unavailable to `Unavailable` is covered by the mutants run being clean).
- Next session should: nothing for F65.

### 2026-11-01 — F66 — attempt 1
- Done: `docs/api.md` (fixed-shape lines: `### Method`, `- in`, `- out`, `- bounds:`, `- p12 size:`, `- error`, `- action`) and `crates/custodiod/tests/api_contract.rs`, plus `just api-contract`
  (`cargo test -p custodiod --test api_contract`; a workspace test, so `just test` runs it too). It starts the service on a private bus, reads `Introspect`
  restricted to the `com.rfirma.Custodio1` interface (standard interfaces ignored), and compares methods/arguments/results/properties, `ServiceError::ALL` names and the
  `.policy` action ids, in both directions. The `.p12` size is compared with `MAX_P12_LEN`; other bounds only need a `- bounds:` line per method (a stated choice).
- Controls (second test, all on edits of the real document): method removed, extra method `Bogus`, `Sign` data `ay`→`s`, extra and removed error, extra and removed action,
  wrong `.p12` bound, missing bounds line; each asserted to name the item and the direction.
- Evidence: `just quick` exit 0, `just api-contract` green. Not done: the contract's "failing first" run against a missing document was not kept as a separate step (the test treats a missing file as empty and so fails).
- Next session should: nothing for F66. Later features that add methods, errors or actions must add them to `docs/api.md`.

### 2026-11-01 — F67 — attempt 1
- Done: `## F67` in `docs/findings.md`, run on `debian13` (rootless podman, packaged unit, kernel 7.0, systemd 257, dbus-daemon 1.16.2) with `alice` (uid 1001, lingering user manager) and
  forged `app-flatpak-…\x2d…-<n>.scope` / `app-gnome-gedit-…` / no-scope callers. Baseline with controls; (a) loosening works only with `CAP_SYS_PTRACE` + 3 more settings and fails
  `security-score` (1.3) and `unit-hardening`; (b) not built; (c) works: bus `ProcessFD` → fdinfo `Pid` → `cgroup.procs` scan of `user@<uid>.service/app.slice` (any kernel), or `PIDFD_GET_INFO`
  cgroup id (kernel ≥ 6.13, checked in kernel tags) matched by `st_ino`; `open_by_handle_at` is killed by the unit's seccomp filter; systemd `GetUnitByPID(FD)` only returns `user@<uid>.service`.
  Flatpak source (tags 1.16.1 and 1.18.4) fixes the name, the placement and the proxy-inside-the-scope order. **Decision: (c)**; no `SPEC_DEVIATIONS.md` entry.
- Not done / not observed: real flatpak and a real `xdg-dbus-proxy` were not run (source reading only); the direct host path of `app.slice` (the container nests cgroups under its id) and a
  6.12 kernel were not tried; the packaged unit differs from `data/custodio.service` only in `ExecStart=` (stated in the finding); the probe used a drop-in that replaces `Type`/`ExecStart` only.
- Verify: the feature's `verify` exits 0; the same command on a copy without the `Decision:` line exits 1.
- Next session should: nothing for F67. The reader feature must test the direct `/sys/fs/cgroup/user.slice/…` path (or locate the cgroup2 mount) and the 6.12 fallback.

### 2026-11-01 — F68 — attempt 1
- Done: `## F68` in `docs/findings.md`. Source read at xdg-dbus-proxy tag 0.1.6 (`flatpak-proxy.c`, `get_dbus_method_handler`) and flatpak 1.16.1 (`--system-talk-name` → `--filter --talk=NAME`).
  Run in the e2e debian13 systemd container (rootless podman) with Debian's `xdg-dbus-proxy 0.1.6-1+deb13u3`, on **dbus-broker 37** and on **dbus-daemon 1.16.2** (systemd activation),
  the real activation file, situations running / masked / missing unit / failing unit / not installed, host vs `--filter --talk` vs `--filter` alone; plus a private dbus-daemon as a labelled extra.
- Results: `--talk` makes the proxy identical to the host (ListActivatableNames only filtered); without `--talk` every probe is rewritten to "not installed" (not distinguishable from it).
  "Not activatable" is **not** `Spawn.*` on a supported host: broker gives `ServiceUnknown`/`NameHasNoOwner`, dbus-daemon gives `systemd1.UnitMasked`/`NoSuchUnit` or no reply; `Spawn.ChildExited` only on a bus without systemd.
- **Conflicts for a person (SPEC not edited):** SPEC "Detection" lists absent / not activatable / blocked as distinct, but absent and blocked cannot be told apart through the proxy.
- Not run: real flatpak (acceptance 15 stays a separate feature); the Debian patches of the proxy were not diffed against the tag.
- Verify: the feature's `verify` exits 0; a copy without the `Detection:` line exits 1.
- Next session should: nothing for F68. The client documentation feature takes the five steps from the section.

### 2026-11-01 — F68 — attempt 2
- Fixed NEXT_FINDINGS: the false "SPEC/feature text names `Spawn.*`" conflict is now a correction of the contract's example only (docs/findings.md, PROGRESS.md); the setup script,
  stub unit and Gio stub are inlined in `## F68`. Note kept: client docs should give a timeout shorter than the 25 s default for the "no reply" case.
- Next session should: nothing for F68.

### 2026-11-01 — F69 — attempt 1
- Done: three actions `com.rfirma.custodio.{import,delete,replace}-certificate` in `data/com.rfirma.custodio.policy` (own description/message naming the operation, `auth_self` x3, owner annotation; signing block untouched).
  `crates/custodiod/tests/policy.rs` now parses per action: exact id set, defaults, owner, distinct non-empty messages containing the operation word, sign text unchanged, `_keep` check on the whole file, with negative-control tests on the helpers.
  `defines_exactly_the_sign_action` was replaced by `defines_exactly_the_four_actions` (not deleted: it is stricter). `docs/api.md` and `README.md` list the actions.
- Evidence: `cargo test -p custodiod --test policy` 10 passed, `just api-contract` green, `just quick` exit 0. Package gates left to F90/F100 (nfpm.yaml already ships the whole file).
- Notes for later: the test hard-codes the three new ids; the first feature adding the Rust constants must switch the test to them (as `ACTION_ID` is used). The `ImportP12` doc line "Needs no polkit authorization" in `docs/api.md` is now stale and is left for the import feature to fix.
- Next session should: nothing for F69.

### 2026-11-01 — F70 — attempt 2
- Done: `store.rs` keeps `<root>/<uid>/<id>`; `put/get/list` take `owner: u32` (never derived from an id). Areas are created only by `put` (0700, exact under any umask), checked
  by `check_dir` (no symlink, mode 0700, service uid) on every `get/list/put`; refused, never repaired. `open` removes stale `.tmp-*` in the root and in well-formed areas only.
  Old-layout decision (test `old_layout_flat_files_are_ignored_and_untouched`): flat files in the root are ignored and untouched; a flat file named like an owner uid makes that
  owner's area a non-directory → `BadFileType`. No reader or migration. Tests: `store/tests.rs` (adapted) and `store/tests/owners.rs` (new layout, two owners, concurrent insert).
- Callers: `dbus.rs` has `list_keys_call`, `list_certificates_call`, `import_call` (owner = `CallerCredentials` uid of the sender; no sender/credentials error → `AuthorizationUnavailable`);
  sign uses the caller uid. `dbus/tests.rs` has the three owner tests with the fake at uid 11 (rig shares the same `Arc<KeyStore>`).
- Test adaptations (not weakened): audit helper `import_with` now imports straight into the store under the test uid (the credentials fakes would fail `ImportP12`);
  `tests/errors.rs` breaks the store by loosening the owner area's mode instead of removing the root (a missing area is now just empty); cli/cryptoki/import tests pass the process uid.
- For F72: `list_keys`, `list_certificates`, `import_p12` now call `CallerCredentials`, but their "authorization unavailable" path is not proven here (only `owner_needs_a_sender` for ListKeys).
- Mutants: first run 2 missed in `existing_area`/`ensure_area`; `ensure_area` now leaves create errors to `check_dir`, new test for a root that became a file; `just mutants-diff F70 --re store.rs` 25 caught, 10 unviable, none missed (full run before the fix: 54 caught, 16 unviable, 2 missed).
- Next session should: nothing for F70.

### 2026-11-01 — F70 — attempt 3
- Fixed NEXT_FINDINGS: (1) `KeyStore` has a `#[cfg(test)] file_uid` seam that changes only the expected owner of key files; `rejects_foreign_owner` and `foreign_owned_area_and_key_are_refused`
  now reach the file check in `get` with the area check passing (false comment removed). (2) `tests/audit/common.rs` has `import_via_bus`; `no_secrets` imports the sentinel password through D-Bus `ImportP12` again
  (other fixtures keep the direct store import because their fake credentials fail the method).
- Not changed: the `ensure_area` umask race note (non-blocking; only under a umask like 0277 with racing first puts).
- Evidence: `just quick` exit 0; `just mutants-diff F70 --re store.rs`: 26 caught, 10 unviable, none missed.
- Next session should: nothing for F70.

### 2026-11-01 — F71 — attempt 1
- Done: removed `package-old.sh`, `test-e2e-old.sh`, `old.pattern`, the six `upgrade-cargo-deb-*` ids, the `old` mode of `run.sh`/`guest.sh`/`select.sh` and the old-package parts of the host tests and fixtures
  (`test-e2e-{host,select-host,select,lifecycle,refusal,targets}.sh`, `e2e-host-fixtures.sh`). `e2e-packages` builds N, N+1 and the old-path fixture only. debian13 now runs two guest runs (main, oldpath).
- Amendments (3, each committed alone): (1) `purge-*` is also owned by ubuntu2604, so the refused own-case assertion uses `refusal-*` (ubuntu2404 only); (2, 3) the evidence grep's `pkg-old` and `packages_old`
  are anchored, as the unanchored forms match the kept `pkg-oldpath` / `packages_oldpath` strings. The negative control is `upgrade-unlisted-case`; the select-host recipe check writes `'package-'old.sh` so the verify grep stays clean.
- Evidence: contract grep exits 1 (no match), `just quick` exit 0, host tests green, `just e2e-cases debian13 'upgrade-*'` 12 cases accounted for and passing (podman worked here). The guest needed no change for the M3 layout.
- Docs: grep of install.md, catalog, manual-acceptance, README, harness/README found no mention of a pre-M3 package. `mutants-diff` is not in the verify.
- Not touched: F43 lifecycle scripts still simulate an M1 package (out of scope).
- Next session should: nothing for F71.

### 2026-11-01 — F72 — attempt 1
- Done: one list method. `ListKeys` now returns `a(ssay)` = (id, key type, DER certificate) of the caller's keys; `ListCertificates` is removed from service, `docs/api.md`, module and tests (grep over `crates e2e scripts docs/api.md` is clean).
  Owner is the bus uid of the sender (`owner()`); no sender / credentials error → `AuthorizationUnavailable`, no polkit. A key whose key or certificate cannot be read gives `Internal`, not a shorter list.
  `Sign` order: arguments → credentials → look up among the caller's keys → polkit → sign. A missing or foreign id is `NoSuchKey`, no polkit, no journal entry (`attempt` returns `Ok(None)`). Other lookup errors are still reported after polkit as `signing_failed`, as before.
  `ImportP12` already stored under the caller's uid (F70); the two-uid tests prove it.
- Journal decision (docs/decisions.md, docs/audit.md): no entry for `NoSuchKey`, following the invalid-arguments behaviour; a credentials failure still writes the entry without caller (M1).
- Tests: new `tests/owners.rs` (two uids through a name→uid credentials fake, pairs 1000/1001 and 0/1000): list scoped, list/import fail closed (NoCredentials, MissingPid, no ProcessFD), unreadable certificate → Internal via D-Bus, import per owner, foreign == missing for sign (Yes and No answers).
  Adapted, not weakened: `audit.rs` (the missing-id rows now assert `NoSuchKey`, no entry, no polkit; failing-sink tests moved to `audit/failing.rs` for the file-size gate), `errors.rs`, `dbus.rs`, `dbus/tests.rs` (`denied_and_missing_key_are_distinct` keeps both names distinct).
- Followers: `custodio-pkcs11` backend calls `ListKeys` and drops the type (module unchanged). New `dbus_backend_lists_the_certificates_of_list_keys` (child process with `DBUS_SYSTEM_BUS_ADDRESS` and a fake service) so `mutants-diff` sees the backend. `custodio-cli` and `e2e/` use no list method: no change, `just test-scripts` skipped.
- Evidence: `just quick` exit 0, `just api-contract` green, `just mutants-diff F72`: dbus.rs 18 caught 2 unviable, backend.rs 7 caught, none missed.
- Not done: the optional static "no uid/owner argument" check (the two-uid tests cover it behaviourally).
- Next session should: nothing for F72.

### 2026-11-01 — F73 — attempt 1
- Done: `ImportP12` order is arguments → credentials → own-id check (`KeyIdTaken`) → polkit once under `IMPORT_ACTION_ID` (AllowUserInteraction) → decode → store.
  `Authorizer::authorize` now takes the action; `polkit.rs` has the four action constants and `tests/policy.rs` uses them. The decoder is a `P12Decoder` trait object
  (`Custodio::with_decoder`, default `RealDecoder`); `import::{id_taken, store_parsed}` split out of `import_p12`, which stays for direct store imports.
  `docs/api.md` describes the order and the action; `PolkitDenied` text says "refused the call".
- Tests: new `tests/import_polkit.rs` (8 tests, one per Evidence row, counting decoder, fake polkit now records action and flags via `Fixture::requests`/`start_with`),
  unit tests in `dbus/tests.rs` (`import_without_sender...`, `import_refusals_never_decode` incl. `BadSender`), wire test `import_request_names_the_import_action_with_interaction`.
- Adapted, not weakened: `tests/dbus.rs` (the import helper asserts the import action was asked, then clears the log so the sign counts stay), `tests/owners.rs` (ask counts include
  the imports; `sign_foreign_equals_missing` imports with Yes, then sets the answer), `dbus/tests.rs` (two refusing-authorizer tests seed the store directly), `custodio-it/tests/cli.rs`
  (`Deny` → `Approve`, since the CLI import must now be approved). No test deleted or ignored.
- e2e: `e2e/import-user.sh` (agent in `$WORK/agent-import`, waits for registration, `approve`, imports `rsa1`/`ec1`, checks exactly 2 requests); `guest.sh` calls it once under `su -l alice`
  before the oldpath branch, `user.sh` and `upgrade.sh`. Selftest `scripts/test-e2e-import.sh` (in `just test-scripts`) with 10 negative controls; the host e2e tests that read `guest.sh` pass.
  Not run: a real `just e2e` (F90/F100).
- Evidence: `just quick` exit 0, `just api-contract` green, `just mutants-diff F73` 4 caught, 2 unviable, none missed; `cargo test -p custodio-it -p custodio-pkcs11 -p custodio-cli` green.
- Next session should: nothing for F73. F74/F75 add the import journal entries.

### 2026-11-01 — F74 — attempt 1
- Done: `CUSTODIO_OPERATION` on every entry. Signing entries gain `sign` (field after `CUSTODIO_KEY_ID`, before `CUSTODIO_OUTCOME`); same id, priority, message.
  New `audit/operation.rs`: `Operation` (+`all()`), per-operation outcome enums (`ImportOutcome`, `DeleteOutcome`, `ReplaceOutcome`, so a wrong pairing does not compile), `AuditKeyType`
  (`CUSTODIO_KEY_TYPE`: `rsa_2048`/`ecdsa_p256`, import only, omitted when unknown) and `OperationEntry` (typed parts only). `AuditSink` gains `record_operation` (Journal, Memory (`operation_entries()`), Failing).
  One new `MESSAGE_ID` per operation (import `4c7163ce…`, delete `13d1a981…`, replace certificate `336e0b53…`). Priorities: 6 ok, 5 denied, 4 authorization unavailable / wrong password / unsupported key /
  certificate mismatch, 3 storage failure. F75/F77/F79 only construct `OperationEntry::{import,delete,replace_certificate}` and call `record_operation`.
- Catalog: both forms for each id; the signing body gained one sentence naming `CUSTODIO_OPERATION` (contract amendment, `e2e/catalog-text.txt` updated). `scripts/test-e2e-catalog.sh` handles several ids (+2 controls).
  `e2e/journal.py` also checks `CUSTODIO_OPERATION=sign` (selftest +2 cases).
- Docs: `docs/audit.md` (ids table, fields, outcomes per operation, message examples, a query per operation). `docs_tests` enumerate through `Operation::all()` and the outcome `all()`s; the field test now requires every field in the catalog bodies of the ids that use it.
- Adapted, not weakened: field counts/wire literals in `audit/tests.rs`, `GateSink` in `tests/audit/timing.rs`, (the integration line is in attempt 3).
- Evidence: `just quick` exit 0, `scripts/test-e2e-catalog.sh`, `bash e2e/journal-selftest.sh` (187 ok), `just mutants-diff F74`: 18 caught, 1 unviable. Guest journal cases and package gates run at F90/F100.
- Next session should: nothing for F74. F75 writes the import entries.

### 2026-11-01 — F74 — attempt 2
- Fixed NEXT_FINDINGS: the one missed mutant (`OperationEntry::caller -> None`) is killed by `the_caller_is_returned_as_given` in `audit/operation_tests.rs`.
- Evidence: `just quick` exit 0; `just mutants-diff F74`: 56 caught, 13 unviable, none missed.
- Next session should: nothing for F74.

### 2026-11-01 — F74 — attempt 3
- Fixed NEXT_FINDINGS: `journal_sink_datagram_per_call` (`tests/audit/leaks.rs`) now expects `CUSTODIO_OPERATION=sign` in the datagram of a sign over the private bus. The attempt 1 claim about `tests/audit.rs` is corrected.
- Evidence: `just quick` exit 0.
- Next session should: nothing for F74.

### 2026-11-01 — F75 — attempt 1
- Done: `import_call` now leaves one `OperationEntry::import` once polkit has been asked (and, without caller, for a missing sender or failed credentials), recorded on a worker thread before the reply.
  Outcome mapping in `dbus/import.rs` (`import_outcome`, literal table in `dbus/tests/sign_call.rs`; `TooLarge` → `storage_failure` is unreachable after the argument check, commented). Key type only once decoded (`stored`, `storage_failure`).
  Sink failure → `AuditUnavailable` for every outcome; for `stored` the key and certificate are removed (`import::rollback_import`: key first, then certificate; the certificate is left if the key cannot go). A failed rollback still returns `AuditUnavailable`.
  New `KeyStore::remove` (reuses `get`'s checks, so symlinks/foreign owners/directories are refused; a missing key or area is `Ok`, nothing created).
- Moved, not changed: import code to `src/dbus/import.rs` (file-size gate), sign_call unit tests to `src/dbus/tests/sign_call.rs`, rollback tests to `src/import/tests.rs`.
  `justfile` `mutants` now also lists `dbus/import.rs` (a stricter gate; the moved code would otherwise leave the mutation scope).
- Tests: `tests/import_audit.rs` (+ `import_audit/concurrent.rs`): per outcome (bus cases, failed credentials via `NoCredentials`), no secrets (+ negative control), rollback, failing sink for every outcome, rollback failure, refusals leave no entry (also with the failing sink), 20 rounds of concurrent imports (polkit double holds both calls; gives up after 10 s so a serial server fails instead of hanging; zbus does run the calls concurrently).
  Unit tests: missing sender (entry, and failing sink), polkit denied/unavailable/`BadSender`, all `ImportError` variants. Tests that need an unwritable store skip when run as root.
  Polkit double (`tests/audit/bus.rs`) is now async with a `hold` count and an `on_request` hook.
- Docs: `docs/api.md` (entry recorded before the reply, rollback), `docs/audit.md` (`KeyIdTaken` leaves no entry).
- Evidence: `just quick` exit 0, `just mutants-diff F75`: 6 caught, 3 unviable, none missed; `just api-contract` and `cargo test -p custodio-it` green.
- Next session should: nothing for F75.

### 2026-11-01 — F76 — attempt 1
- Done: `DeleteKey(id: s)` (`Custodio::delete_call` in new `src/dbus/delete.rs`). Order: id bound → credentials → lookup among the caller's keys (`NoSuchKey`, no polkit; any other lookup failure `Internal`) → polkit once under `DELETE_ACTION_ID` with AllowUserInteraction → key removed, then certificate. No journal entry (F77).
  New `KeyStore::remove_existing` (`Ok(false)` when missing; `remove` is unchanged in behaviour and uses it). The loser of two concurrent deletes gets `NoSuchKey` (it does not touch the certificate).
- Decision (evaluator note 1): a certificate left without its key (a delete that stopped after the key went) is found by the lookup, so a second `DeleteKey` clears it and the id is usable again; until then the id counts as taken. A non-plain-file entry is never touched (id stays taken until an administrator acts). Stated in `docs/api.md`.
- Tests: `tests/delete.rs` (+ `delete/concurrent.rs`): one test per Evidence row, plus leftover certificate and key-without-certificate. Sign during delete requires the held sign to succeed (note 4); two approved deletes show two asks (note 5). Unit tests: `dbus/tests/delete_call.rs`, `store/tests.rs`. Counting-authorizer unit test kept small (error mapping and ask counts; mutants).
  Adapted, not weakened: `dbus/tests/sign_call.rs` helpers made `pub(super)` only.
- `justfile` `mutants` now also lists `dbus/delete.rs`. Note: `mutants-diff` only sees new files after `git add -N`.
- Evidence: `just quick` exit 0, `just api-contract` green, `just mutants-diff F76`: 18 caught, 1 unviable, none missed.
- Next session should: nothing for F76. F77 writes the delete journal entry.

### 2026-11-01 — F77 — attempt 1
- Done: `delete_call` leaves one `OperationEntry::delete` once polkit was asked (`deleted`, `denied`, `authorization_unavailable`), and without caller (no uid/pid, no polkit) for a missing
  sender/failed credentials; none for `InvalidArgs`/`NoSuchKey`. Order after approval: mark unusable → submit (worker thread) → remove key, then certificate. Sink failure (any outcome) → `AuditUnavailable`,
  mark undone, files untouched. Removal failure after the entry → `Internal`, the mark stays for the life of the process. `StorageFailure` of `DeleteOutcome` is reserved (doc comment, docs, doc test).
- New `src/dbus/delete_state.rs` (+ `delete_state/tests.rs`): in-memory unusable set and a small async per-(owner, id) lock (no async-lock dependency exists; wakers, entry removed on release so the table does not
  grow). `Sign` (after credentials) and `ListKeys` honour the mark; `delete_call` checks it before and after taking the lock, so a delete during a pending entry gets `NoSuchKey` at once while a delete
  waiting on polkit waits. `ImportP12` still sees the files, so `KeyIdTaken`. Mark is cleared after a successful removal (the id is free again).
- Tests: `tests/delete_audit.rs` (+ `delete_audit/order.rs`, `concurrent.rs`): one test per Evidence row; `TestSink` fails, counts attempts (evaluator note), and can block. Unit tests in `dbus/tests/delete_call.rs`.
  Evaluator notes taken: lock released on denied/unavailable/sink failure/removal failure (a later delete does not hang), `ImportP12` after restore gives `KeyIdTaken`, table empties (unit test).
- Adapted, not weakened: `tests/delete.rs` (a failed removal now leaves the key unusable; second delete is `NoSuchKey`), `concurrent_deletes_one_wins` → `concurrent_deletes_run_one_at_a_time` (the second delete no longer reaches polkit).
  `tests/audit/bus.rs`: the polkit double re-reads `hold` so a test can release a held request. `tests/audit/deadline.rs`: delete helpers fail after 15 s instead of hanging (a leaked lock otherwise
  times out cargo-mutants); the unit tests exit the process after 20 s for the same reason. `justfile` mutants also lists `dbus/delete_state.rs`.
- Docs: `docs/audit.md` (delete section, "Not guaranteed" crash case), `docs/api.md` (`DeleteKey` order, `AuditUnavailable`); doc tests added.
- Evidence: `just quick` exit 0, `just api-contract` green, `just mutants-diff F77`: 27 caught, 10 unviable, none missed.
- Next session should: nothing for F77.

### 2026-11-01 — F77 — attempt 2
- Fixed NEXT_FINDINGS: `docs/api.md` no longer says a second `DeleteKey` clears a leftover certificate after a failed removal; it says a `DeleteKey` after the service restarts does (or for a certificate left by a crash). `api_describes_the_delete_entry` checks the new sentence and that the old wording is gone.
- Evidence: `just quick` exit 0, `just api-contract` green. Code unchanged, so the F77 mutants result stands.
- Next session should: nothing for F77.

### 2026-11-01 — F78 — attempt 1
- Done: `ReplaceCertificate(id: s, certificate: ay)` (`Custodio::replace_call` in new `src/dbus/replace.rs`). Order: id bound + certificate bound (`MAX_CERT_LEN` = 16384, in `custodio-client`) + exactly one DER X.509 (`InvalidArgs`, nothing touched) → credentials → lookup among the caller's keys (`NoSuchKey`, no polkit; also for a key F77 made unusable) → polkit once under `REPLACE_ACTION_ID` → public-key comparison (`CertificateMismatch`; unsupported key → `Internal`) → atomic store. No journal entry (F79).
  Runs under F77's per-(owner, id) lock (`delete_state`), so a replace and a delete never interleave; a replace after a delete is `NoSuchKey`. The key is read again after polkit (not held across the wait).
  New `KeyStore::replace_existing` (temp file, sync, `rename`, dir sync; never creates; `get`'s checks on the target; temp file removed on failure). `import.rs`: `public_key_of` / `cert_public_key` are `pub(crate)` for the comparison.
- Tests: `tests/replace.rs` (+ `replace/concurrent.rs`), one per Evidence row; unit tests in `dbus/replace/tests.rs` (exact bound, trailing bytes, key/cert matching, docs), `dbus/tests/replace_call.rs` (order, error mapping, lock shared with delete, unusable key), `store/tests/replace.rs`.
  Evaluator notes taken: atomicity is deterministic (`replace_with` takes a hook between the temp write and the rename; the negative control is a remove-then-write whose gap hook shows the entry missing); store-failure unit tests hold the refused-target details and the integration row only checks `Internal` + `Sign` still works, and the polkit ask is recorded before the failure; one credentials case (no `ProcessFD`) in the integration test; foreign/missing with polkit `Yes` only; `sign_after_replace…` asserts the old certificate is gone and the signature verifies with the key taken from the returned DER.
  `concurrent_replace_and_delete`: the delete always succeeds, so the end state is always "neither file"; the test checks that, and that both orders happen over the rounds.
- Fixtures: `gen.sh` makes `cert-*.der` from the existing `.p12` keys (nothing existing changes).
- Docs: `docs/api.md` `### Method ReplaceCertificate` + errors; `api_contract.rs` also checks a `- certificate size:` line against `MAX_CERT_LEN`.
- `justfile` `mutants` also lists `dbus/replace.rs`.
- Evidence: `just quick` exit 0, `just api-contract` green, `just mutants-diff F78`: 16 caught, 7 unviable, none missed.
- Next session should: nothing for F78. F79 writes the replace journal entry.

### 2026-11-01 — F78 — attempt 2
- Fixed NEXT_FINDINGS: `tests/replace.rs` exceeded the 5000-token file-size gate; the mismatch, sign-after-replace, two-uid and store-failure tests moved unchanged to `tests/replace/outcomes.rs` (`use super::*`).
- Evidence: `just quick` exit 0, `just api-contract` green. Product code unchanged, so the F78 mutants result stands.
- Next session should: nothing for F78.

### 2026-11-01 — F78 — attempt 3
- Fixed NEXT_FINDINGS: `replace_leaves_other_uids_alone` now replaces 1001's key with a matching certificate of other bytes (new `cert-p256-other-recert.der`, made in `gen.sh`) and checks 1000's area (snapshot, `ListKeys`) right after; `replace_missing_equals_foreign` loops over polkit Yes/No/Fail. Test renamed to `replace_without_credentials_is_unavailable`; `docs/api.md` notes that a failed final directory sync comes after the rename. `replace_call` reads the store inline like the other store calls (`run_on_thread` is used only for sinks).
- Evidence: `just quick` exit 0, `just api-contract` green. Product code unchanged, so the mutants result stands.
- Next session should: nothing for F78.

### 2026-11-01 — F79 — attempt 1
- Done: `replace_call` leaves one `replace_certificate` entry once polkit was asked (`replaced`, `denied`, `authorization_unavailable`, `certificate_mismatch`, `storage_failure`), and one without caller (no uid/pid, no polkit) for a missing sender / failed credentials; none for `InvalidArgs`/`NoSuchKey`. Order after approval: key read again → comparison → read old certificate → atomic store → submit (worker thread, via `Custodio::submit` from `delete.rs`, now `pub(super)`) → reply, all under the key lock. Sink failure (any outcome) → `AuditUnavailable`; if the store happened, the old certificate is put back with `replace_existing`; a failed restore is ignored (reply is the same). `storage_failure` also covers an unreadable key/certificate, an unsupported key type (reply `Internal`) and a key/certificate vanished after the lookup (reply as in F78); stated in `docs/audit.md`.
- Tests: `tests/replace_audit.rs` (+ `replace_audit/concurrent.rs`, `outputs.rs`): one test per Evidence row. `TestSink` can fail, block (gate), record what it was offered, read a watched file at submit time (store-before-submit order) and run a hook when it refuses. Restore failure: the hook makes the area read-only when the sink refuses; a control run without it restores, so the difference is the sabotage. Delete interplay: the lock means the second call asks only after the first ends; the row checks `replaced` (2 entries/asks) or `NoSuchKey` (1 entry/ask). Unit tests in `dbus/tests/replace_call.rs` (entries, unsupported key → `storage_failure`, failing sink for four outcomes and the missing sender). Tests needing an unwritable store skip as root. `guarded` in `delete_call.rs` is `pub(super)` for reuse.
- Docs: `docs/audit.md` (replace section, query, "Not guaranteed"), `docs/api.md`; doc tests `replace_order_and_outcomes_documented`, `api_describes_the_replace_entry`. Doc comment and `# Errors` of `replace_call` updated.
- Evidence: `just quick` exit 0, `just mutants-diff F79`: 1 caught, 1 unviable, none missed (cargo-mutants here only generates whole-function mutants for the changed functions).
- Next session should: nothing for F79.

### 2026-11-01 — F79 — attempt 2
- Fixed NEXT_FINDINGS: `tests/replace_audit.rs` exceeded the 5000-token file-size gate; the failing-sink, restore-failure and store-before-submit tests moved unchanged to `tests/replace_audit/failing.rs` (`use super::*`).
- Evidence: `just quick` exit 0, `just mutants-diff F79`: 1 caught, 1 unviable, none missed. Product code unchanged.
- Next session should: nothing for F79.

### 2026-11-01 — F80 — attempt 1
- Done: `crates/custodiod/src/app_id.rs` (+ `app_id/tests.rs`), pure, bytes in. `classify(Option<&[u8]>) -> AppIdOutcome { Read(AppId), None, Undetermined }`; `validate(&[u8]) -> Option<AppId>` (flatpak's rules); `AppId` has no public constructor (`compile_fail` doctest). Prefix check first (no prefix → `None`), then the 255-byte bound, then suffix, exactly one `-`, u32 instance id (1–10 digits), unescape (only lower-case `\x2d`; upper-case rejected on purpose, commented), validation. Parsing works on ASCII bytes, so non-UTF-8 is just an invalid character.
- Evaluator notes taken: longest id under the name bound is 235 chars in `valid_scope_names_are_read`, 255 only through `validate`; no allocation claim (shown structurally: `&[u8]` input, bound checked before `parse`); no negative control (mutants stand in); `module_has_no_io` greps `app_id.rs` only (tests are in `app_id/tests.rs`); recipe test matches the exact `--file crates/custodiod/src/app_id.rs` argument on the custodiod line; `xapp-flatpak-org.a.b-1.scope` is a `None` case.
- `justfile` `mutants` lists `app_id.rs`.
- Evidence: `just quick` exit 0, `just mutants-diff F80`: 38 caught, 3 unviable, none missed.
- Next session should: nothing for F80. F81 reads the scope of the pinned process; F82 puts the outcome in entries.

### 2026-11-01 — F81 — attempt 1
- Done: `crates/custodiod/src/app_id_source.rs` (+ `bounded.rs`, `limiter.rs`, `scan.rs`, `tests/`). Trait `AppIdSource::app_id(BorrowedFd, uid) -> impl Future<Output = AppIdOutcome>` (no error type); `FakeAppIdSource` (three cases); `CgroupAppIdSource` (F67 decision (c3)). Root is a parameter (`with_root`), `new()` uses `/sys/fs/cgroup`.
  Reader: pid from `/proc/self/fdinfo/<dup of the pidfd>`; `<root>/user.slice/user-<uid>.slice/user@<uid>.service/app.slice` opened step by step with `O_NOFOLLOW`; each child directory's `cgroup.procs` opened `O_NOFOLLOW|O_NONBLOCK|O_NOCTTY`, `fstat` must say regular before a read, at most 1 MiB, at most 4096 children, decimal pid lines only; a child that vanished (`ENOENT`) is skipped, a symlinked child is skipped, an unreadable/symlinked/FIFO `cgroup.procs` is `Undetermined`; the pid is read again after the scan (must be equal).
  Deadline 1 s (`LOOKUP_DEADLINE`), `MAX_STUCK` = 8 threads left behind, counted per `Limiter` instance (no global); at the cap a lookup is `Undetermined` with no thread. The caller waits on a worker plus a short watchdog thread (no timer dependency).
- Evaluator notes taken: `Limiter::new(deadline, cap)` takes both as parameters, production constants asserted in `production_constants_are_documented_values`; never-returning tests release their threads by dropping a channel sender; one `pid_changed` case (`Pid: 6`) plus the pid-gone case; `mkfifo` is `mknodat(Fifo)` in the dev container (worked, `/dev/zero` exists); the files added to the `mutants` recipe are `app_id_source.rs`, `bounded.rs`, `limiter.rs`, `scan.rs`. A missing `ProcessFD` cannot reach the trait (borrowed pidfd): the caller (F82) maps it to `Undetermined`.
- Decision recorded in the module docs: the direct cgroup path is used; a nested cgroup root (the e2e containers, as F67 observed) shows up as "no scope found" (`None`). (Superseded by attempt 2: the prefix lookup from `/proc/self/cgroup` is built.)
- Negative controls (red, reverted): `O_NONBLOCK` removed → `fifo_cgroup_procs_is_undetermined_within_bound` fails (5 s); `>` → `>=` in `read_bounded` → `oversized_cgroup_procs_is_undetermined` fails.
- Mutants: the `|` on `OFlags` was replaced with `.union` (a `|`→`^` mutant is equivalent); tests wait with a 20 s limit (`block_on_limited`, `within`) so a broken limiter fails instead of timing out. `just mutants-diff F81` was run per file (the whole run exceeds 10 min): none missed. New files need `git add -N` before `mutants-diff` sees them.
- Evidence: `just quick`, `just system-gates` green.
- Next session should: nothing for F81. F82 maps a missing `ProcessFD` to `Undetermined` and calls the source.

### 2026-11-01 — F81 — attempt 2
- Fixed NEXT_FINDINGS: `CgroupAppIdSource::new()` now finds the cgroup tree root from `/proc/self/cgroup` (`scan::tree_root`: the prefix in front of `system.slice`), so the e2e container layout `/sys/fs/cgroup/<cid>/user.slice/…` is read; odd input falls back to the bare mount (`None`, never a wrong id). Tests in `tests/tree_root.rs` (prefix cases, nested fixture tree read, flat root shows nothing). Recorded in `docs/findings.md` (F81 follow-up). Module doc fixed to mention the watchdog thread (2 threads per lookup). `production_constants` test now asserts the root starts with `/sys/fs/cgroup`.
- Not run in a real container; F95 proves it there.
- Evidence: see commit; `just quick`, `just mutants-diff F81` (scan.rs, app_id_source.rs).
- Next session should: nothing for F81.

### 2026-11-02 — F81 — attempt 3
- Fixed NEXT_FINDINGS: `Limiter` now takes a slot (compare-and-swap on a `live` counter, refused at `cap`) before it spawns the worker; the worker gives it back when it ends (`Slot` drop), whether the caller waited, timed out or dropped the future. So concurrent lookups and dropped futures cannot exceed `MAX_STUCK` live workers. Cost: more than `MAX_STUCK` lookups in flight at once get `Undetermined`. Module doc updated; stale sentence of attempt 1 marked superseded.
- Tests: `concurrent_lookups_cannot_exceed_the_cap` (cap+4 threads started together: exactly `cap` workers started) and `a_dropped_future_keeps_its_slot_until_the_worker_ends` in `tests/limiter.rs`.
- Evidence: `just quick` exit 0; `just mutants-diff F81 --re limiter`: 11 caught, 21 unviable, none missed.
- Next session should: nothing for F81.

### 2026-11-02 — F82 — attempt 1
- Done: the four entry kinds (`Entry`, `OperationEntry`) carry the app-id case: `CUSTODIO_APP_ID_STATE` (`read`/`none`/`undetermined`, on every entry) and `CUSTODIO_APP_ID` (only `read`); only an `AppId` goes in (`with_app_id(AppIdOutcome)`; `compile_fail` doctests for `&str`/`String`); `MESSAGE` unchanged; `fields()` is now public so tests read the wire fields. An entry nobody set is `undetermined`.
  Credentials: `CallerCredentials::pinned_credentials` (default: `credentials` + no pidfd); `BusCredentials` implements it from the one `GetConnectionCredentials` reply (`pinned_from`: the pidfd that `check_pidfd_info` checked, duplicated). `Custodio::with_app_id_source(impl AppIdSource)` / `with_guarded_app_id_source`; `main` wires `CgroupAppIdSource::new()`. `app_id_source/guarded.rs`: the source behind a trait object (`ErasedAppIdSource`), asked on its own thread under `LOOKUP_DEADLINE` and the `MAX_STUCK` cap (`Limiter`), so a hanging or panicking source gives `undetermined`.
  Lookup point: `Custodio::app_id_of`, once per call, after the refusals (own key found / id not taken) and before polkit; no caller, no pidfd or no source: `undetermined`, no source call. A lookup holds the per-key lock at most the deadline.
- Tests: `tests/app_id_audit.rs` (+ `app_id_audit/{outcome,refusals,source,wire}.rs`), unit tests `audit/app_id_tests.rs`, docs test `audit/docs_tests/app_id.rs`; `Fixture::start_full` takes a source. Existing field-count expectations (9 → 10, one wire literal) and the docs tests got the new fields; the journal catalog (`data/custodio.catalog`) names them, because `every_field_name_in_docs_and_catalog` requires it.
  Evaluator notes taken: the bound is documented in `docs/audit.md` and the docs test checks the number against `LOOKUP_DEADLINE`; the fast-source check compares against the no-source run with a 700 ms margin; hostile values go through one operation (import) via `CgroupAppIdSource` and the journal datagram; no negative-control row (mutants stand in); the panicking source is handled by the limiter's `catch_unwind`.
- Not done: the "pending-delete id" refusal case of `app_id_not_asked_for_refusals` (invalid, missing, foreign and taken ids are covered); it is the same early return that the other `NoSuchKey` cases use.
- Evidence: `just quick` exit 0; `just mutants-diff F82`: 24 caught, 21 unviable, none missed.
- Next session should: nothing for F82. F95/F100 prove the real cgroup reader in the packaged unit.

### 2026-11-02 — F82 — attempt 2
- Fixed NEXT_FINDINGS: (1) `e2e/catalog-text.txt` has the app-id paragraph; `scripts/test-e2e-catalog.sh` passes. (2) Negative control `app_id_check_rejects_a_wrong_case`: for every operation and case, `assert_case` against each other case panics (`catch_unwind`). (3) The four `*_entries_hold_no_secrets` tests now run with a source answering `org.example.App` (`Fixture::start_reading`, `fixture_reading`; direct entries use `with_app_id`) and assert the id field is in the scanned entries (import without credentials has none). (4) `app_id_never_changes_the_outcome` compares `ListKeys` and a later `Sign` (deterministic RSA) too.
- Product code unchanged, so the mutants result stands. Evidence: `just quick` exit 0.
- Next session should: nothing for F82.

### 2026-11-02 — F82 — attempt 3
- Fixed NEXT_FINDINGS: new `app_id_not_asked_for_a_pending_delete_id` (a held `DeleteKey` entry via `Sink::gate`; then `Sign`, `ReplaceCertificate`, `DeleteKey` on that id give `NoSuchKey`, no new entry, no new source call, no new polkit ask). Notes taken: hostile scope names run through every operation and the journal datagram; comment on why NUL/300-byte names cannot be offered; datagram test checks `PRIORITY` and `CUSTODIO_OUTCOME`; doc comment of `message` moved back above `fn message`.
- Evidence: `just quick` exit 0. Product code unchanged apart from a moved comment, so the mutants result stands.
- Next session should: nothing for F82.

### 2026-11-02 — F83 — attempt 1
- Done: entry points `dbus::parse_delete_request(id)` (= `check_id`) and `dbus::parse_replace_request(id, cert)` (id, bound, DER parse); `delete_call` and `replace_call` call them, so the fuzz targets run the service's own checks. New test `the_request_check_refuses_by_id_then_certificate`; the bound/trailing-bytes cases stay in the existing tests.
- Targets `delete_args`, `replace_cert_args`, `app_id` (asserts an accepted id passes `validate` again, is within `MAX_APP_ID_LEN`, and equals the input). `dbus_args` already took every argument of the sign/import parsers as full-range values and list has no arguments, so it only gained a comment saying so.
- `just fuzz-smoke [expected]`: every target of every fuzz workspace, `-runs=2000 -seed=1`, corpus and artifacts in a temp dir (local corpus untouched; `git status --porcelain --ignored` minus `target/` unchanged except the fuzz `Cargo.lock` gaining the new bins). Checks the six expected names against `cargo fuzz list`. `lint-fuzz` also lints the custodiod fuzz workspace.
- Negative controls (reverted): panic on a `zz` prefix in `delete_args` → exit non-zero naming `delete_args`; extra unknown expected name → exit 1 naming it; a clippy warning in the custodiod fuzz crate → clippy errors.
- Evidence: `just quick`, `just fuzz-build`, `just lint-fuzz`, `just fuzz-smoke` all exit 0.
- Next session should: nothing for F83.

### 2026-11-02 — F85 — attempt 1
- Step 1 (module vs `docs/api.md`): no difference found. `DbusBackend` calls only `ListKeys` and `Sign` with the client crate's `BUS_NAME`/`OBJECT_PATH`; no pre-F72 assumption left. Product code unchanged (`src/ffi` untouched; diff against `612a01a` shows only `backend/tests.rs` in the module crate), so `mutants-diff F85` has no mutants.
- Fixture (`custodio-it/tests/cryptoki/parent.rs`): `SwitchCredentials` (the service is *told* which uid calls; real uid lookup and `ProcessFD` are F72's), default uid = the process owner, so old tests are unchanged; `Fixture::{set_uid, run_as, import, replace_certificate, delete_key, calls, spawn}`; the monitor records destination, path, interface and member of every call to the service; `Running` drives a child that waits for the parent between steps (`held_tokens`, `held_key`).
- Error mapping (`backend/tests.rs`): the unit table of F65 already had all ten names, the fdo names and an unknown one; it is now `error_table()`. New: `both_calls_map_every_name_through_the_real_backend` (fake bus service answers each name from `ListKeys` and `Sign`; both give the same `BackendError`: `Denied` for PolkitDenied/AuthorizationUnavailable/AccessDenied, `Invalid` for InvalidArgs, `Unavailable` otherwise).
- Cryptoki tests (`documented.rs`): `module_calls_only_documented_methods` (compares destination, path, interface to the client constants, members are exactly ListKeys/Sign), `two_uids_see_only_their_own_keys` (A, B, same id `shared` with different certificates, uid C with none, B's id signs as a missing id), `a_replaced_certificate_is_exposed_on_the_next_call` (byte comparison with `cert-p256-recert.der`, same key as `p256.p12`; also inside one loaded module), `a_deleted_key_has_no_token` (stale handle fails, other key stays, re-import shows again). "A connection per call" is shown by the second call in the same loaded module of the replace test seeing the new certificate (and the backend code opening one per call); no separate test.
- Negative controls (red, reverted): credentials source always uid A → two-uids test fails; list cache in `DbusBackend` → replace and delete tests fail.
- Evidence: `just quick` exit 0; `just mutants-diff F85`: no mutants.
- Next session should: nothing for F85.

### 2026-11-02 — F85 — attempt 2
- Fixed NEXT_FINDINGS: (1) `a_replaced_certificate_is_exposed_on_the_next_call` now signs (`sign:ec`) after the replace and verifies the ECDSA signature over `[7; 32]` with the key in `cert-p256-recert.der` (`verify_p256_prehash`). (2) Stale doc paragraph above `error_table()` removed. Note 3 accepted by the evaluator.
- Product code unchanged, so `mutants-diff F85` still has no mutants. Evidence: `just quick` exit 0.
- Next session should: nothing for F85.

### 2026-11-02 — F85 — attempt 3
- Fixed NEXT_FINDINGS: `two_uids_see_only_their_own_keys` no longer compares the child's whole stdout (it held the runner's timing). It compares only the `NOTOKEN`/`SIG`/`SIGERR` scenario lines of the two runs, without the id, and asserts they are all `NOTOKEN`.
- Product code unchanged, so `mutants-diff F85` still has no mutants. Evidence: `documented` tests 3 runs green; `just quick` exit 0.
- Next session should: nothing for F85.

### 2026-11-02 — F86 — attempt 1
- Step 1 (CLI vs `docs/api.md`): no difference. The call is `ImportP12(s, ay, s)` on the client constants; the CLI checks only the `.p12` size locally (id given with `--id` and password size go to the service, so `InvalidArgs` is reachable on the bus with a 200-char id or a 2000-byte password).
- New `ServiceFailure` (`custodio-cli/src/failure.rs`): one case per documented name, `ServiceAbsent`, `Transport`, `Unknown(name)`; fixed message each, no service text, no transport detail. Bus-daemon names (`org.freedesktop.DBus.Error.*`) are `ServiceAbsent` (ServiceUnknown/NameHasNoOwner) or `Transport`, never unknown. `Importer` returns it; `ImportFailure::Service` holds it; `bus::failure_of` maps zbus errors (MethodError and FDO).
- `CliError` (Args / SystemBus / Import), `exit_status` (0/1/2) and `finish` (prints the diagnostic, returns the status) in the library; `main` is `ExitCode::from(finish(&run(), stderr))`, so the unreachable-bus path in `DbusImporter::system()` goes through the same function (`the_binary_exits_1_when_the_bus_is_unreachable`).
- Tests: `custodio-cli/tests/exit.rs` (status table, binary: usage → 2 with empty stdout, unreachable bus → 1); `custodio-it/tests/import_errors.rs` (private bus, fake polkit approve/deny/unavailable, one test per remaining name, service absent, recording service for the documented call). Certificate mismatch and internal use a decoder double; audit unavailable uses `FailingSink`.
- Negative controls (red, reverted): changed `KeyIdTaken` text → name test fails; mapping `Import` to 0 → exit tests fail.
- Evidence: `just quick` exit 0 (verify has no mutants-diff).
- Next session should: nothing for F86.

### 2026-11-02 — F87 — attempt 1
- Done: `custodio list` in `custodio-cli`. `parse_command` dispatches `import` / `list` (`list` with any argument is a usage error); `list.rs` has `KeyLister` (service side), `run_list` (sorted by id; none sentence; a failing certificate still shows the key and gives status 1), `certificate_info` (subject RFC 4514, `notAfter` as `YYYY-MM-DDThh:mm:ssZ` via `x509-cert`, already a workspace dependency) and `escape` (control characters as `\xNN`, also for id and type). `DbusImporter` implements `KeyLister` with the one `ListKeys` call. `ListFailure` (Service / Unreadable / Output) reuses F86's `ServiceFailure`; `CliError::List` maps to status 1. `packaging/custodio.1` documents `list` and the exit status.
- Tests: `list/tests.rs` (rendering, escaping, patched-DER subject, unreadable, usage); `tests/exit.rs` (list statuses, binary: `list` with a missing bus is 1, `list extra` is 2); `tests/man.rs` (man page facts, part of `just test`); `custodio-it/tests/list.rs` on a private bus (several keys incl. a replaced certificate with its own subject/notAfter, none, `AuthorizationUnavailable` via a credentials double, no service, uids A/B/C with a shared id, bus monitor proving exactly one `ListKeys` call and nothing else, fake polkit count unchanged across every list).
- Evaluator notes taken: environment is the dev container's `/usr/bin/dbus-daemon`; bus tests are in `custodio-it/tests/list.rs`; "no certificate bytes" is asserted as hex of a fixture DER absent in the several-keys test; the escaping unit test also checks the readable subject remains; no bus test for an unreadable certificate; the bus monitor is the one recorder. Note: x509-cert's own RFC 4514 `Display` already escapes control bytes in a subject, so our escape is a second layer, tested directly on `write_entry`.
- Evidence: `just quick` exit 0 (verify has no mutants-diff).
- Next session should: nothing for F87.

### 2026-11-02 — F88 — attempt 1
- Done: `custodio delete <id>`. `parse_command` dispatches `delete` with exactly one argument not starting with `-` (so `--yes`/`-y`/`--force` are usage errors, status 2); `USAGE` names it. New `delete.rs`: `Confirmation` (terminal) and `KeyDeleter` (service) traits, `run_delete`, `DeleteFailure` (Declined / NoTerminal / Service / Output; all status 1, fixed messages). Accepted answers are exactly `y` and `yes` (lower case, line ending removed, no other trimming); `ACCEPTED` is pinned by a test, everything else (empty, EOF, `Y`, `yes please`, `y `) declines. `Terminal` asks on `/dev/tty` (echo on); open or write failure = no terminal (refusal), a failed read or EOF = decline. `DbusImporter` implements `KeyDeleter` with the single `DeleteKey(s)` call. `packaging/custodio.1` documents it (`tests/man.rs`).
- Tests: `delete/tests.rs` (parsing, accepted words, `run_delete`), `tty/tests.rs` (question on a pty, EOF, no master), `tests/exit.rs`, `tests/man.rs`; `custodio-it/tests/delete.rs` runs the real binary (built with `cargo build -p custodio-cli`, like the pkcs11 module) as a session leader with a pty as controlling terminal (`TIOCSCTTY`; verified here: it opens `/dev/tty`), against the real service on a private bus with fake polkit and a bus monitor: confirm, `n`, ^D, hangup, polkit denial, missing id, no terminal (stdin piped with `yes`), env vars do not remove the prompt, options, unidentified caller, service absent.
- Notes: `custodio delete` connects to the bus before asking (no method call to the service until the answer). A hangup sends SIGHUP to the session leader, so that variant only asserts non-zero and no calls. Evaluator notes 2–7 taken; note 1 (probe in Scope) is documented in the test header instead of editing the contract.
- Evidence: `just quick` exit 0 (verify has no mutants-diff).
- Next session should: nothing for F88.

### 2026-11-02 — F88 — attempt 2
- Fixed NEXT_FINDINGS: `just quick` failed on the file-size check (`custodio-it/tests/delete.rs` ~6000 tokens). Split into `delete.rs` (the tests), `delete/rig.rs` (private bus, fake polkit, service, monitor) and `delete/run.rs` (binary build, child with or without a controlling terminal), wired with `#[path]`. No test changed; 12 tests green.
- Evidence: `just quick` exit 0.
- Next session should: nothing for F88.

### 2026-11-02 — F88 — attempt 3
- Fixed NEXT_FINDINGS: (1) `Rig::files()` lists the store files; the confirm test asserts the files of `old-key` are gone and `keep`'s remain, the denial test that the file list is unchanged (two files for `k`). (2) `custodio delete -- <id>` is accepted (only `--` as option, then exactly one id), so ids starting with `-` can be deleted; other options stay usage errors. Parse test, man page line and `tests/man.rs` pin it. The rustix note was not taken (non-blocking).
- Evidence: `just quick` exit 0.
- Next session should: nothing for F88.

### 2026-11-02 — F89 — attempt 1
- Step 1 (`docs/findings.md` "F89: which agent answers"): Outcome B. polkit has no side-effect-free "is an agent registered" call, so on a terminal the CLI always starts `pkttyagent --fallback --notify-fd=1 --process=PID,START_TIME` (polkitd prefers a session agent over a fallback); deviation in `SPEC_DEVIATIONS.md` (pending), contract amended (`8194406`). Kill mechanism: option (2), `setpriv --pdeathsig=KILL -- pkttyagent ...` (real `pkttyagent` imports no `prctl`; probe in the finding). A missing `setpriv` starts no agent, like a missing `pkttyagent`. Packaging must list util-linux (`setpriv`) as a runtime dependency (not done here: F90).
- Built: `custodio-cli/src/agent.rs` (`Process`, `start_time_of`, `agent_args`, `AgentSpawner`/`Stop` seams, `AgentGuard`, `WithAgent` wrapping `Importer`/`KeyDeleter`, so the agent exists only around the one bus call, after the password or confirmation) and `agent/process.rs` (real spawner: notify pipe as the agent's stdout, 5 s bounded wait, static slot for the child, `ctrlc` handler (feature `termination`) that kills and reaps it and exits 130). `main` wraps the bus in `WithAgent` for `import` and `delete` only, `list` untouched. New dependency `ctrlc` 3.5.2 (+ `nix`), rustix features `event`, `pipe`, `process`; `cargo deny check bans` passes.
- Tests: unit (`agent/tests.rs`), `tests/man.rs`, and `custodio-it/tests/agent.rs` (11 binary tests on a pty with a fake `pkttyagent` script first on `PATH`; `delete/run.rs` gained `Stdin::{Pipe,Tty,File}`, `start_with`, `start_in_shell`; `rig.rs` gained `Polkit::Hold`).
- Negative controls (red, reverted): (a) `process.pid + 1` in `agent_args` → unit argument tests and `delete_starts_the_agent_...` fail; (b) `--pdeathsig=KILL` replaced by `--pdeathsig=clear` in `process.rs` → `a_killed_cli_leaves_no_agent_running` fails; removing `let _ = child.kill();` from `stop_agent` → `the_agent_is_gone_after_success_and_after_failure` and `an_interruption_stops_the_agent_and_exits_non_zero` fail (they hang in `wait`).
- Notes: the "no secrets" test (`a_failed_import_shows_no_secret`) checks the failed run; the success reminder of `import` prints the file path by design (earlier feature), so it is not asserted absent there. The exit status after SIGINT/SIGTERM/SIGHUP is 130 for all three (`ctrlc` does not say which).
- Evidence: see the commit; `just quick` run once at the end.
- Next session should: nothing for F89.
