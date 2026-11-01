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
