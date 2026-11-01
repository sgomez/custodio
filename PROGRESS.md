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
- **Conflicts for a person (SPEC not edited):** the feature text expects `Spawn.*`; SPEC "Detection" lists absent / not activatable / blocked as distinct, but absent and blocked cannot be told apart through the proxy.
- Not run: real flatpak (acceptance 15 stays a separate feature); the Debian patches of the proxy were not diffed against the tag.
- Verify: the feature's `verify` exits 0; a copy without the `Detection:` line exits 1.
- Next session should: nothing for F68. The client documentation feature takes the five steps from the section.
