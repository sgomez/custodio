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
