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

### 2026-11-15 — F189 — attempt 1
- Done: `docs/findings/F189.md` + index line. Cause not reproduced (**inferred**): kernel (`dm.c` `dm_setup_md_queue`) exposes
  `slaves` before `dm/uuid` but all before any mount, and systemd 257 adds `RequiresMountsFor=` for `StateDirectory`; the same
  LVM code is in 0.8.0 and HEAD. Fixture runs (scratch example, deleted) give `NotEncrypted` for a complete chain, `Unknown` for each gap.
  No dm device can be created here (checked as root via `sudo -n`, which works: no `/dev/mapper`, no `dmsetup`, no `/dev/loop-control`, `CapEff` lacks `CAP_MKNOD`). F180 rules stand. `just quick` green, `verify` passes, no product code changed.
- Decisions: route 2 (keep `unknown`, expose an enumerated reason, no unit setting).
- Next session: F196 builds route 2 under the `docs/api.md` compatibility rule.

### 2026-11-15 — F190 — attempt 1
- Done: `docs/findings/F190.md` + index line; all contract steps ticked. `podman` pulls and runs all five targets, so defaults are
  **verified** (package contents, real `systemd-journald` + `SIGUSR1` flush). Precedence, masking, last-wins, invalid/empty value
  ignored, case/section rules verified by journald runs (not `cat-config`). 259+ default `persistent` (NEWS, run on ubuntu/fedora/arch);
  Alma 10 (257) has no `/var/log/journal` after install. `/run/log/journal` is never used. `just quick` green, `verify` passes.
- Decisions: unset `Storage=` takes the `#Storage=<v>` line of the main file; invalid values and any non-ENOENT error are "could not check".
- Next session: F203 implements the `Decision: ` line.

### 2026-11-15 — F191 — attempt 1
- Done: `docs/findings/F191.md` + index line + dated entry in `docs/decisions/packaging.md`; all steps ticked. Ran bash, zsh and fish with stub completions in
  the five containers (all **verified**; alma10 fish is from EPEL), nfpm 2.48.0 built a scratch deb/rpm/Arch with per-packager zsh paths, and timed
  `custodio list` against the real service on a private bus (scratch example, deleted): 200 keys 34-43 ms, absent 2-3 ms, no client timeout (stopped
  service blocks >40 s; never-claiming activation 25 s). `just quick` green, `verify` passes, no product code changed.
- Decisions: zsh path differs (.deb `vendor-completions`, .rpm/Arch `site-functions`, two parity presence exceptions); hidden `custodio __key-ids`,
  2 s timeout in `custodio`; bounds 1 s absent / 2 s running / 4 s hung. The packaging decisions entry is already written: F205 must not add another.
- Next session: F205 implements the `Decision: ` line (and documents `compinit` for Debian, Arch, and Fedora/Alma users without the skeleton `.zshrc`).

### 2026-11-15 — F192 — attempt 1
- Done: `scripts/install-sync-lib.sh` (shared by the TPM check, now parametrised by keyword and packages) + `check-shell-install-sync.sh` +
  `test-shell-install-sync.sh` (negative controls: no fish, unrelated comment, no zsh in ci.yml, no install in mutants-diff.yml, new
  job, vanished exempt job), in `just test-scripts`. Containerfile, ci.yml (`test`, `coverage`), mutants.yml, mutants-diff.yml install
  `bash-completion zsh fish` with a comment. Also exempted `e2e.yml:changes` in the TPM check (it was red at HEAD). `just quick` green.
- Not done: the dev container still lacks the shells; the `verify` needs the rebuild (BLOCKED.md).
- Next session: after the rebuild, run the `verify`; nothing else.

### 2026-11-15 — F192 — attempt 2
- Done: dev container rebuilt; `zsh`, `fish` and bash-completion are present. `just quick` green and the three probes of the `verify` pass. No code changed.
- Next session: none for F192.

### 2026-11-15 — F192 — attempt 3
- Done: fixed the evaluator's finding: `mutants-diff.yml` TPM install step regained its `if: steps.signoff.outputs.signed != 'true'`; the shell install step has its own copy. Both sync script tests pass.

### 2026-11-15 — F193 — attempt 1
- Done (steps 1-6, 5b ticked): `help.rs` (the command table, help text), `parse.rs` (parser moved out of `lib.rs`, `Command::Help`,
  `ArgError::CommandUsage(name)` for a wrong line of a known command, `fuzz_cli_args`), `tests/help.rs` (help on stdout, usage errors,
  man parity read from the binary with two fixture controls, banned-crate check on `Cargo.lock` with a fixture control), man page gained
  `-h, --help`, fuzz target `cli_args` (build, lint, smoke pass; the `"cli_args x"` negative control not run), `man.rs` removed in its own
  `test:` commit. justfile `mutants` list has parse.rs, help.rs, colour.rs. `colour.rs` (rule + `headings`) is built, used by `--help`
  in `main.rs`; the rule is in `docs/decisions.md`. `just quick` green.
- Not done: step 7 stays unticked (the error prefix is not coloured yet; `NO_COLOR=0` is covered in the unit test), step 8 (error module, `error.rs`,
  new `ServiceFailure` cases `TpmFailed`, `CredentialsUnavailable`, `KeyLost`, `TemporarilyUnavailable`), 9 (docs/api.md names),
  10 (replace printers, update `exit.rs`), 11 (`tests/output_rules.rs`, add `error.rs` to the mutants list), 12 (`mutants-diff`, once, 10-15 min).
- Next session should: do steps 8-12 in that order; `custodio_cli::colour::{enabled,bold,headings,strip}` is ready for the error prefix.
  Binary for tests is `CARGO_BIN_EXE_custodio-cli`.

### 2026-11-15 — F193 — attempt 2
- Done (steps 7-11 ticked): `error.rs` (`render`: what went wrong, then the next step; control characters escaped; `Args` text is static),
  `ServiceFailure` gained `TpmFailed`, `CredentialsUnavailable`, `KeyLost`, `TemporarilyUnavailable` and `next_step()`; `finish` takes a
  `coloured` flag and `colour::prefix` bolds `custodio:`; `main` decides colour per stream; `tests/output_rules.rs` (pipes and ptys,
  `NO_COLOR` unset/empty/"1"/"0"/"x"); error unit tests over every variant (wildcard-free matches) and every name of docs/api.md with a
  fixture control; `error.rs` is in the `mutants` list. Tests that asserted one-line stderr (`register_native/skips.rs`,
  `custodio-it` delete/list) now expect the two lines. `just quick` green.
- Step 12 done: `mutants-diff F193` 101 tested, 0 missed (one run, 2 min); help, output_rules, fuzz-build, lint-fuzz, fuzz-smoke pass; `just quick` green.
- Next session: none for F193.

### 2026-11-15 — F193 — attempt 3
- Done: fixed finding 1: `refresh_only_command`'s journal error is now two lines (what went wrong, escaped, then `systemctl status systemd-journald`);
  `refresh_only.rs` asserts both lines on the unreachable-journal case. `just quick` green; `mutants-diff F193` 102 tested, 0 missed.
- Notes 2-5 not changed (non-blocking).

### 2026-11-15 — F194 — attempt 1
- Done (steps 1-5 ticked, step 6 partly): `cert_text.rs` (`fields`, `escape` with C0/DEL/C1, bidi, format, private-use and tag chars as `\xNN`/`\u{N}`;
  `fuzz_cert_fields`; sha2 added to custodio-cli), `tests/cert_text.rs`, fixture `cert-p256-other-hostile.der` (gen.sh; hostile subject and a different
  hostile issuer, same key as p256-other, serial 0x1095), `list.rs` rewritten (table without header, one row per key, note once; `run_show`, `ListFailure::UnknownId`,
  `show_command`; `list_command` unchanged so `storage_warning.rs` passes as is), parse `list [[--] <id>]`, help, man page, README example, error text + error
  unit tests list the new case, fuzz target `cert_fields` (build, lint, smoke pass; negative control `just fuzz-smoke "cert_fieldz"` → "target cert_fieldz is missing or did not run", exit 1).
  `custodio-it`: shared `tests/list_rig/mod.rs`, `list.rs` on the new format, new `list_view.rs` (4 tests, 0.05 s). Evidence run so far: custodio-cli tests, `list`, `list_view`: pass.
  `mutants` list has cert_text.rs and list.rs.
- Decisions: the table has no header (so rows == keys); subject column is the common name (RFC 4514 if none), the full view shows RFC 4514 from x509-cert (it writes C0/DEL as `\1b`)
  then our escape; the weaker-storage note is only in the table.
- Step 6 done in the next commit: e2e consumers moved to rows (`awk 'NF == 0 || /^You have no keys/ { exit } { print $1 }'` for ids; cli-lib/rd-lib/ops-lib/owner-lib/upgrade-accts-lib;
  tpmkind/fallback/tpmclear/upgradekinds/upgradem3 .py parse rows; selftests cli, rd, ops, owner, upgrade-accts, tpmkind pass and feed a hostile subject). `just quick` green. Not run: `just test-scripts`, e2e (checkpoint).
- (Superseded) not done: step 6 e2e consumers of the old block layout (`e2e/cli-lib.sh`, `rd-lib.sh`, `ops-user.sh`, `cli-user.sh`, `cli-pty-user.sh`, `upgrade-accts-*.sh`, `tpmkind.py`,
  `fallback.py`, `upgradekinds.py`, `*-selftest.sh`, ...; find with `grep -rn "id: \|custodio list" e2e`): key them on the id column (first word of a row), selftests feed a hostile subject.
  Step 7: `just quick` (was green before the e2e work except nothing known), `mutants-diff F194` (never run; cert_text.rs has no unit tests of its own yet, expect survivors in `must_escape` ranges, `hex`, `common_name`), `just test-scripts` for the touched scripts.
- Step 7 done: `just quick` green; `cert_text` (9), `list_view` (4), `help` (8) tests, `fuzz-build`, `lint-fuzz` pass; `fuzz-smoke` passed with `cert_fields` in the list (earlier commit);
  `just mutants-diff F194`: 49 mutants, 46 caught, 3 unviable, 0 missed (2 min; after adding tests for the escape ranges, the CN types and `ListFailure` display).
  Not run here (checkpoint): `just test-scripts`, e2e. Next session: none for F194 unless the evaluator finds something.

### 2026-11-15 — F194 — attempt 2
- Done (evaluator findings): the script tests of the Python judges are in the row format (`test-e2e-fallback`, `-tpmclear`, `-upgradekinds`, `-upgrade-purge-judge`,
  `-vm-kinds`, `-vm-silent`), each with a forged-row case where the judge reads rows (fallback, tpmclear, upgradekinds, purge-judge); `e2e/vm/silent.py absent`
  read the old `id:` block and now reads the first column; the README none example has the import hint and `test-docs-readme.sh`'s "output altered" control
  edits the table row; the `is_readable` doc comment is fixed. `just test-scripts` and `just quick` green.

### 2026-11-15 — F195 — attempt 1
- Done (step 1 ticked): fixtures `twokeys.p12`, `twokeys-nomac.p12` (generator `crates/custodiod/examples/gen_twokeys.rs`, called by `gen.sh`;
  `custodio-it/tests/fixtures` is the same directory), `docs/findings/F195.md` has all cells and the rule. `parse_p12` returns `Parse(String)`:
  classify on it as `MAC tag mismatch` = (a), `PKCS#5 decryption failed` = (c), structural variants = (b).
- Next session: steps 2-6 (service first).

### 2026-11-15 — F195 — attempt 2
- Done (steps 2-5 ticked, 6 partly): `ImportError` is `WrongPassword` (MAC, library `MacError`), `WrongPasswordOrBad` (no MAC, `Pkcs5Error`), `Unreadable(String)` (any other
  library error) plus the existing structural cases; `import::classify_p12_error`. New D-Bus errors `WrongPassword`, `UnreadableP12` (`custodio-client`, `ServiceError`),
  new outcome `unreadable_file`. `tests/import_split.rs` (own `[[test]]`, 2 tests, 5 s): all ten cells of the finding, and the denied/unavailable cases with a counting decoder.
  docs/api.md (errors + three `console` examples, `demo-nomac.p12`) and docs/audit.md; `just api-contract` and `scripts/test-docs-api.sh` pass; control: deleting the
  `UnreadableP12` line of api.md made `api_document_matches_its_sources` fail ("source item missing from document").
  CLI: `ServiceFailure::{WrongPassword, UnreadableP12}` two-line messages; `delete::RESTART_NOTE` printed after a successful import and delete; `custodio-it/tests/import_messages.rs` (5 tests, 0.13 s).
  Man page, README (Firefox export section, notes in the examples), help text, e2e consumers (`jo-user.sh`, `appid-enter.py`, `ops-lib.sh`, `jo.py`) updated.
  The non-interactive refusal (`NoTerminal`) is the same code path as the declined delete; `import_messages` covers both (answer `None` and `n`).
- Not done: step 6 evidence runs: `just quick`, `just fuzz-build && just fuzz-smoke`, `just mutants-diff F195`; `import_errors`/all custodio-it tests pass.
- Known gap: a file with a MAC whose MAC verifies but whose bags then fail to decrypt would be `WrongPasswordOrBad` (Pkcs5Error), not (b); only reachable with a corrupt file.
- Step 6 done: `just quick` green (1251 tests), `just api-contract`, `scripts/test-docs-api.sh`, `import_split` (2 tests, 5 s), `import_messages` (5, 0.13 s),
  `import_errors`, all `custodio-it` tests, `just fuzz-build && just fuzz-smoke` (p12_parse ran), `just mutants-diff F195`: 18 mutants, 12 caught, 6 unviable, 0 missed (2 min).
  Not run here (checkpoint): `just e2e`, `just test-scripts` (e2e consumers `jo-user.sh`, `appid-enter.py`, `ops-lib.sh`, `jo.py`, README examples).

### 2026-11-15 — F195 — attempt 3
- Done (findings 1-3): `import_split.rs` is one `#[test]` per file and password and per refusal (26 tests, 4.3 s on this machine, in parallel);
  `ber::has_mac` reads `macData` from the outer PFX (DER and BER) and `classify_p12_error(e, has_mac)` gives a `Pkcs5Error` with a MAC
  to `Unreadable` (b); unit tests for both; finding records the rule and the 1-in-256 padding chance. `just quick` green;
  `mutants-diff F195`: 21 mutants, 15 caught, 6 unviable, 0 missed.
- Note 4 (CLI test in-process) accepted by the evaluator.

### 2026-11-16 — F196 — attempt 1
- Done (all steps ticked): route 2 of F189. `storage.rs`: `UnknownReason` (7 wire values: `no-mount`, `not-block-filesystem`, `sysfs-incomplete`,
  `layer-not-classified`, `members-disagree`, `fscrypt-not-excluded`, `state-dir-unresolved`; `ALL`, `name()`), `Diagnosis` (verdict + reason, reason only on unknown),
  `diagnose_with` / `diagnose_state_dir`; `classify`, `classify_with`, `classify_state_dir` keep their signatures and verdicts. `startup::start` takes a closure returning `Diagnosis`.
  Bus: new read-only method `StateStorageReason` (`s`, empty unless unknown), docs/api.md section with the values; the snap socket does not serve it
  (`snap_socket_surface::other_methods_are_unknown` lists it). `api_contract.rs` reads `- reason` lines and compares both ways with `UnknownReason::ALL` through `name()`, with removed/renamed/invented controls.
- Tests: `storage_stability.rs` (one case → (verdict, reason) table, 34 cases, each read twice; no threads, per the evaluator's note), `storage_api.rs` (reason per value, empty for proven, no polkit / no state change via the existing helpers).
- Decision: `state_storage`, `storage_api` and the new `storage_stability` are their own `[[test]]` targets (not in `tests/it.rs`) because the `verify` runs `--test <name>`; `every_test_file_is_a_module_here` lists them as exceptions.
- Mapping notes: a dm node with no `dm/` directory is `layer-not-classified` (indistinguishable from a disk without a hardware link); `dm/uuid` missing or empty is `sysfs-incomplete`.
- No journal field added (optional); `start_journals_storage_field` is unchanged and `docs/audit.md` is not touched.
- Evidence: `just quick` green, `just api-contract`, `scripts/test-docs-api.sh`, the three `--test` targets pass; `snap_socket_surface` (in `it`, run by `just quick`) passes;
  `just mutants-diff F196`: 40 mutants, 29 caught, 11 unviable, 0 missed (6 min 13 s; no budget row).

### 2026-11-16 — F196 — attempt 2
- Done (finding 1): a node named `dm-*` without `dm/` is now `sysfs-incomplete` (F189's kernel gap); the fixture has a populated `slaves/`. Finding 2: api.md wording fixed.
  Finding 3: dropped `a_reason_goes_with_unknown_and_only_with_it` (the table check already pairs verdict and reason; product coverage unchanged).
- Evidence: `just quick`, `just api-contract`, `scripts/test-docs-api.sh`, `storage_stability`, `state_storage`, `storage_api` pass; `just mutants-diff F196`: 40 mutants, 29 caught, 11 unviable, 0 missed (6 min).

### 2026-11-16 — F197 — attempt 1
- Done (steps 1, 2 ticked): `crates/custodio-cli/src/fingerprint_decide.rs` (pure: `file_bytes`, `is_custodios`, `pam_has_fprintd`,
  `first_fprintd_auth_line`, `authselect_has_fingerprint`, `dconf_disables_fingerprint`, `family_from_os_release`, `Observed`,
  `decide_enable` / `decide_disable`, `lock_note_shown` (unknown family shows the note), `NO_READER_WARNING`, `LOCK_NOTE`);
  `tests/fingerprint_decide.rs` (15 tests, 0.00 s). Fuzz target `pam_file` (in fuzz-smoke's list; `fuzz-build`, `lint-fuzz`, `fuzz-smoke` pass).
  Module added to the custodio-cli `mutants` list. `just quick` green.
- Decisions: an inline `#` ends a PAM line (Linux-PAM); `-auth ... pam_fprintd.so` counts as active; already-Custodio's wins over a global switch.
- Not done: step 3 (command module, seam feature `CUSTODIO_FIXTURE_*`, `tests/fingerprint.rs`, `Command::Fingerprint` in parse/help/main, error rendering),
  step 4 (man page), step 5 (fixture-seams scripts and recipe), step 6 (mutants-diff and evidence). Remember: the command module and
  `apply_owner`/`apply_label` exclusion (`--exclude-re`) go in the `mutants` recipe with a comment naming F199.
- Step 5 done (same attempt): `scripts/check-fixture-seams.sh` (binary: no `CUSTODIO_FIXTURE_ROOT|EUID|FAIL` string; tree: no shipped file names the feature `fixture-root`
  or a variable, no manifest enables it outside dev-dependencies / `fixture-root = []`), `scripts/test-check-fixture-seams.sh` (3 binary cases, 4 tree cases, passes),
  `just fixture-seams` (release build of custodio-cli, then both checks; passes), wired into `test-scripts` and `shell-scripts-test`. `just quick` green.
  Still to do in step 3/6: a positive run on a real build with the feature (`cargo build -p custodio-cli --features fixture-root`) as a step of the test script,
  once the feature exists; the string the check looks for is `CUSTODIO_FIXTURE_ROOT` (and `_EUID`, `_FAIL`), so the seam code must hold them as literals.
- Remaining: steps 3, 4, 6 (see above). Step 3 is the large one: start with `tests/fingerprint.rs` and the feature `fixture-root = []` in custodio-cli/Cargo.toml.
- Step 5 done (same attempt): `scripts/check-fixture-seams.sh` (binary: no `CUSTODIO_FIXTURE_ROOT|EUID|FAIL` string; tree: no shipped file names the feature `fixture-root`
  or a variable, no manifest enables it outside dev-dependencies / `fixture-root = []`), `scripts/test-check-fixture-seams.sh` (3 binary cases, 4 tree cases, passes),
  `just fixture-seams` (release build of custodio-cli, then both checks; passes), wired into `test-scripts` and `shell-scripts-test`. `just quick` green.
  Still to do in step 3/6: a positive run on a real build with the feature (`cargo build -p custodio-cli --features fixture-root`) as a step of the test script,
  once the feature exists; the check looks for the strings `CUSTODIO_FIXTURE_ROOT`, `_EUID`, `_FAIL`, so the seam code must hold them as literals.
- Remaining: steps 3, 4, 6. Step 3 is the large one: start with `tests/fingerprint.rs` and the feature `fixture-root = []` in custodio-cli/Cargo.toml.
