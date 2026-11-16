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

### 2026-11-16 — F197 — attempt 1 (continued: steps 3, 4)
- Done: `src/fingerprint_cmd.rs` (observe → `decide_*` → apply), `Command::Fingerprint`, `CliError::Fingerprint`, help entry, man page, error rendering. Seam: cargo feature
  `fixture-root` (custodio-cli dev-dependency on itself, so test binaries have it; release builds do not), reading `CUSTODIO_FIXTURE_ROOT|EUID|FAIL`. With a fixture root the owner and
  label calls are skipped (F199 proves them); `FAIL=rename|label` fail after the temp file is written. The label step runs `restorecon -F` after the no-clobber rename
  (`renameat2 NOREPLACE`) where `/sys/fs/selinux/enforce` is 1, and removes the file on failure.
- Decisions: fprintd "installed" = the D-Bus service file `usr/share/dbus-1/system-services/net.reactivated.Fprint.service`; the module is searched in `{usr/,}lib{,64}/security` and
  `{usr/,}lib{,64}/*/security`; the reader probe (`GetDevices`, limit 1.5 s, a thread with `recv_timeout`) runs only when the decision is "write"; unanswered = no reader.
- Tests: `tests/fingerprint.rs` 16 tests, 1.5 s (private `dbus-daemon` + a fake `net.reactivated.Fprint` that records calls; delay case 2 s vs the 1.5 s limit). `tests/help.rs` passes.
  `just fixture-seams` now also builds debug with `--features fixture-root` and requires the check to fail naming all three variables (the real-seam positive run).
- Mutants recipe: `fingerprint_cmd.rs` added; `--exclude-re` matches only `apply_owner` / `apply_label` (comment names F199). `just quick` green.
- Remaining: step 6 (`mutants-diff F197`, other evidence).
- Step 6 done: `just quick` green; `fingerprint_decide` (17), `fingerprint` (17, 1.5 s), `help` (8); `just fuzz-build && just lint-fuzz && just fuzz-smoke` pass (`pam_file` runs);
  `scripts/test-check-fixture-seams.sh` and `just fixture-seams` pass (the recipe's debug build `cargo build -p custodio-cli --features fixture-root` must fail the check
  naming `CUSTODIO_FIXTURE_ROOT`, `_EUID` and `_FAIL`: the real-seam positive run). `just mutants-diff F197`: 130 mutants, 116 caught, 14 unviable, 0 missed (2 min).
  Survivors fixed with: a vendor-is-a-directory case, an unreadable `etc/pam.d` case (disable must refuse, non-root only), Display tests for `Failure` and `Refusal`, a fuzz-entry test.

### 2026-11-16 — F197 — attempt 2
- Findings fixed: (1) `tests/fingerprint.rs` has no looping test now: one `#[test]` per refusal, module layout, global form, not-root action and failing step (33 tests, 1.5 s, parallel);
  (2) a failing directory flush after the rename removes the file again (new seam value `CUSTODIO_FIXTURE_FAIL=flush`, own test); the `Io` second line no longer claims
  "nothing was left behind" (it says to check `ls -l /etc/pam.d/polkit-1`, true for `disable` too). Notes: `restorecon` by absolute path (`restorecon_path`, excluded from
  `mutants` with the other two system-call functions, comment updated); the always-true package assert is now `libpam-fprintd`; a drop guard restores directory modes.
- Evidence: `just quick`, `fingerprint_decide` (17), `fingerprint` (33), `help` (8), fuzz build/lint/smoke, `test-check-fixture-seams.sh`, `just fixture-seams` pass;
  `just mutants-diff F197`: 132 mutants, 118 caught, 14 unviable, 0 missed (2 min).

### 2026-11-16 — F198 — attempt 1
- Gate: `scripts/check_packages.py` has the three rules per format (a: "PAM directory" for any file under /etc/pam.d or /usr/lib/pam.d; b: `/etc/pam.d` in any script — deb control scripts, rpm
  scriptlets, Arch `.INSTALL` and the files under libalpm hooks/scripts; c: the install script holds `sudo custodio fingerprint enable` and `custodio doctor`).
- `scripts/test-check-packages-pam.sh` (new, in `package-gate-test`; ~15 s): clean + pam-usr, pam-etc, names-pam (in the post-removal script, not the install one), no-enable, no-doctor, parallel.
  New `nfpm_edit.py` op `scripts-dir DIR` sets scripts per format from files.
- Notice (stderr, one text in three formats, first install only): deb `postinst` (`$2` empty), rpm `post` (`$1`=1), Arch `post_install`. Removal scripts unchanged.
- `scripts/test-package-scripts.sh`: notice on install/absent on upgrade, removal scripts silent on pam/fingerprint. `test-arch-lifecycle.sh` now expects the notice on post_install stderr.
- Passed: `just quick`, test-check-packages-pam, test-check-packages, -deps, test-package-scripts, deb/rpm/arch lifecycle, arch/rpm scripts-static.

### 2026-11-16 — F198 — attempt 2
- Findings fixed in `scripts/test-package-scripts.sh`: removal silence now rejects `pam|fingerprint` (case-insensitive); the `custodio: ` lines of the deb, rpm and Arch install stderr are compared byte for byte (other stderr, e.g. journalctl catalog noise in deb, is ignored).
- Passed: `test-package-scripts.sh`, `just quick`.

### 2026-11-16 — F199 — attempt 1
- Done (all 5 steps): `e2e/fingerprint.py` (judge) + `scripts/test-e2e-fingerprint.sh` (accepted set + 38 negative controls, <1 s, in `test-scripts`); `e2e/fingerprint-run.sh` (guest step, after
  journalkind, containers only), `e2e/fingerprint-pam.py` (ctypes PAM client); ids in `e2e/cases.list` (7 common) and per-target lists (`pam-auth-update` on debian13/ubuntu2604, `selinux-label` +
  `authselect` on fedora44/alma10, new lists); Containerfiles add fprintd + the PAM module (+ authselect, libselinux-utils, policycoreutils on the rpm family). Finding: `docs/findings/F199.md`
  (Debian's fprintd profile is off by default, so the evaluator's note 1 did not apply; authselect `local` profile is present on both rpm targets).
- Observation that `pam_fprintd` was reached through the override: the client reads `/proc/self/maps` after `pam_authenticate` and before `pam_end` (libpam dlcloses at `pam_end`): `fprintd=1` with
  the override, `fprintd=0` after `disable`. The authselect case edits `/etc/pam.d/system-auth` first; `apply-changes` must regenerate it (proves the tool ran) and leave the override identical.
- SELinux: not enforcing on this host; the run record shows `fingerprint: note: SELinux not enforcing here: the label ... was NOT proven`. The enforcing check is a person's run: added to
  `docs/manual-acceptance.md` section 11 (step 7, "Fingerprint override label").
- Passed (each `just e2e-cases T 'fingerprint-*'`, run one at a time: parallel runs race on the package build): debian13, ubuntu2604, arch, fedora44, alma10. The group's step takes 4 s per target.
  `just quick`, `test-e2e-fingerprint.sh`, `test-e2e-select.sh` (its no-cases.list control now uses arch), `test-e2e-skips.sh`, `test-e2e-selftests.sh` green. guest.sh comments were
  shortened to stay under the 5000-token file limit.

### 2026-11-16 — F200 — attempt 1
- Done: steps 2 and 3. Judge `e2e/vm/fingerprint.py` (events format at its top; bounds: timeout prompt 10–15 s after the finger prompt, negative killed no earlier than 15 s, fallbacks ask within 5 s, sudo needs a refused wrong password
  before the right one, fallbacks need `unit=active device=listed`, `end` judges that both set-aside files are back) and `scripts/test-e2e-vm-fingerprint.sh` (accepted set + ~75 controls, ~2 s, in `test-scripts`).
  Wiring: 12 ids in `e2e/vm/cases.list` and (as `snap-*` does, so that `lacking` can report them skipped) in `e2e/vm/skip.list`; `check-cases.sh` refuses them skipped in a full VM run; `select.sh`
  `case_group`/`phase_runs` (`vm-fingerprint`), `guest.sh` call; `test-e2e-vm-cases.sh` and `test-e2e-select.sh` learn the group (<1 s each). `just quick`, `e2e-vm-check` line pass.
- Written, NOT run in a VM yet (step 4/5 untouched): `e2e/vm/fingerprint.sh` (staging, drop-in, enrol, `enable`, polkit-finger/unenrolled/timeout/negative, sudo, disabled; `restore` trap) and
  `e2e/vm/fingerprint-pty.py` (pty driver that writes the events). Unknowns the first run settles: pkexec text-agent prompt wording (regexes in the driver), `busctl monitor` text for `verify-match`,
  the enroll scan loop, the apt package name of libfprint, whether the harness's sudo rule is under /etc/sudoers.d (grep NOPASSWD). It ends with an explicit `fail` for the unwritten sign and fallback cases.
- Remaining: step 1 (findings/F200.md from the first run), steps 4–6: run `just e2e-vm-cases full 'vm-fingerprint-*'` (debugging run; step 6's is the timed one), then write sign (needs an fpuser key import with the
  test agent before the harness's pam file is set aside) and the four fallbacks, then drop the final `fail`. Evaluator note: the install uses `--no-install-recommends` (judge.sh checks it).

### 2026-11-16 — F200 — attempt 2 (partial, stopped at the time limit)
- VM debugging runs only (not the step-6 timed run). `e2e/vm/fingerprint.sh` fixes: `pkexec` is installed with the other packages (`--no-install-recommends`); `wait_for` runs bash
  with exported functions (the `sh` form never saw them); the socket is checked during the enrolment; the test user runs through `su -lP`; failure output has the tail of each events file
  and the polkit journal. `vm-fingerprint-stage` and `vm-fingerprint-negative` pass in the VM; sudo works (wrong password refused, right accepted) but its judge result was not seen.
- Blocked on the polkit helper's `No session for cookie` and on the polkit text agent not re-asking after a wrong password: see `docs/findings/F200.md` (open items and next steps).
  The judge's polkit-unenrolled and -timeout orders (wrong password before the right one) probably have to change to a single right password (judge and its controls together).
- Steps 1, 4, 5, 6 untouched/unticked; sign and the four fallbacks are still unwritten; the script still ends with the explicit `fail`.

### 2026-11-16 — F200 — attempt 3 (partial, stopped at the time limit)
- Debugging runs only (not the step-6 timed run). Polkit cases now go through `e2e/vm/fingerprint-check.sh` (pkttyagent + pkcheck; pkexec cannot work, see `docs/findings/F200.md`); the pty driver
  waits for ECHO off before typing and judges a refusal before the next prompt. Judge: polkit-unenrolled/-timeout take one right password (no wrong-then-right), the timeout case forbids only scan/matched.
  `scripts/test-e2e-vm-fingerprint.sh` passes. Last VM run: stage, polkit-finger, -unenrolled, -timeout, -negative, -disabled judged ok; sudo failed only because `refused` was skipped
  by the driver (fixed in the last commit, NOT rerun in the VM).
- Remaining: rerun the group to see sudo pass; write sign (import a key as fpuser with the test agent, sign by the PKCS#11 module with the finger, openssl verify, journal `signature made`) and the four
  fallbacks (`CASE.restored` = `unit=active device=listed`), drop the final `fail` in fingerprint.sh and the `sign | fallback-*` skip in its judge loop; step 1 (findings are mostly there), then step 6 timed run.

### 2026-11-16 — F200 — attempt 4
- Done: all steps. Added `fingerprint-user.sh` (import of the key as fpuser), `fingerprint-sign.sh` (pkttyagent for the signing process), sign and the four fallbacks in `fingerprint.sh`
  (module moved aside, daemon masked, drop-in removed, finger deleted; each restored, `CASE.restored`), journal key field `CUSTODIO_KEY_ID`; `run.sh` records `polkit_version`, `fprintd_version`,
  `libfprint_version`, `libpam_fprintd_version` (unknown fails) and the step `vm-fingerprint`.
- The timed run `just e2e-vm-cases full 'vm-fingerprint-*'` (earlier runs were debugging runs): exit 0, 12 cases `run`, whole command 82 s; step `vm-fingerprint=53` s, install 8, boot 14.
  Versions: polkit 127-2ubuntu1.1, fprintd 1.94.5-4, libfprint 1:1.95.1+tod1-0ubuntu2, libpam-fprintd 1.94.5-4. The judge's `end` passed: `/etc/pam.d/polkit-1` and the sudo rule were back.
  Budget: vm/full is not read by the loop yet (budgets.tsv); no BLOCKED.md.
- Passed: `just quick`, `test-e2e-vm-fingerprint.sh` (~2 s), `test-e2e-vm-cases.sh`, `test-e2e-select.sh` (<1 s), `just e2e-vm-check full '<five names>'`.

### 2026-11-16 — F200 — attempt 5
- Findings fixed: `restore` is idempotent (`$PAMF` is removed only while the harness's file is set aside, so the exit trap's second pass leaves the file; `end` runs `restore` twice before it records the state);
  the contract amendment says skip.list holds the ids (separate commit); dead branch in `fingerprint-pty.py` removed; the redundant `disabled.scans` and `no-fprintd` dropped from the judge and its controls;
  `k.p12` is deleted after the import.
- Passed: `test-e2e-vm-fingerprint.sh`, `just e2e-vm-cases full 'vm-fingerprint-*'` (exit 0, 12 `run`, step `vm-fingerprint`=53 s), `just quick`.

### 2026-11-16 — F200 — attempt 6
- Findings fixed (docs only): `docs/findings/F200.md` rewritten under the rules of `docs/findings.md` (headed `## F200`, conclusions first with versions, no diary); index line added. `just quick` passes.

### 2026-11-16 — F201 — attempt 1
- Done (all 4 steps): one VM run (ubuntu2604, virtual sensor, pkttyagent) with a throwaway driver outside the repo; `docs/findings/F201.md` and its index line. Result: B (switch + Custodio file) asks a wrong finger / no touch twice (20 s); C (Omarchy-style) four prompts / 40 s; matching finger once everywhere. Decision: doctor warns when `/etc/pam.d/polkit-1` and `common-auth` both have a `pam_fprintd` auth line; F202 implements it.
- VM stopped by the driver's trap (`vm.sh stop`); no qemu left. `just quick` passes. No product code changed.

### 2026-11-16 — F201 — attempt 2
- Findings fixed (docs only): the run was repeated in the VM with a new throwaway driver (same table) and the finding now quotes the `dpkg-query -W` versions, one `RESULT` line per cell (A, D, B, C), the restore lines (pam file md5 as before, drop-in and rule gone, sudo rule never moved) and `vm.sh stop` with no qemu left. Said that the harness's pam_permit file was set aside for A. `just quick` passes.

### 2026-11-16 — F202 — attempt 1
- Done (all 5 steps): `custodio doctor` (`doctor_decide` pure, `doctor_cmd` observes), help entry, man page section and synopsis, both modules in the `mutants` list (no function excluded), no new seam variable. Shared test fixture moved to `tests/fprint_fixture/mod.rs` (root builder, `GLOBAL_FORMS`, fake fprintd with `Fake`/`Fingers`, records the `ALLOW_INTERACTIVE_AUTH` flag); `tests/fingerprint.rs` uses it (33 tests pass). `fingerprint_decide` gained `global_via` (same detection as `enable`, now says which file) and a public `packages`.
- Contract amendment (separate commit): each question to fprintd waits 1.5 s (`ASK_LIMIT`); "not installed" = no service file AND `ServiceUnknown`; anything else is "could not check". Tests use the signals crossed (no file + slow owner, no file + erroring owner, file + no owner).
- Decisions the contract left open: a broken include puts check 3 first (its own line, not a copy); `-auth ... pam_fprintd.so` counts as active (F197's `first_fprintd_auth_line` does; the contract's "control" with `-auth` would contradict that, so the controls are a comment and an `account` line); exit 2 for root (as `register`), 1 for a broken include (report on stdout, two lines on stderr).
- Measured: `doctor_reader` 1.5 s (14 cases), `doctor_polkit` 0.02 s (11), lib tests 0.3 s, `just fixture-seams` 4.6 s warm, `mutants-diff F202` 2 min (67 mutants: 0 missed after one round).
- Passed: `just quick`, `doctor_reader`, `doctor_polkit`, `help`, `scripts/test-check-fixture-seams.sh`, `just fixture-seams`, `just mutants-diff F202`.

### 2026-11-16 — F202 — attempt 2
- Findings fixed: contract amended (separate commit) so `-auth` is proven active, not a not-active control, with a new `doctor_polkit` case; serial loops in `doctor_reader` (four families) and `doctor_polkit` (two broken-include fakes, comment/account, four global forms) are now one `#[test]` each over a shared helper. Tests only, no product code changed.
- Passed: `doctor_reader` (17, 1.5 s), `doctor_polkit` (17, 0.01 s), `just quick`.

### 2026-11-16 — F203 — attempt 1
- Done: check 4 (`doctor_later::firefox`; observation in `doctor_cmd` reuses `register_discover::discover`, `parse_entries`/`plan`, the snap copy comparison and `register_modutil::nss_loads_p11_kit`), check 5 (`journald_conf`: pure `parse`/`evaluate`, `read`, `stat_journal_dir`, `fuzz_journald_conf`; fuzz target `journald_conf` and its name in `fuzz-smoke`), check 6 (`doctor_cmd::ask_service`, own thread, 1.5 s per question), exit status from the real states (`Check.later`, `Failure::Unsatisfied`), help text and man page. `doctor_decide` was over the 5000-token file limit: checks 4 to 6 live in `doctor_later.rs` (re-exported from `doctor_decide`); both are in the `mutants` list.
- Contract amendment (separate commit): doctor runs register's scratch-database `modutil -create`/`-list` probe for p11-kit, only when a native profile has no entry; never on a profile. The stub's record is asserted to hold only scratch runs.
- Tests: `doctor_firefox` (13), `doctor_system` (55), `doctor_acceptance` (16) plus the fixture's fake Custodio service (own connection, so a slow answer does not stall fprintd), fake polkit authority (`org.freedesktop.PolicyKit1`, records `CheckAuthorization`, one negative control in acceptance). F202's `doctor_reader`/`doctor_polkit` now expect exit 1 where the bus has no Custodio service (check 6 `could not check`); `doctor_polkit` serves a fake with check 6 ok.
- Passed: `just quick`, the five doctor test targets, `just fuzz-build`, `just lint-fuzz`, `just fuzz-smoke`. `just mutants-diff F203`: first run 11 missed of 105 (3 min), killed with tests (a link as the snap copy, exactly 1 MiB / 1 MiB+1 / 100 KiB files, an unreadable drop-in directory, a comment ending in a backslash, the line of the default comment, the fuzz entry point) and `copy_state` rewritten without a match guard; second run 0 missed of 101 (2 min 25 s). All six contract steps ticked. Measured: doctor_firefox 0.02 s (14), doctor_system 1.5 s (60), doctor_acceptance 1.5 s (16).

### 2026-11-16 — F203 — attempt 2
- Findings fixed (tests only): acceptance run with the fprintd service file and no owner: check 1 `could not check`, checks 4 to 6 ok, exit 0 (`doctor_acceptance`, 17 tests). Dropped the `ORDER.len()` assert and the leftover `fx.put(profiles.ini)`.
- Passed: `doctor_acceptance`, `just quick`.

### 2026-11-16 — F203 — attempt 3
- Findings fixed: `journald_conf::parse` treats a `\`-ended non-comment line as continued in any section (test `a_backslash_outside_journal_is_could_not_check` now expects `could not check`); the over-long doc comment in `doctor_decide` is wrapped. Notes 2 and 3 not acted on (within the amendment's scope; check 6 waits at most 1.5 s per question).
- Passed: `doctor_system` (60), `just quick`, `just mutants-diff F203` (101 mutants, 80 caught, 21 unviable, 0 missed, 2 min).

### 2026-11-16 — F203 — attempt 4
- Finding fixed: `profile_fact` runs register's p11-kit probe for a native profile whose entry is `Missing` or `Stale` (never on a profile directory), so a stale entry on a p11-kit system is `ok`. New test `a_stale_entry_on_a_p11_kit_system_is_ok_because_register_skips_it` (`doctor_firefox`, 15 tests).
- Passed: `doctor_firefox`, `just quick`, `just mutants-diff F203` (100 mutants, 79 caught, 21 unviable, 0 missed, 2 min).

### 2026-11-16 — F204 — attempt 1
- Done (all 5 steps): `e2e/doctor.py` (judge) + `scripts/test-e2e-doctor.sh` (accepted set, 33 controls, <1 s, in `test-scripts`), `e2e/doctor-run.sh` (root: staging, manifests, judging) and `e2e/doctor-user.sh` (`su -l` account `docuser`, stdin `/dev/null`, `timeout 30`), group `doctor-*` in `select.sh`, step in `guest.sh` after `fingerprint` (containers only), 11 ids in `e2e/cases.list`, lists of `test-e2e-select.sh`. `guest.sh` was trimmed to stay under the 5000-token file limit.
- Facts found by the first run (all five targets alike): check 1 `not ok` ("fprintd reports no fingerprint reader") with a fix, check 2 `could not check`, check 3 `not ok` (no override), check 4 `ok` (no profile), check 5 `ok` (Storage=auto, /var/log/journal exists), check 6 `not ok` (reason `not-block-filesystem`); every run exits 1.
- Differences from the contract text: stderr on exit 1 is the two-line diagnostic (`custodio doctor: ...` + `Do what ... says`), not empty (judge: only those lines, none on exit 0); a broken include prints its line FIRST (judge: first line, other lines compared as a set); the bus restarts a stopped custodio.service on the call, so `nosvc` masks it with `systemctl mask --runtime` (unmasked in the trap); directory mtimes are left out of the /etc and home manifests (staging changes a parent's mtime; the listing still shows any added or removed file), the per-run `/etc/pam.d` manifests keep them. The journal flip is a `Storage=volatile` drop-in when `/var/log/journal` exists, else the directory made; journald restarted and restored; the polkit/signature journal cursor is taken after the restart. Home restoration is judged in `doctor-no-firefox-profile` and `doctor-changes-nothing`. Exit 0 is F203's `doctor_acceptance`, not judged here.
- Passed: `just e2e-cases <target> 'doctor-*'` on debian13, ubuntu2604, arch, fedora44, alma10 (11 `run` each; whole command 74, 45, 59, 43, 18, 52 s wall; debian13 74 s first run), `test-e2e-doctor.sh`, `test-e2e-select.sh`, `test-e2e-skips.sh`, `test-e2e-selftests.sh`, `just quick`.

### 2026-11-16 — F204 — attempt 2
- Findings fixed: both `sleep 1` after the journald restarts removed (`systemctl restart` waits); `jflip.storage` is re-read with `systemd-analyze cat-config` after the restart; the journal judge requires the documented step in the fix (`mkdir -p /var/log/journal` when the directory is missing, `restart systemd-journald` otherwise); the signature count uses the sign `MESSAGE_ID` on `custodio.service` entries.
- Note 3 (changes the first run forced, recorded in attempt 1): stderr holds the exit diagnostic; with a broken include the other lines are compared as a set; directory mtimes are left out of the /etc and home manifests (files keep theirs); the stopped-service run masks the unit with `systemctl mask --runtime`. Phase time `doctor` is `E2E-PHASE doctor 14` s on debian13 in the verify log; group wall time 18 s on debian13 in this run.
- Passed: `scripts/test-e2e-doctor.sh`, `just e2e-cases` debian13, arch, fedora44 `'doctor-*'`.

### 2026-11-16 — F205 — attempt 1
- Step 1 done: `custodio __key-ids` (`key_ids.rs`: `is_id`, `render`, `within` with a 2 s limit over the whole call; `Command::KeyIds` in the parser only, not in `COMMANDS`; `main.rs` exits 1 with no output on failure). Unit tests in `key_ids/tests.rs`, parser/help test (hidden from help and USAGE). Rig tests in `crates/custodio-it/tests/completions.rs` (ids, ListKeys only, polkit count 0 with the live counter after two imports, state dir identical, absent, bus socket missing, hung peer 2 s..4 s); the binary is built by `completions_rig::binary()` (`cargo build -p custodio-cli` once, after cargo's own build lock is released, as `delete/run.rs` does). `just lint-fuzz` passes.
- Evaluator notes to apply in the next steps: fingerprint `enable`/`disable` in the comparison (and `__key-ids` not among them); compare the temporary HOME in bash; say if bash is loaded by sourcing; negative control per shell removes `--remove`; `test-check-packages-completions.sh` goes in `package-gate-test`.
- Step 2 done: `packaging/completions/custodio.bash` (shellcheck clean) and its 7 tests in `completions.rs` (commands/options incl. fingerprint `enable`/`disable` + negative control removing `--remove`; key ids; absent; hung; 200 keys; hostile ids as data; nothing written/no polkit, bash compares the whole temporary HOME). The bash test loads the file through bash-completion's own default loader (`complete -D`, found under `BASH_COMPLETION_USER_DIR/completions/custodio`), then calls the function the loader registered with `COMP_WORDS` set as bash sets them (no pty, no readline TAB). Tests run in ~4 s together. Rig test of `__key-ids` lives in `completions.rs` too (the 15 s estimate covers it).

### 2026-11-16 — F205 — attempt 2
- Step 3 done: `packaging/completions/_custodio` (`zsh -n` clean) and its 7 tests in `completions.rs` (same cases as bash, `Shell::Zsh`). The test drives a real interactive zsh on a pty (`zsh/zpty`): `compinit -D` with the file in an `fpath` directory, a `compadd` wrapper that records the matches that fit the word, the words and a real TAB; the time is measured from TAB to the next prompt. Stray output is the terminal text when nothing is offered. All 18 tests of `completions` pass in 7 s.
- Step 4 done: `packaging/completions/custodio.fish` (`fish --no-execute` clean) and 7 fish tests (`Shell::Fish`): real `fish -c` with the vendor directory prepended to `fish_complete_path` and `complete -C` (fish loads the file only when `custodio` is on PATH; `--no-config` empties the path, so it is not used; fish creates its own dirs under the temporary HOME, so for fish and zsh only paths named `custodio` are compared). Negative control per shell: bash/zsh drop the word `--remove`, fish drops its line. 25 tests of `completions` pass in 7 s.
- Remaining: steps 5 (packages) and 6 (docs, `just quick`, verify line).
- Step 5 done: nfpm entries (bash, fish all formats; zsh `packager:` deb→vendor-completions, rpm/arch→site-functions), `package_expected.py` (`ZSH`, bash/fish in `FILES`), `check_packages.py` (zsh path per format, packager-limited allowed for it), the two zsh exceptions, `nfpm_edit.py` ops `drop-for` and `redst`, `scripts/test-check-packages-completions.sh` (clean set + three listings + parity with/without the zsh exception + 9 drops + deb zsh in site-functions; ~1 s wall) added to `package-gate-test` (evaluator note 5). `test-check-packages.sh` and `test-check-parity.sh` pass.
- Step 6 done: `docs/install.md` section "Shell completion" (locations per shell; `autoload -U compinit; compinit` for Debian, Alma, Arch and Fedora users not from the skeleton). `test-check-parity.sh` now expects the two zsh exceptions (7 differences, 7 exceptions). All six steps ticked.
- Passed: `just quick`, `cargo test -p custodio-it --test completions` (25, 7 s), shellcheck, `zsh -n`, `fish --no-execute`, `test-check-packages-completions.sh`, `test-check-packages.sh`, `test-check-parity.sh`. Evaluator note 7: `just lint-fuzz` passed in attempt 1 (parser changed only there); note 8: unit assertions in `parse/tests.rs` (`help::command("__key-ids")` is none, rendered help lacks it).

### 2026-11-16 — F205 — attempt 3
- Finding fixed (tests only): the zsh driver now strips the echoed words from each terminal line instead of dropping the line, so stray output on the TAB line reaches stderr. Negative control `zsh_stray_output_is_noticed` (a copy of `_custodio` that prints to stderr from `_custodio_key_ids`). `completions`: 26 pass, 7 s.
- Passed: `cargo test -p custodio-it --test completions`, `just quick`.

### 2026-11-16 — F206 — attempt 1
- Steps 1-3 done. `just check` (red once: `docs/install.md` had a ```zsh block, now ```bash; rerun green, 81 script tests in 63 s), `just api-contract`, `just fuzz-smoke` (18 targets run = 1 + 11 + 6 from `cargo fuzz list` of the three fuzz crates), `just memory-safety` (41 s, exit 0) pass.
- e2e fixes: `cli-list-none` judge accepts the F180 `Warning:` line on stderr (selftest case added); `tpmfail` judge and its script test look for the CLI sentence of each error, not the bus error name that F193 stopped printing. Two earlier e2e runs also showed pty timeouts in `cli-import-pkttyagent*` on fedora44/debian13 that did not repeat (load with six at once, not reproduced; watch for it).
- Final e2e on this tree (`just e2e`, six records, exit 0, wall 173 s): alma10 149 s, arch 153, debian13 swtpm 173, fedora44 139, ubuntu2604 147, debian13 none 157; all under `budgets.tsv` rows. Per log `E2E-CASE run doctor-` = 11 on all six (debian13 none too); `fingerprint-` run: alma10 9, arch 7, debian13 8 (swtpm and none), fedora44 9, ubuntu2604 8; no fingerprint/doctor case skipped.
- Acceptance 16 (docs commands run as written) is NOT proven here: the Design 5 documents come in F207. VM group (acceptance 18, 19) is left to F209.
- Remaining: steps 4 (`package-gates`), 5 (`coverage`, `crap`), 6 (rerun `check` after the e2e script edits, `just quick`). No regression test was added beyond the selftest case (<1 s).
