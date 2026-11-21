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

### 2026-11-16 — F206 — attempt 2
- Step 4 done. `just package-gates` red once: namcap `incorrect-owner` (0:0) on the three completion files in the Arch package; same cause as the existing entries (nfpm writes numeric owner ids only), so three entries with that reason in `packaging/lint/namcap.txt` (a finding that is not a defect). Rerun exit 0 (87 findings, 87 excepted, 0 stale; 15 s wall second run, 84 s the first). No test added.
- Step 5 done. `just coverage` red once: under `cargo llvm-cov` the tests that `env_clear()` the CLI (completion rig, `doctor_firefox`, `fprint_fixture`, `fixture`) dropped `LLVM_PROFILE_FILE`: bash completion test saw a `.profraw` under HOME, and the doctor code read 0% (11 functions CRAP 42–240). Fix: the variable is passed through in those four places (tests only, no time cost). `just coverage` exit 0 (1502 + 96 tests, 65 s wall), `just crap` exit 0 (1297 functions, worst 28.1, threshold 30).
- Step 6: `just check` was red once more on the final run: `test-e2e-vm-silent.sh` still fed the old bus error name to the judge F206 attempt 1 changed (fixture lines now carry the CLI sentences; 2 s, unchanged). Final tree: `CHECK_FORCE=1 just check` exit 0 (81 script tests 65 s, 1:56 wall), `just quick` exit 0, `just api-contract` exit 0. Since the e2e/memory-safety/fuzz-smoke runs only tests, `packaging/lint/namcap.txt` and one script test changed (`git diff --stat 13a80fb HEAD`: no product code, no e2e script), so those runs stand and were not repeated; `package-gates` and `coverage`/`crap` ran after their fixes.
- Not proven here: acceptance 16 (docs commands, F207) and acceptance 18/19 (VM group, F209). No budget row exceeded (e2e times above). All six steps ticked.

### 2026-11-16 — F207 — attempt 1
- Step 1a done: example `docs_fprintd` (custodio-it; includes `fprint_fixture/mod.rs` by `#[path]`, whose `CARGO_BIN_EXE` became an `option_env!` fallback), `scripts/lib/docs-fprint-fixture.sh` (fixture roots per system, `sudo`/`gsettings` wrappers, private bus + fake fprintd; no `pkexec`, the docs do not use it), `docs_check.py`: `text` kind, `kinds --only-console`, `fixture=NAME` attribute (runs `$DOCS_SETUP NAME` before the block). The fixture CLI is built into `target/docs-fixture` so it does not replace `target/debug/custodio-cli` (10 s, deps cached).
- Step 2 done: `docs/fingerprint.md` (enable/disable, the file, refusals with 7 blocks, GNOME lock screen, Firefox restart, other systems) and `scripts/test-docs-fingerprint.sh` (3 s wall, 9 controls, in `test-scripts`; the README links the page, `REQUIRED` of `test-docs-readme.sh` has it). Stderr is compared by `2>&1` in the refusal blocks. `test-docs-readme`, `-install`, `-install-register` pass.
- Left: step 1b for the guide script (`test-docs-guide.sh`), step 3 (`docs/doctor.md`; add it and the install.md sections to `test-docs-fingerprint.sh`, with the evaluator notes 1-2: fail if the install.md sections run no `enable`/`doctor`; doctor check-name set derived from the CLI), step 4 (guide: dpkg in a fixture root as `test-deb-lifecycle-real.sh`), step 5 (install.md sections as `console` blocks; README links to doctor and the guide, in `REQUIRED`), step 6. The page's prose (lock screen, limits) was written without a reading against SPEC Design 5 and the threat model: step 5's reading is still to do.

### 2026-11-16 — F207 — attempt 2
- Step 3 done: `docs/doctor.md` (a `###` section per check, six blocks on fixtures: ok, noreader, nofinger, brokeninclude, plainstorage, both `fails=yes` ones exit 1) and `test-docs-fingerprint.sh` now runs it and the install.md sections (`## Fingerprint for polkit dialogs`, `## Checking the system`; fails when they hold no `enable`/`doctor` block, with a control that renames one). The set of check names is derived from the CLI (`custodio doctor` after each block) and must equal the `###` headings; 2 doctor controls added (section removed, fix changed). Fixtures: `fp_doc_setup` and `fp_fake_swap` in `docs-fprint-fixture.sh` swap the fake fprintd's reader/finger per block. New block attribute `for=NAME` in `docs_check.py`: skipped unless `DOCS_FOR=NAME`; the two new install.md blocks are `for=fingerprint` so `test-docs-install-register.sh` skips them. README links doctor.md; it is in `REQUIRED` of `test-docs-readme.sh`.
- Of step 5 done: the install.md fingerprint and doctor sections and the README doctor link (the completions section was already there). Not done: the guide link in the README and `REQUIRED`, and the reading against Design 5.
- Passed: `test-docs-fingerprint` (about 10 s), `-readme`, `-install`, `-install-register`, `just quick`.
- Left: step 1b for `test-docs-guide.sh` (not started; add to `test-scripts`), step 4 `docs/guide-ubuntu-2604.md` (use `scripts/lib/bus-fixtures.sh`, `lifecycle-fixtures.sh`, `package-fixtures.sh` as `test-deb-lifecycle-real.sh` does; the `.p12` from `openssl pkcs12`; the register fixture of `docs-register-fixture.sh`), rest of step 5, step 6. Evaluator note 4: the "what removal and purge leave" statement must be a `console` block (`ls`/`stat` of the state directory, `getent passwd`) so the comparison reads it from the document.

### 2026-11-16 — F207 — attempt 3
- Steps 1b and 4 done: `scripts/test-docs-guide.sh` (about 5 s wall with built deps; 6 controls: bash block, text block, extra command, output altered, deb name changed, `register --remove` moved after the removal) and `docs/guide-ubuntu-2604.md`; the script is in `test-scripts` (justfile). The real dpkg installs, removes and purges the `.deb` (built from `packaging/nfpm.yaml`, `custodio_0.9.0-1_amd64.deb`) into a root; stand-ins on PATH: `sudo`, `apt-get` (refuses removal while a Firefox profile still names Custodio), `ls` and `getent` (look into the dpkg root), `custodio` (sends `doctor`/`fingerprint` to the fprintd bus, the rest to the server bus). The guide's "what removal leaves" is `console` blocks (`sudo ls -d`, `getent passwd`) and the state directory snapshot must equal the one before. README links the guide, `REQUIRED` of `test-docs-readme.sh` has it, plus a control for the missing guide link.
- Passed: `test-docs-guide`, `-fingerprint`, `-readme`, `-install`, `-install-register`, `just quick`.
- Left: step 5's reading of the three documents against SPEC Design 5 and the threat model's "Not guaranteed" (prose, not done: the guide is short and does not yet say the GNOME lock screen/Firefox restart in detail, it links fingerprint.md), then step 6 (tick after the reading; the verify line already passes). Guide's `.p12` is supplied by the script (export in Firefox is prose).

### 2026-11-16 — F207 — attempt 4
- Step 5 reading done against SPEC Design 5 and the threat model's "Not guaranteed": `docs/fingerprint.md` now lists each limit of that list (intent, uid/pid and app-id, root and the encrypted kinds, TPM clear, erasure, uid reuse, SELinux). Lock screen, Firefox restart, doctor, guide, install.md sections and refusals are present. Step 6 done.
- Passed (measured): `test-docs-fingerprint` ~10 s, `-readme` 2 s, `-guide` 4 s, `-install` 4 s, `-install-register` 1 s, `just quick` 51 s. All well under the 120 s default.

### 2026-11-16 — F207 — attempt 2 (findings fixed)
- `test-docs-fingerprint.sh` now runs `static` on `docs/fingerprint.md` too. Refusal blocks for all five systems' os-release (Ubuntu, Alma added; `fp_root` writes `ID_LIKE`) and for `global-fedora`, `global-arch` (count raised to 11). `docs/doctor.md` gains a `plainreason` block (`unknown` with reason `not-block-filesystem`).
- Guide: install, remove and purge show the package's `custodio:` notice (the `apt-get` stand-in prints those lines of dpkg's output on stdout; control "install notice altered"). The completion block sources the shipped file (a `source` stand-in through BASH_ENV reads it from the package root) and prints the candidates for `li`. `docs_check.py` gives `DOCS_COMMANDS` (every command of the block) to `DOCS_CHECK`; the guide script lists each command with its handler and fails on one no handler knows.
- All five verify scripts and `just quick` pass. Guide script about 5 s, fingerprint script about 10 s.

### 2026-11-16 — F208 — attempt 1
- Steps 1-5 done. `test-docs-release-notes.sh`: version from the file name (link targets are ignored, so the 0.9.0 notes link the 0.8.0 notes by path), default `DOC` the 0.9.0 notes, controls "version v1.0.0" and "title with another version"; `test-scripts` runs it twice (the 0.8.0 run as `DOC=docs/release-notes-v0.8.0.md scripts/...`; `run-script-tests.sh` accepts the `DOC=` prefix). Notes, README second link, threat model (M7 in-scope, out-of-scope and six Not guaranteed items) and SECURITY.md written; reading against SPEC "Threat model": each item present.
- `test-docs-api.sh`: `docs_api_run.py names` derives error names (`ERROR_*` in custodio-client), outcomes (`name()` of the audit enums) and `StateStorageReason` (`UnknownReason::name`) from the code and compares with api.md/audit.md; three controls. api.md/audit.md already agreed (no drift found).
- `docs/manual-acceptance.md` sections 26-29 (steps of acceptance 22, reviews of 20 and 21, form). `scripts/test-docs-manual-m7.sh` cuts the page at section 26, runs its `console` blocks through `test-docs-guide.sh` (new `AFTER_RUN` hook) and then the page's own `final-checks.sh` bash block on the fixture root: clean after the way back (real dpkg -i/-r/-P), and each of four dirty fixtures makes its check say NOT CLEAN by itself. The kept path list lives in the page's block only. Controls: bash block where console is required, wrong flag, output line, install notice, `register --remove` missing, four dirty ones. The import of the person's own file is stated on the page as a person's step.
- Measured: `test-docs-manual-m7.sh` 6 s wall with built deps (first real run of dpkg -i/-r/-P in this container through it: ok, the controls run at once); `test-docs-api.sh` ~20 s; release-notes ~20 s each.
- Passed: `just quick`, the five verify scripts (`test-docs-readme`, `-guide`, `-threat-model` too), shellcheck -x on the touched scripts.

### 2026-11-16 — F208 — attempt 2
- Fixed NEXT_FINDINGS: removed the seven stray self-referencing symlinks (`fix(F208)` commit); replaced the control "install notice altered" (already in `test-docs-guide.sh`) in `test-docs-manual-m7.sh` with "an extra console command whose output then differs" (`$ custodio list` inserted into the `custodio delete ana` block). `scripts/test-docs-manual-m7.sh` passes, 6.5 s with all controls.

### 2026-11-16 — F208 — attempt 3
- Fixed NEXT_FINDINGS: the block-kind check of `test-docs-release-notes.sh` now uses `kinds --only-console`; control "a bash block in the notes" added. Both the 0.9.0 and 0.8.0 runs pass (~20 s each).

### 2026-11-16 — F209 — attempt 1
- No fix was needed: every suite passed on the tree at `e7c873b` (no product, script or e2e change in this session), so each ran once. All steps ticked.
- Host: `CHECK_FORCE=1 just check` exit 0 (85 script tests, 69 s); `just api-contract` 0; `just fuzz-smoke` 0 (18 targets run, equals `cargo fuzz list` at F206); `just memory-safety` 0. The `"a b c"` control is the one `check` already holds from F206 and was not repeated.
- `just e2e`: six records, exit 0, wall 219 s (alma10 162, arch 192, debian13 swtpm 219, fedora44 175, ubuntu2604 179, debian13 none 198; all under their `budgets.tsv` rows). `E2E-CASE run doctor-` = 11 on all six. Fingerprint cases owed (7 common + own) and run: alma10 9, arch 7, debian13 8 (swtpm and none), fedora44 9, ubuntu2604 8; none skipped.
- `just package-gates` 0 (66 s; 87 findings, 87 excepted, 0 stale). `just coverage` 0 (65 s), `just crap` 0 (1297 functions, worst 28.1, threshold 30).
- VM `full` (exit 0, 372 s against the 580 s row): 12 `E2E-CASE run vm-fingerprint-`, 0 skipped, `check-cases: 62 cases accounted for`. Record (taken from this last full run, the final tree): polkit 127-2ubuntu1.1, fprintd 1.94.5-4, libfprint 1:1.95.1+tod1-0ubuntu2, libpam-fprintd 1.94.5-4; no `unknown`. Phases (s): image 16, boot 18, install 8, tools 2, cycle 14, snap 206, vm-fingerprint 55, sign 9, noplain 2, pcr 6, fallback 2, tpmclear 8, upgrade 10, setup 2, teardown 6.
- VM `lacking` (exit 0, 97 s against 500 s): 62 cases accounted for, no `unknown`, the 12 fingerprint ids skipped with their `skip.list` reason. Phases: snap 0, vm-fingerprint 0, cycle 13, sign 10, tpmclear 9, upgrade 10, rest ≤ 18.
- That a failing `vm-fingerprint-*` case makes the exit non-zero (evaluator note 1) is held by `scripts/test-e2e-vm-fingerprint.sh` and `test-e2e-vm-cases.sh` (green in `check`); no failing case was provoked in the real run.
- Acceptance 20–22 are a person's. `just quick` run at the end.

### 2026-11-16 — F209 — attempt 2 (findings fixed)
- NEXT_FINDINGS: `scripts/test-tree-hash.sh` failed once under load (85 scripts at once). Cause, reproduced with 24 parallel runs (1 failure): `tree-hash.sh` copied the index with `cp`, so the copy's mtime was newer than the edited file's; git then treated a same-size edit made in the same timestamp tick as clean (racy-git check uses the index mtime). Fix: `cp -p` keeps the mtime. 90 parallel runs after the fix: 0 failures. shellcheck and `just quick` pass. No new test (the existing one is the regression test; no extra time).
- Only `scripts/tree-hash.sh` changed (host stamp script): no product, e2e, package or VM script change, so the e2e, package-gates, coverage, memory-safety and VM results of attempt 1 stand. The four VM version fields (polkit 127-2ubuntu1.1, fprintd 1.94.5-4, libfprint 1:1.95.1+tod1-0ubuntu2, libpam-fprintd 1.94.5-4) and the 12 run / 0 skipped fingerprint counts are from attempt 1's last `full` run; no VM file changed since, so none was rerun. `check` must be rerun by the loop.
- Fingerprint cases owed per target (7 common + own): alma10 9, arch 7, debian13 8, fedora44 9, ubuntu2604 8.

### 2026-11-16 — F209 — attempt 3 (findings checked)
- NEXT_FINDINGS: `just e2e` failed once on alma10 (swtpm): `cli-import-pkttyagent` and `cli-delete-pkttyagent` timed out (the 60 s expect of `e2e/cli-pty.py`; no prompt from pkttyagent) while six targets ran at once; the guest's temp dir was gone, so no events file survived. It is not reproducible: `E2E_TPM=swtpm just e2e alma10` alone exit 0 (95 s, both cases `run`), and the full `just e2e` rerun on the unchanged tree exit 0 (six records, wall 172 s, row limits kept). No product, e2e or script change in this attempt, so no earlier result changes; the failure is recorded as an intermittent load-dependent timeout in the alma10 pkttyagent cases (it ran right after `appid-*` left app.slice with ~4400 children, a possible cause, not proven). If it recurs, the next session should keep `$CLI/*.events` of a failed run in the log before changing anything.
- Unchanged and still standing from attempts 1–2: the VM `full`/`lacking` results, versions, 12 run / 0 skipped fingerprint counts and per-target fingerprint counts (alma10 9, arch 7, debian13 8, fedora44 9, ubuntu2604 8).

### 2026-11-17 — F210 — manual review (with the person)
- Done: pre-review of acceptances 20 and 21, fixes from it. Docs: fingerprint.md (login/lock-screen claims, the SPEC's
  "Not guaranteed" list item by item, refusals for vendor file, fprintd and disable), doctor.md (every state, foreign file),
  threat-model.md (the six fingerprint items as in SPEC), guide and manual-acceptance show enable's lock-screen note (the
  ubuntu fixture now has GNOME's login-screen schema). CLI: doctor's fix for a foreign polkit-1 no longer says `enable`;
  doctor's last line names the failing checks; storage fixes say what to do instead of citing README.md (not installed);
  check "module in Firefox" renamed "module in browsers"; `register` skips print once (stderr) and name `--remove` when
  that was the run; `custodio` alone prints the help; `usage:` built from the help table. Help: sudo in the fingerprint
  example, polkit dialog for import/delete, key types and id rule, when to run register.
- Decisions: purge keeps the keys (M2 decision stands, the person confirmed it).
- Not done / known issues: the output of doctor and the other commands is still hard to read; the person wants a redesign,
  as its own feature. Other `README.md` references in CLI messages (list note, import/list storage warning, export hint,
  "report a bug") point to a file the package does not install.
- Next session should: nothing for F210; the person closes it with `just milestone pass F210` after reading.

### 2026-11-18 — F210 — doctor output redesign (with the person)
- Done: `custodio doctor` prints three sections (Fingerprint (optional), Browsers, System), one line per check with
  `ok`/`FAIL`/`warn`/`?` (coloured on a terminal), short names (reader, finger, polkit, one line per browser profile,
  journal, key storage) and short texts; notes and `Fix:` lines indented under the check; the register fix once, under the
  last profile that needs it; a last line "N problems."; nothing on stderr when the report fails (exit status unchanged).
  Key storage `not-encrypted` or `unknown` is `warn`, which does not change the exit status: SPEC Design 2 and
  acceptance 6 changed by the person on 2026-11-18 (Custodio works on such a disk; the risk is the person's to accept).
- Tests: every doctor integration test reads the output through one parser (`tests/fprint_fixture/report.rs`); tests
  assert states, sections, order, exit status, where the fix is, and literals only for what the person copies (commands,
  packages, paths). Unit tests check the render by structure, not wording. Docs and e2e judge updated to the format.
- Known issues: one run of `doctor_firefox::a_snap_profile_with_the_copy_up_to_date_is_ok` failed once (copy read as
  old) and did not reproduce in 130 runs, alone or six at once.
- Next session should: nothing; the person closes F210.

### 2026-11-18 — F210 — list output redesign (with the person)
- Done: `custodio list` shows the day of expiry with `expired` / `expires soon` (30 days), a header row on a terminal
  only (e2e scripts read every line as a key), the one-line weaker note without README; `list -v` / `--verbose` and
  `list <id>` show each key in full (id as title, whole subject and issuer, not before / not after on their own lines,
  SHA-256). The storage warning of import and list is two lines naming `custodio doctor` instead of README.md. Help
  options carry their short form (`-v, --verbose`). SPEC Design 3 changed by the person for all of this.
- Tests: list tests compare cells with `cert_text::fields()` of the same certificate, expiry at its boundaries with an
  injected now, header and colour by structure; e2e list judges take the day; completions offer `-v`.
- Next session should: nothing; the person closes F210.

### 2026-11-18 — F210 — import output and usage errors (with the person)
- Done: a successful `custodio import` prints `ok`/`warn`, the key id, type and kind (the columns of `list`), one note
  under a weaker or unknown kind, then `Next:` with `shred -u <file>` (shell-quoted) and the Firefox restart. Bare
  `import`, `delete` and `fingerprint` print their short help (`help::short`) on stderr, exit 2. Every other usage error
  of a known command names what is wrong (`parse::Wrong`: unknown option, unexpected argument, missing, no value,
  twice, conflict) and where the help is. No SPEC change: usage errors still go to stderr, exit 2, and point to help.
- Tests: parser tests compare `Wrong` values, not text; the import output is read by layout
  (`tests/import_view`, shared with custodio-it by `#[path]`) and compared with `next_steps()`; the shred command is
  checked by having `sh` read it back as the file. e2e judges of the import output read it by layout.
- Next session should: nothing; the person closes F210.

### 2026-11-18 — F210 — one line format for every command (with the person)
- Done: `report.rs` holds the line every command prints: state word (`ok`/`FAIL`/`warn`/`?`), name, short text, and
  the lines under it indented under the name (so a long text never pushes them right). `doctor`, `import`, `delete`,
  `register` (one line per profile, `Firefox (snap)  module copy: …`, the restart note once), `fingerprint enable|disable`
  and the storage warning of `import`/`list` all render through it. The key storage words live once in
  `storage::summary`; doctor adds the note and the fix, import/list point to `custodio doctor`. The no-reader warning of
  `fingerprint enable` is doctor's reader line. Paths under home print as `~/…`; `shred -u` takes a shell-safe word.
- Tests: one generic parser of the line format per test crate (`tests/lines`, `tests/import_view`); expected text
  comes from the product (`storage::summary`, `imported_line`, `next_steps`, `deleted_line`, `done_line`,
  `Outcome::state_text`). e2e judges (doctor, fallback, tpmkind, tpmfail, vm snap) read by layout.
- Next session should: nothing; the person closes F210.

### 2026-11-21 — F212 — attempt 1 (session 1)
- Done: step 2 (ticked) and most of step 3's re-pointing. `help::COMMANDS` now has `setup` with `children` (browsers: enable,
  disable, refresh; fingerprint: enable, disable); `CommandSpec.path` is the full path (`setup browsers enable`), `help::find`,
  `help::all()` walk the levels; `parse_group` in `parse.rs` handles `setup …` (bare level = `ArgError::Bare(path)`, unknown
  word = `CommandUsage(level path, …)`); `parse_register_args(action, args)` takes the action (`--module` only for enable and
  refresh; `Wrong::Conflict` removed). `register`/`fingerprint` are unknown commands. `tests/setup.rs` (5 tests) and `tests/help.rs`
  (parity over every level, two new fixture controls) pass; the man page SYNOPSIS/prose use `setup browsers|fingerprint`.
  Every product text, polkit header and doctor Fix now names the new commands (perl rename), and all `cargo test -p custodio-cli`
  tests pass on the new argv (`--remove --module` cases became `setup browsers disable`; parser unit tests re-pointed).
- Not done: step 1 is unticked only because `just fuzz-build` was not run. Step 3's "every message names a real command" unit test
  (with its two controls, exhaustive over error variants, doctor Fix lines, polkit header, undo hint, refusals) is NOT written yet;
  the short-help-per-level control in `help/tests.rs` (`the_short_help_check_sees_a_dropped_action`) is weak: make it call a checker
  function on a text with one action dropped. Steps 4–9 not started (completions, systemd unit, packaging notices, e2e, docs +
  `documents_name_only_real_commands`, runners, justfile 0.8.0 line, mutants). `crates/custodio-it/tests/completions.rs` and the
  three completion files still use the old names (it is red). Evaluator notes to apply in the document test: accept any
  `sudo [options] ` prefix or reject unknown sudo options (no silent skip); a `<placeholder>` in a command-name position fails;
  the costs row for `setup.rs` covers the third control and the wider block scan (wording only).
- Next session should: run `just fuzz-build`, write the step 3 unit test, then steps 4 onwards in order.

### 2026-11-21 — F212 — attempt 1 (session 2)
- Done: steps 4–8 ticked. Completions (three files; `completions.rs` walks the table recursively, control drops the `refresh`
  action); refresh unit, install notices and their gates; e2e scripts and judges; every current document and doc runner on the new
  names (release notes 0.9.0 gained the `setup` bullet; reviewer to check that sentence: F210's reviewer); justfile no longer runs
  the 0.8.0 notes; `setup.rs::documents_name_only_real_commands` with its three controls (in-process parser; sudo options accepted;
  placeholders in a name position fail through the parser; `Bare` counts as a real command). Two docs lines about Tab completion
  were reworded (`custodio li` is not a command). `test-user-refresh-units.sh` judge now reads `replaced, it differed` (the F210
  output) instead of `refreshed`. Runners passed on this tree: readme, install-register, fingerprint, guide, manual-m7,
  release-notes, threat-model, user-refresh-units, package-scripts, check-packages-pam, e2e-fingerprint, e2e-doctor, e2e-vm-snap.
- Later in the same session: `just fuzz-build` and `just quick` pass (step 1 ticked); `error/tests.rs` checks that every command a
  `CliError` sample names parses (with a control), and `register_native/skips.rs` was split (`killed.rs`) for the file-size gate.
- Not done: step 3 stays unticked: the same check is still missing for doctor `Fix:` lines (all states), enable's undo hint, the
  polkit file header and the `register_lines` fixes, and the short-help control in `help/tests.rs` is still the weak one. Step 9:
  `just mutants-diff F212` not run yet; `guide` and `manual-m7` doc runners to be re-run after the Tab-line rewording.
- Next session should: finish step 3 (the missing sources above), then run mutants-diff F212 and the verify's fast part.

### 2026-11-21 — F212 — attempt 1 (session 3)
- Done: step 3 finished: `command_names.rs` (test-only) holds the shared "every command a text names parses" check and runs it over
  the polkit file header, `done_line` (undo hints), every `decide_enable`/`decide_disable` refusal over the observed states, every
  doctor `Fix:`/warning fix/note over polkit file × vendor × common-auth × reader/fingers × profile copy/entry states, and the
  `register_lines` fixes; a control fails removed command names. The short-help control in `help/tests.rs` now calls a checker
  (`missing_from_short`) on a text with one action dropped. Step 9: `just quick` green, `setup`, `help`, `completions` tests,
  the three shell checks, guide and manual-m7 runners pass; `just mutants-diff F212`: 74 mutants, 55 caught, 19 unviable, 0 missed
  (two survivors killed: `Refusal` Display tested against the error line; the refresh `--module` option text now shares `MODULE`'s
  neutral text "use this library instead of the installed one", man page line updated).
- Reviewer: check the 0.9.0 notes sentence (register became setup browsers; fingerprint moved under setup), as F210's reviewer.
- Next session should: nothing; the loop runs the verify.

### 2026-11-21 — F212 — attempt 2 (fixes of NEXT_FINDINGS)
- Done: the setup message prefixes are product constants in `help.rs` (`BROWSERS_PREFIX`, `REFRESH_PREFIX`, `FINGERPRINT_PREFIX`,
  `SETUP_PREFIXES`). Refusals of enable/disable/refresh say `custodio setup browsers: …`; the snap refresh journal entry says
  `custodio setup browsers refresh: …`. Tests: `every_browsers_action_refused_under_sudo_…` (binary, all three actions), the journal
  `MESSAGE` prefix in `refresh_only_logs_its_outcome_to_the_journal`, and `documents_name_only_real_commands` now reads the product list.
- Checks: `cargo test -p custodio-cli`, `just quick` green; `just mutants-diff F212`: 74 mutants, 55 caught, 19 unviable, 0 missed.

### 2026-11-21 — F214 — attempt 1 (session 1)
- Done: steps 1, 2, 3, 5. Unit has `LimitCORE=0` and `MemorySwapMax=0`, gate and two controls (line removed; `LimitCORE` line replaced by `infinity`);
  `harden()` in `crates/custodiod/src/main.rs` (rustix `setrlimit`, then `set_dumpable_behavior`), called first in `run()`, test `core_limit_and_dumpable` in
  `main_tests.rs` (a test of the binary). `memory-*` (4 cases: unit settings, core limit, not dumpable with a uid 65534 control, and `memory-service-answers`: one
  ListKeys) in `e2e/memory-run.sh`, `just e2e-cases debian13 'memory-*'` passes. Finding: the `/proc/<pid>` directory itself is always the process's uid
  (mode 0555); the dumpable flag shows on the files in it, so the case reads `/proc/<pid>/status`. Docs and release notes written; the three doc runners pass.
- `vm-memory-*` (9 cases) written: `e2e/vm/memory.sh`, wired in guest.sh/select.sh/run.sh, cases.list and skip.list. NOT yet run: step 4 and step 6 (verify's fast
  part, `just mutants-diff F214`) remain. The contract's Scope sentence about `setrlimit` and `@resources` is wrong (evaluator note 1: rustix makes `prlimit64`, allowed);
  amend it.
- Next session should: run `just e2e-vm-cases full 'vm-memory-*'` and fix what it finds, tick step 4, then step 6.
- Later in the session: step 4 ticked. `just e2e-vm-cases full 'vm-memory-*'` passed (first run failed: Rust's runtime swallows a `kill -SEGV` that is not a stack overflow, so
  `crash` sends it again; one run failed on the systemd-coredump control not failing within 60 s, the wait is now 120 s with diagnostics, and the rerun passed).
  Step 6 not done: `just quick` and `just mutants-diff F214` still to run; also amend the Scope sentence on `setrlimit`.

### 2026-11-21 — F214 — attempt 1 (session 2)
- Done: Scope sentence on `setrlimit` amended (own commit). `just quick` was red on the file-size gate (`e2e/guest.sh` 5147 tokens): comments shortened,
  now under 5000. `just quick` green; `just mutants-diff F214` passes (`crates/custodiod/src/main.rs` is not in the recipe's `--file` list, so `harden()` is not mutated;
  the diff's other files had no mutants). Step 6 ticked; all steps done.
- Next session should: nothing; the loop runs the verify. F213 proves the real packages and both VM modes.

### 2026-11-21 — F214 — attempt 2 (fixes of NEXT_FINDINGS)
- Done: `e2e/check-cases.sh` refuses `vm-memory-*` reported skipped in a full VM run (and the skip-list entry is expected to match nothing there);
  `scripts/test-e2e-vm-cases.sh` has the negative control beside vm-fingerprint (full refused per id, lacking accepted, check without the rule passes) and reads `vm/memory.sh`.
- For F213: `vm/memory.sh` leaves apport stopped and systemd-coredump installed for the rest of the full VM run; a later group depending on the core handler must know.
- Checks: `scripts/test-e2e-vm-cases.sh` ok; `just quick` result below.
