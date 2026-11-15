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
