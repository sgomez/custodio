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
- Not done: step 12 (`just mutants-diff F193`, then the rest of the verify: help test, fuzz-build, lint-fuzz, fuzz-smoke).
- Next session should: run `timeout 1700 just mutants-diff F193` once; kill survivors narrowed with `--re`.
