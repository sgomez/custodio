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

### 2026-10-30 — F36 — attempt 1 (session 1)
- Done: steps 1-4. nfpm 2.48.0 pinned (mise.toml + mise.lock, Containerfile, CI `package` job and CI lint step installs
  the tools); `ExecStart` moved; `packaging/nfpm.yaml` and the four lifecycle scripts; `scripts/lib/package-fixtures.sh`,
  `scripts/lib/nfpm_edit.py` (fixture ops), `scripts/test-package-scripts.sh`, recipe `package-gate-test` in `check`.
- Decisions: nfpm takes version/prerelease from `NFPM_VERSION`/`NFPM_PRERELEASE`; Arch gets `0.2.0_rc.1` as version
  and an empty prerelease (nfpm drops the prerelease from Arch pkgver). rpm system-bus dependency is `dbus`, not
  `dbus-daemon` (evidence in docs/findings.md). `mise.lock` excluded from check-files (lockfile, 28 KB).
  Arch `.INSTALL` is Bash (`function`), source it with bash. bsdtar shows numeric owner `0 0` for Arch files.
  rpm queries need `--dbpath <tmpdir>` as a plain user.
- Not done: steps 5-11 (gate parts a and b, `package` recipe, remove cargo-deb incl. Cargo.toml metadata/data/debian/
  mise.toml/lock/Containerfile cargo-binstall list, shell_scripts, decisions.md, final verify). cargo-deb is still
  everywhere; `just package` still calls it (nfpm.yaml is ready; `NFPM_VERSION=0.1.0 NFPM_PRERELEASE= nfpm package ...` works).
- Next session should: start step 5 (tests first for `scripts/check-packages.sh`), using the fixture library.

### 2026-10-30 — F36 — attempt 1 (session 2)
- Done: step 5. `scripts/check-packages.sh [DIR [CONFIG]]` (tool check, extraction, calls) + `scripts/check_packages.py`
  + `scripts/package_expected.py` (explicit file list, override allow-list); `scripts/test-check-packages.sh` in
  `package-gate-test`; `fx_mix` in the fixture library. `just check` green.
- Decisions: nfpm writes numeric 0/0 for Arch files whatever `file_info` says, so owner/group cases for Arch are caught
  by the config check (test uses the edited config there). nfpm refuses duplicate destinations itself, so that case
  feeds the gate good packages plus a bad config. `config` type shows as conffiles (deb) / `backup =` (Arch) / dump flag (rpm).
  Gate arguments: PKG_DIR then CONFIG; helper gets an extraction dir (`deb`, `rpm`, `arch`, `deb-control`, `rpmdb`).
- Not done: steps 6-11. Part (a) tests were not run against a failing stub first (negative cases all assert failure).
- Next session should: step 6 (deps, NEEDED table, scripts set, versions, missing-tool tests) in
  `scripts/test-check-packages-deps.sh`, extending `check_packages.py`/`package_expected.py`.

### 2026-10-30 — F36 — attempt 1 (session 3)
- Done: step 6. `scripts/test-check-packages-deps.sh` (deps, NEEDED, script set, versions, six missing tools) in
  `package-gate-test`; gate extended in `check_packages.py`/`package_expected.py`; fixture ops `script-add`, `fx_require`,
  `fx_elf_needed`. Tests were seen failing against the part (a) gate first. `just check` green.
- Decisions: libc and libgcc are always required (listed in `DEPS`) besides the NEEDED-mapped ones; the gate also fails when
  the three packages differ in version (`~` and `_` equal) or the revision is not `-1`. `CHECK_PACKAGES_SKIP_TOOL_CHECK=1`
  skips the shell tool loop so tests reach the helper's missing-tool message (rpm, readelf).
- Not done: steps 7-11. Step 7 must add any extra `NEEDED` soname of the release binaries to `NEEDED` (findings: only
  libgcc_s, libc, ld-linux so far).
- Next session should: step 7 (`package` recipe, version override, e2e/manual-acceptance paths).

### 2026-10-30 — F36 — attempt 1 (session 4)
- Done: step 7. `just package [version]` (accepts `0.1.1` or `version=0.1.1`): release build, version from the custodiod
  package metadata or the override, `target/packages` cleaned, three nfpm builds (Arch gets `X_pre` as version), then
  `scripts/check-packages.sh`. Real binaries need only libc, libgcc_s, ld-linux, so the NEEDED table is unchanged. Checked
  0.1.0, 0.1.1 and 0.2.0-rc.1 builds; Cargo files untouched. `e2e/run.sh`, `docs/manual-acceptance.md` use `target/packages`;
  the e2e `find` is tested in `scripts/test-check-packages.sh`. `just check` green.
- Not done: steps 8-11 (remove cargo-deb everywhere, shell_scripts + test, decisions.md, final verify).
- Next session should: step 8.

### 2026-10-30 — F36 — attempt 1 (session 5)
- Done: steps 8-11. cargo-deb removed (Cargo.toml metadata, data/debian, mise.toml/lock, Containerfile, docs);
  `scripts/list-shell-scripts.sh` (shebang or `.sh`) is the `shell_scripts` recipe value, `scripts/test-shell-scripts.sh`
  (seen failing first) runs as `shell-scripts-test` in `check`; decisions.md entry. `just check` and `just package`
  green, `verify` and the evidence greps pass, `version=0.1.1` rebuild leaves one of each.
- Not done: nothing known.
- Next session should: nothing for F36; the evaluator decides.

### 2026-10-30 — F36 — attempt 2 (session 6)
- Fixed NEXT_FINDINGS: removed the committed `scripts/__pycache__/*.pyc`, added `__pycache__/` to `.gitignore`, and
  `scripts/check-packages.sh` now runs `python3 -I -B`, so a gate run writes nothing into the tree. CI step runs
  `shell-scripts-test` as well.
- Disclosure: step 5 is ticked without the evidence of a stub `scripts/check-packages.sh` that exits 1 (not done in
  session 2); the negative cases assert failure and the good set asserts success, so the tests discriminate.
- Next session should: nothing for F36; the evaluator decides.

### 2026-10-30 — F37 — attempt 1 (session 1)
- Done: all five steps. `packaging/glibc-ceiling.txt` (ceiling 2.39 and six targets with sources), `packaging/parity-exceptions.txt`
  (no entries), `scripts/check-glibc-ceiling.sh` + `check_glibc_ceiling.py`, `scripts/check-parity.sh` + `check_parity.py`,
  shared `scripts/package_tree.py`, tests `test-glibc-ceiling.sh` and `test-check-parity.sh` in `package-gate-test`
  (fixture ops `link` and `dir` added to `nfpm_edit.py`, `elf_patch.py` for the byte patches), recipes `package-parity`,
  `glibc-ceiling`, `package-gates` (in `check-slow`), two named steps in the CI `package` job. `just check`, `just package`,
  both gates and `package-gates` pass; mutating the numeric compare and the exception scoping makes the tests fail.
- Decisions: exception line format `PATH | PACKAGES | FIELD | REASON`; named packages may deviate, the others must agree.
  Findings are in docs/findings.md. CI actionlint/zizmor ran within `just check` locally (green).
- Not done: nothing known. The `GLIBC_PRIVATE` fixture is not yet proven on the ubuntu-24.04 runner (CI will).
- Next session should: nothing for F37; the evaluator decides.

### 2026-10-30 — F38 — attempt 1 (session 1)
- Done: step 1. `packaging/lint/pins.txt`, research in docs/findings.md. rpmlint outcome (b) (Debian 2.7.0 vs Fedora 2.8.0-2.fc44);
  namcap branch 2 (container only); lintian_profile = lintian package version.
- Not done: steps 2-7. BLOCKED.md: no root and no container runtime in the session, so no linter can run.
- Next session should: read BLOCKED.md; once a runtime exists, step 2.

### 2026-10-30 — F38 — attempt 1 (session 2)
- Done: steps 2-7. `scripts/package-lint.sh` + `package_lint.py` (host linter at the pin, else a container; every line parsed; lists
  `packaging/lint/{lintian,rpmlint,namcap}.txt`, all with reasons), `package-lint` in `package-gates`, CI step, `rpmlint-empty.toml`, dev image
  installs lintian at the pin and podman. Packaging fixes: strip, copyright, Debian changelog, man page, LICENSE, short synopsis, rpm group.
  Tests `test-package-lint.sh` (stubs; seen failing against an `exit 0` stub first) and `test-package-lint-lists.sh` in `package-gate-test`.
  `just check`, `just package`, `just package-lint` and `just package-gates` pass; `reports/package-lint-container.txt` holds the container run.
- Outcomes: rpmlint outcome (b) (always the Fedora 44 container, none in the dev image); namcap branch 2 (container only); lintian host once
  the dev image is rebuilt. The dev container lost podman between sessions: reinstall with `sudo apt-get install podman uidmap` and the
  `~/.config/containers` files of docs/findings.md. Nested rootless podman needs `--user 0:0` (the gate picks it when `/etc/subuid` has no entry).
- Contract amendment (commit 3541d16, for the evaluator): literal `hardening-no-fortify-functions` entry for the daemon path, `--user` rule,
  namcap `-m`. Path question: namcap and rpmlint draw no path finding on `/usr/lib/custodio/custodiod` (docs/findings.md).
- Disclosure: the dev image (`harness/Containerfile`) change was checked by running its lintian lines in a Debian container, not by a full
  image build. Package changes added files to all three packages (`package_expected.py`, fixtures updated). `git commit -- <path>` breaks the
  commit hook (GIT_INDEX_FILE leaks into test-shell-scripts); commit with the index instead.
- Next session should: nothing for F38; the evaluator decides.

### 2026-10-30 — F38 — attempt 2 (session 3)
- Fixed NEXT_FINDINGS: the contract body now states the two literal lintian path entries, the exact `--user 0:0` condition (podman, non-root,
  no subuid entry) and namcap `-i -m`, with matching Evidence (committed alone as the amendment). Added tests that `0:0` is not passed to a
  caller with a subuid range (`PACKAGE_LINT_SUBUID` overrides the file in tests). `just check` green.
- Next session should: nothing for F38; the evaluator decides.

### 2026-10-30 — F38 — session 4 (BLOCKED.md answered: option 1)
- Applied the person's answer only: contract path rule now lists ten literal (linter, tag, subject) pairs (commit ce6fdae, alone). The lists
  hold exactly those entries for the path (no `*` covers it); the gate sorts bracketed lists in namcap subjects (namcap's order varies per run)
  and treats `[` as literal in a glob. `test-package-lint-lists.sh` now reads every finding naming the path in the committed
  `reports/package-lint-container.txt` (force-added; `reports/.gitignore` ignores `*`) and asserts exactly the decided pairs, each covered by one literal entry.
  Report regenerated: `PACKAGE_LINT_FORCE_CONTAINER=1 just package-lint` exit 0, 56 findings, 0 stale.
- Next session should: nothing for F38; the evaluator decides.

### 2026-10-30 — F38 — session 5 (re-verification after an empty attempt)
- No code change needed: all contract steps were already ticked and committed. Re-ran `just check`, `just package` and
  `just package-lint` on a clean tree: all exit 0 (56 findings, 56 excepted, 0 stale).
- Outcomes (as stated before): rpmlint outcome (b) (Fedora 44 container always), namcap branch 2 (container only), lintian host in the dev image.
- Next session should: nothing for F38; the evaluator decides.

### 2026-10-30 — F38 — session 6 (NEXT_FINDINGS fixes)
- Fixed all four findings: (1) `packaging/deb/postinst` reloads the bus with `deb-systemd-invoke reload dbus.service`, so the lintian
  `maintainer-script-calls-systemctl` entry is gone (55 findings, 0 stale; `test-package-scripts.sh` stubs the new call); (2) the
  `docs/findings.md` paragraph on the daemon path lists the ten findings and cites option 1; (3) the reason check in
  `test-package-lint-lists.sh` now reads through process substitution, so it can fail; (4) a host rpmlint/namcap whose printed version is only
  the upstream part is accepted only when `rpm -q`/`pacman -Q` reports the full pin (test with another release added).
- `reports/package-lint-container.txt` regenerated. `just check`, `just package`, `just package-lint` pass.
- Next session should: nothing for F38; the evaluator decides.

### 2026-10-30 — F38 — session 7 (NEXT_FINDINGS fixes)
- Fixed both findings in `scripts/test-package-lint.sh`: the stale `rpmlint.txt` entry is cleared after the "listed only in the rpmlint
  list" case, and every negative list case asserts `(NOT excepted)`; added a namcap case where an unsorted bracketed list is covered by
  the sorted literal entry (and an unsorted entry is not). Mutations (`covers` always true, prefix glob, no `sort_lists`) now fail the suite.
- Next session should: nothing for F38; the evaluator decides.

### 2026-10-30 — F39 — session 1
- `caller_from` now needs `ProcessFD` (borrowed from the map, no dup) and cross-checks the `Pid:` line of `/proc/self/fdinfo/<fd>` against
  `ProcessID` (`check_pidfd_info`); any failure is `CredentialsError::Missing` → `AuthorizationUnavailable`, polkit not asked. Safe code only.
- Tests: unit (`credentials/tests.rs`), `tests/audit.rs` (no fd, wrong type, other process's pidfd, journal wire value), `tests/fd_leak.rs` (own binary).
- Optional "why" field: not added (conservative); `docs/audit.md` only extends the outcome's meaning text.
- `just check`, `just test-integration`, `just mutants` pass; zero missed/timeout in `target/mutants`.
- Next session should: nothing for F39; the evaluator decides.

### 2026-10-30 — F39 — session 2 (NEXT_FINDINGS fix)
- `sign_refused_with_pidfd_of_another_process` now opens the parent's pidfd up front with `?` and asserts the parent pid differs from
  ours, so it cannot pass as a copy of the no-`ProcessFD` test. Test-only change; `just check` and `just test-integration` pass.
- Next session should: nothing for F39; the evaluator decides.

### 2026-10-30 — F40 — session 1
- F39's cross-check stays (docs/findings.md M1.2); no unit change, no decisions.md entry. Added: unit tests for reaped child (own pid and old
  pid → `Missing`) and zombie (accepted, recorded as current behaviour); `tests/audit.rs` comparisons of mismatch vs missing `ProcessFD`
  (error name, message, `asked()`, whole entries; parent's pidfd and reaped pidfd) and a journal wire test; fd_leak covers both paths;
  `unit-hardening` gate (`scripts/check-unit-hardening.sh`, in `system-gates`) with `scripts/test-check-unit-hardening.sh` in `shell-scripts-test`.
- Manual removal of the `check_pidfd_info` call: failing tests were `credentials::tests::{pidfd_of_another_process_is_refused,
  pidfd_of_reaped_child_is_refused, pidfd_of_reaped_child_is_refused_for_own_pid, process_fd_that_is_not_a_pidfd_is_refused}`, audit
  `{mismatch_is_refused_identically_to_missing_process_fd, reaped_pidfd_is_refused_identically_to_missing_process_fd,
  mismatching_pidfd_reaches_the_journal_as_authorization_unavailable, sign_refused_with_pidfd_of_another_process}` and fd_leak
  `credential_reading_leaks_no_fd`. Call restored.
- `just check`, `just test-integration`, `just mutants` pass (0 missed, 0 timeout). Not exercised under the unit's hardened /proc (see contract).
- Next session should: nothing for F40; the evaluator decides.

### 2026-10-30 — F40 — session 2 (NEXT_FINDINGS fixes)
- `check-unit-hardening.sh` now accepts `Key = value` (counts `^\s*Key\s*=`, normalizes whitespace before the exact match);
  `test-check-unit-hardening.sh` inserts duplicates inside `[Service]` (before `[Install]`) and adds spaced variants for all three keys.
- `tests/audit.rs`: a failed pidfd clone now panics via `insert_pidfd` (justified `#[allow(clippy::expect_used)]`).
- `just check`, `just test-integration`, `just mutants` pass (0 missed, 0 timeout).
- Next session should: nothing for F40; the evaluator decides.

### 2026-10-30 — F41 — session 1
- Outcome A applied. A subagent read polkit tag `124` (commit 82f0924) and Ubuntu noble `policykit-1 124-2ubuntu1.24.04.4`: links 1-4
  verified, link 5 is a visible non-pinned PID path; noble patches touch none of the cited code. Result in `docs/findings.md` section 3a
  (`Verdict: A`); the section 3 "not pinned down" sentence is corrected. Nothing else changed: packages keep `>= 124`, no `BLOCKED.md`.
- Ubuntu 24.04 stays "Only with dbus-broker installed" (dbus-daemon 1.14.10 has no `ProcessFD`, inferred). Step 4/5 (outcome B) do not apply
  and stay unticked.
- Limit recorded in the findings: `check_authorization_sync` was not traced line by line.
- `just check` and the `verify` command pass.
- Next session should: nothing for F41; the evaluator decides.

### 2026-10-30 — F41 — session 2
- Nothing to build: outcome A holds, so contract steps 4 and 5 (outcome B only) are marked `- [-]` and skipped. `verify` passes, one
  `Verdict: A`, no "not pinned down", no `BLOCKED.md`, `packaging`/`e2e`/`docs/milestones.md` untouched, `just check` passes.
- Next session should: nothing for F41; the evaluator decides.

### 2026-10-30 — F42 — session 1
- Done (all eight steps): the check is `packaging/bus-check.sh` (busctl, else dbus-send; `GetConnectionCredentials` on the bus itself, `ProcessFD`
  read only from a successful reply); `scripts/embed-bus-check.sh` writes deb `preinst`, rpm `pre`, Arch `pre_install`/`pre_upgrade` and the hook
  script `packaging/arch/custodio-bus-check`; `scripts/check-bus-check-sync.sh` (+ its test) fails on any drift. Arch also ships
  `custodio-bus-check.hook` (PreTransaction, AbortOnFail, Upgrade of `custodio`) via nfpm `packager: archlinux`; `package_expected.ARCH_ONLY_FILES`,
  two parity exceptions and four namcap exceptions (all with reasons) cover them; gates/fixture tests updated for the new scripts.
- Tests: `just test-scripts` (new, in `check`): `test-bus-check.sh` (source and scripts extracted from fixture packages, dash/bash, private dbus-daemon,
  stub bus `scripts/lib/stub-bus.py` with/without/error, absent socket, dead socket, no tool, dbus-send only, default address trace, fake os-release in a
  mount namespace) and `test-install-real.sh` (real `dpkg`, `rpm -i/-U` in a chroot of a user namespace; `pacman -U` in the Arch image). Mutants of the
  check (`|| true`, no rc test, wrong down-detection, missing AbortOnFail) fail the suite. `docs/findings.md`: deb/rpm answers; `docs/decisions.md`: missing tool.
- Decisions: socket present but neither busctl nor dbus-send => refuse. The Arch cases fail (not skip) without a container engine unless
  `CUSTODIO_SKIP_ARCH_INSTALL=1`; `verify` ran them (no SKIPPED line). Check messages are format-neutral (no "nothing was installed", since Arch goes on).
- For a person: SPEC.md and the F42 line of features.json say the installation fails on a bus without ProcessFD; on Arch the first installation only warns
  (pacman ignores pre_install) and the hook refuses later upgrades/reinstalls. CI (`.github/workflows/ci.yml`) was not changed to run `test-scripts`:
  it needs user namespaces and a container engine, which ubuntu-24.04 runners may restrict (AppArmor); decide whether to add it.
- No Rust changed, so `just mutants-diff F42` has nothing to mutate. `just check`, `just test-scripts`, `just package`, `just package-lint` pass.
- Next session should: nothing for F42; the evaluator decides.

### 2026-10-30 — F43 — session 1
- Done (all seven steps): deb `preinst` (F42 check, then `systemd-sysusers -` from sysusers text embedded by `scripts/embed-bus-check.sh`, kept equal to
  `data/sysusers.d/custodio.conf` by `scripts/check-sysusers-sync.sh`; on upgrade notes `is-active` in `/run/custodio-restart-after-upgrade`), `postinst`
  (daemon-reload, bus reload, catalog, one restart only with an old version and the marker), `prerm` (stop on remove), `postrm` (remove = purge: reloads, second
  stop if active, notice on stderr). `systemd` moved to the deb's `Pre-Depends` (top-level `deb.predepends` in nfpm.yaml); `check_packages.py` reads the field
  separately (`package_expected.PRE_DEPS`), fixtures `predep-*` in `nfpm_edit.py`. Gates/fixtures for the four scripts updated (inverted, not dropped).
- Tests in `test-scripts`: `test-sysusers-sync.sh`, `test-deb-scripts-static.sh` (state-path allowlist with reasons, forbidden commands), `test-deb-lifecycle.sh`
  (every action; call lists in its header; 19 mutants; 7 control scripts proving the state check sees `rm`, redirections, chmod, cat), `test-deb-lifecycle-real.sh`
  (real dpkg in a user namespace: install, upgrade from a fixture that looks like the cargo-deb 0.1.0-1 package, remove, purge; 5 mutants incl. account in postinst).
  `test-bus-check.sh` and `test-install-real.sh` needed only fixture changes (stubs on PATH / `rm`, `journalctl` in the root), not the assertions.
- Decisions in `docs/decisions.md`: edited the F42 ProcessFD entry (Pre-Depends no longer rejected; the check is not changed to use busctl from systemd); new
  entries for Pre-Depends + `useradd` fallback rejected, and for the marker, stderr notice, purge printing twice.
- Contract note: the evidence names `/etc/dbus-1/system.d/...` as the bus policy; the package ships it at `/usr/share/dbus-1/system.d/...` and the test uses that.
- A `postinst configure OLD` after a first install of the same version number as the cargo-deb one (both 0.1.0-1) is a reinstall for dpkg; the real-dpkg
  test uses 0.1.1 for the nfpm package. No Rust changed, so `just mutants-diff F43` has nothing to mutate.
- `just check`, `just package`, `just package-lint` pass (`test-scripts` ran inside `check`).
- Next session should: nothing for F43; the evaluator decides.

### 2026-10-30 — F44 — session 1
- Done (steps 1-8): rpm scriptlets `pre` (F42 check, then `systemd-sysusers -` from the embedded sysusers text, then the restart marker in `/run` on `$1 -ge 2`),
  `post` (daemon-reload, `reload dbus.service`, catalog, one restart only with `$1 -ge 2` and the marker), `preun 0` (stop), `postun 0` (reloads, stop if active,
  notice on stderr, same text as the deb); upgrades do nothing in `preun 1`/`postun 1`. No macros, no `%posttrans`, no `user()` provide. `scripts/embed-bus-check.sh`
  renders the rpm `pre` and shares the account function with the deb; `check-sysusers-sync.sh` checks both copies. Research and decisions: `docs/findings.md`
  ("F44: rpm scriptlets"), `docs/decisions.md`.
- Amendment (commit alone): nfpm cannot write `Requires(pre)`; the plain `Requires: systemd` orders it. The evaluator should look at it.
- Tests in `test-scripts`: `test-rpm-scripts-static.sh` (state-path allowlist, forbidden commands, macros in source and in `rpm -qp --scripts`, controls),
  `test-rpm-lifecycle.sh` (every `$1`, offline variants with read-only `/var` and `/run`, parity with the deb scripts, 7 controls, 38 mutants),
  `test-rpm-lifecycle-real.sh` (real `rpm --root` in a user namespace: logging package proves the `$1` rpm passes, install, upgrade from this tree and from an F42-era
  package, active and inactive, erase, offline, refusing bus, failing sysusers, 11 mutant packages incl. account moved to `%post` seen as "present").
  Gates updated (inverted): `RPM_SCRIPTS`, `test-package-scripts.sh`, `test-check-packages-deps.sh`. rpmlint: two exceptions for `rm -f` of the marker.
- **BLOCKED.md written**: `rpm-ostree uninstall` runs no scriptlet of the removed package, so the notice SPEC asks for has no mechanism (options in the file). The last
  step and the evidence item "rpm-ostree uninstall meets SPEC" stay open. The evaluator's note 1 (rpmdb version) is followed: the order of the call log is the evidence.
- For a person: the deb `preinst` writes its marker with `: > file || true`, which ends a dash `sh` when `/run` is read-only (documented in findings); F43 was
  not changed. No Rust changed, so `just mutants-diff F44` has nothing to mutate.
- `just check`, `just package`, `just package-lint` pass (`test-scripts` ran inside `check`).
- Next session should: nothing until BLOCKED.md is answered.

### 2026-10-30 — F44 — session 2
- BLOCKED.md was answered (deviation recorded in `SPEC_DEVIATIONS.md`, contract amended). Last step done: ran `verify` in full: `just check`,
  `just test-scripts` (no SKIPPED line), `just package`, `just package-lint` (61 findings, all excepted, 0 stale) pass. No Rust changed, so no mutants-diff.
- Next session should: nothing for F44; the evaluator decides. A person reviews the pending F44 deviation before the milestone closes.

### 2026-10-30 — F44 — session 3
- Fixed NEXT_FINDINGS: `test-rpm-scripts-static.sh` now fails if the built rpm has a `user(`/`group(` provide, with controls built via the new
  `provides-add` op of `nfpm_edit.py` (a `user(custodio)` and a `group(custodio)` fixture must be seen; also checked by hand against nfpm.yaml). Stale
  `BLOCKED.md` pointers in `docs/decisions.md` and `docs/findings.md` now point to the F44 entry of `SPEC_DEVIATIONS.md`.
- `just check`, `just test-scripts` (no SKIPPED), `just package`, `just package-lint` (0 stale) pass. No Rust changed.
- Next session should: nothing for F44; the evaluator decides.

### 2026-10-31 — F58 — session 2
- Kept the stopped session's work after checking it: `pre_install`/`pre_upgrade` (F42 check, account from the embedded sysusers text, then exit 1 if either failed),
  `post_install`/`post_upgrade` do nothing (systemd's `30-systemd-daemon-reload-system`, dbus's `dbus-reload` and `25-systemd-catalog` already do the reloads and the
  catalog once), `pre_remove` stops, `post_remove` stops if active and prints the notice on stderr. Restart on upgrade is the new PostTransaction hook
  `zz-custodio-restart.hook` (`systemd-hook restart` = `try-restart`, sorts after `dbus-reload`). Research in `docs/findings.md`, decision in `docs/decisions.md`.
- Tests in `test-scripts`: `test-arch-lifecycle.sh` (stubs, mutants, controls; both-failing case), `test-arch-scripts-static.sh`, `test-arch-lifecycle-real.sh` (real
  `pacman -U/-R/-Rns` in the Arch image, upgrade from a build of `cd5afb6`, refusing bus, failing sysusers, mutant packages). Sysusers sync gate covers the Arch scripts;
  package gates, parity and namcap lists updated. The real test needs commit `cd5afb6` in the clone (fails in a shallow one).
- `just check`, `just test-scripts` (no SKIPPED), `just package`, `just package-lint` (0 stale) pass. No Rust changed, so `just mutants-diff F58` has nothing to mutate.
- Next session should: nothing for F58; the evaluator decides.

### 2026-10-31 — F58 — session 3
- Fixed NEXT_FINDINGS: (1) `test-arch-scripts-static.sh` checks that the F58 entry of `docs/decisions.md` names the owner of every call (the three hooks, `systemd-sysusers -`
  in `pre_*`, `pre_remove`, `zz-custodio-restart.hook`, `try-restart`), with a control per name that deletes it from a copy; (2) the entry is cut to the format of the file;
  (3) `arch-real-steps.sh` records any `*.wants/custodio.service` link and the real test asserts none after the first install, with a new mutant that enables by `ln`.
- `just check`, `just test-scripts` (no SKIPPED), `just package`, `just package-lint` (0 stale) pass. No Rust changed.
- Next session should: nothing for F58; the evaluator decides.

### 2026-10-31 — F45 — session 1
- Built steps 1-7: `e2e/run.sh [target]` (default `all`; validates the name before touching the engine; builds the target's Containerfile, runs it privileged with the
  package mounted read-only at `/pkg`, `e2e/` at `/e2e` and the target dir at `/e2e-target`, execs the shared `guest.sh`, checks the cases, saves `target/e2e/<t>.record`;
  a failed target does not stop the others). `just e2e target="all": package`. Target `debian13`: Containerfile (moved; `-o APT::Sandbox::User=root` added for the
  single-uid dev container), `skip.list` (empty), `package.pattern`, `install.sh` (`dpkg -i`), `probe.sh` (bus daemon asked of the bus via `GetConnectionUnixProcessID`, polkit
  version from `pkaction`). Cases: every `echo "ok: ..."` became `case_run ID` (`e2e/report.sh`, prints `E2E-CASE run ID`); `e2e/cases.list` is the known list;
  `e2e/check-cases.sh` lints skip lists (`case: reason`) and fails on a missing, unknown, duplicated or unlisted-skipped case (unused entries: stderr, exit 0).
- Tests in `test-scripts`: `test-e2e-skips.sh` (format, enforcement a-e, accounting), `test-e2e-host.sh` (stub podman: order of calls, read-only mount, record, `all` with fake
  targets, failure isolation, omitted/unknown/duplicated/unlisted-skip through the host, Containerfile and guest greps, shellcheck list). `test-check-packages.sh` now reads the
  `find` line of `e2e/run.sh` with a control. Mutants tried by hand: dropping the accounting call, `--privileged`, and two messages of check-cases were all caught.
- Amendment (own commit): step 4 and the grep sentence, as the evaluator's notes asked.
- **BLOCKED.md written**: the real run is impossible in this dev container (finding "F45: a systemd container cannot boot…"). The last step stays open.
- `just check` passes. No Rust changed, so no mutants-diff.
- Next session should: nothing until BLOCKED.md is answered.

### 2026-10-31 — F45 — session 2
- BLOCKED.md answered: the dev container was restarted (SYS_ADMIN, unmasked /proc, systemd mode; d55f9ac). Real run done, nothing else changed.
- `just e2e debian13` exit 0 and `just e2e` (all; only target `debian13` exists yet) exit 0: "e2e: passed: debian13", 28 cases accounted for by `check-cases.sh`,
  none skipped, journal entries ok, no secret leaks.
- Record `target/e2e/debian13.record`: `target=debian13`, `bus-daemon=dbus-daemon`, `bus-daemon-version=D-Bus Message Bus Daemon 1.16.2`, `polkit-version=126`.
- Last contract step ticked. No code changed.
- Next session should: nothing for F45; the evaluator decides.

### 2026-10-31 — F45 — session 3
- F45 was already committed (c1eb94a) with the real run recorded. Kept the stopped session's two small environment fixes: `package_lint.py` reads the user name from `pwd`
  (not `$USER`) for the subuid check; `test-rpm-lifecycle.sh` removes each case's root so a small /tmp does not fill.
- `just check` and the rest of `verify` pass. No Rust changed.
- Next session should: nothing for F45; the evaluator decides.

### 2026-10-31 — F59 — session 1
- Catalog check: `journal.py catalog` (the one function; the guest case in `e2e/journal-check.sh` runs `journalctl -x -u custodio.service MESSAGE_ID=... -n 1`
  since the start of the run and never `--update-catalog`), case `journal-catalog` in `cases.list`. The matched text is `e2e/catalog-text.txt`;
  `scripts/test-e2e-catalog.sh` (in `test-scripts`) has fixtures (UTF-8 and C-locale markers, entry without explanation, partial text, no entry, text without
  entry, empty), checks the text against BOTH entries of `data/custodio.catalog` (unmarked and `en`), and the wiring.
- `scripts/test-e2e-host.sh`: per-target checks are a loop over `e2e/targets/*` (`target_problems`); `ubuntu*` must `apt`/`apt-get install "$1"`; control with a
  dpkg-only fixture; the shellcheck list covers every target's `install.sh` and `probe.sh`.
- Target `ubuntu2604` (Containerfile from `docker.io/library/ubuntu:26.04`, `install.sh` with `apt-get install`, probe, pattern, empty `skip.list`).
- Two suite fixes the real Ubuntu run needed (neither weakens a check): `user.sh` uses `ls -L` and `cd` for the unreadable state dir (uutils `ls` of Ubuntu 26.04
  exits 0 on a symlink whose target it cannot open); `agent.py` talks to polkit 127's socket-activated helper (`/run/polkit/agent-helper.socket`, first line the
  user) when `polkit-agent-helper-1` is not setuid.
- Findings: `docs/findings.md` "Journald default storage on debian13 and ubuntu2604" (debian13 `auto`, ubuntu2604 `persistent`; `/var/log/journal` exists on both; no warning needed).
- Real runs: `just e2e ubuntu2604` exit 0, 29 cases accounted for, all run, none skipped (incl. `journal-catalog`); `just e2e debian13` exit 0, 29 cases;
  `just e2e` exit 0 ("passed: debian13 ubuntu2604"). `target/e2e/ubuntu2604.record`: `target=ubuntu2604`, `bus-daemon=dbus-daemon`,
  `bus-daemon-version=D-Bus Message Bus Daemon 1.16.2`, `polkit-version=127`. debian13: dbus-daemon 1.16.2, polkit 126.
- `just check` and the rest of `verify` pass. No Rust changed, so no mutants-diff.
- Next session should: nothing for F59; the evaluator decides.

### 2026-10-31 — F59 — session 2
- Fixed NEXT_FINDINGS: (1) `scripts/test-e2e-host.sh` now loops over `e2e/targets/*` for the build/run/exec shape, the read-only mount and the record (so the real
  `ubuntu2604` directory goes through `e2e/run.sh` with the stub), runs `all` on the real targets directory (both must run), and expects "available targets: debian13 ubuntu2604";
  (2) `scripts/test-e2e-catalog.sh` has `split_check CATALOG`; the controls change only the first entry, then only the last, and `split_check` must reject both;
  (3) per-case results from the real runs (`target/e2e/<t>.log`), both targets, 29 `E2E-CASE run` lines each, none skipped:
  `no-key-read pkcs11-tool-approve-rsa pkcs11-tool-deny pkcs11-tool-asks-again pkcs11-tool-approve-ecdsa nss-approve nss-deny nss-asks-again composed-SHA256-RSA-PKCS
  composed-SHA384-RSA-PKCS composed-SHA512-RSA-PKCS composed-SHA256-RSA-PKCS-deny composed-ECDSA-SHA256 composed-ECDSA-SHA384 composed-ECDSA-SHA512 composed-ECDSA-SHA256-deny
  provider-rsa1 provider-ec1 provider-several-updates provider-deny login-approve-rsa login-approve-ecdsa login-asks-again login-deny login-context-specific
  journal-signatures polkit-unavailable journal-entries journal-catalog`. Records: ubuntu2604 `dbus-daemon` 1.16.2, polkit 127; debian13 `dbus-daemon` 1.16.2, polkit 126.
- `just check`, `bash -n e2e/*.sh` and the file greps of `verify` pass. Only test scripts changed; no Rust, so no mutants-diff.
- Next session should: nothing for F59; the evaluator decides.
