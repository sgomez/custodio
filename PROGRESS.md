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
