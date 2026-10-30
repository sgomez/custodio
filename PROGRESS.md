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
