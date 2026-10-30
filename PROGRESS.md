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
