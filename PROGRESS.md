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

### 2026-11-03 — F104 — attempt 1
- Done: `scripts/with-swtpm.sh` + `just with-swtpm *cmd` (swtpm socket mode, `--flags not-need-init`, `tpm2_startup -c`,
  `TPM2TOOLS_TCTI=swtpm:path=<state>/swtpm.sock`, cleanup on EXIT/INT/TERM/HUP, exits with the command's status).
  `scripts/check-tpm-install-sync.sh` (exempt jobs by name: ci `commits`, `ci`; mutants `report`) and its test
  `scripts/test-tpm-install-sync.sh` with negative controls; `scripts/test-with-swtpm.sh` (missing-tool cases run now;
  real-TPM cases print SKIP, or fail when `CI` or `WITH_SWTPM_REQUIRE=1`). All wired into `just test-scripts`.
  Containerfile and every cargo job of ci.yml and mutants.yml install the four packages with a comment. `just quick` green.
- Not verified (tools absent in this container): the real swtpm run. The swtpm invocation, the `.ctrl` socket naming of the
  TCTI and the Debian/Ubuntu package that carries `libtss2-tcti-swtpm0` (the contract asks to name it if `libtss2-dev` and
  `tpm2-tools` do not pull it in; `apt-cache` was unavailable here) must be checked after the rebuild.
- Next session should (after the rebuild): run `scripts/test-with-swtpm.sh` with `WITH_SWTPM_REQUIRE=1` directly (it is not in
  `just quick`), the contract's "rebuilt container" evidence, and fix the recipe if swtpm/TCTI details differ. If the TCTI module
  is missing, add its package to the Containerfile, the CI steps and PACKAGES in the sync check.

### 2026-11-03 — F104 — attempt 2 (rebuilt container)
- Done: ran the real recipe on the rebuilt container. Finding: in this container `swtpm` cannot be signalled (kill gives EPERM,
  even SIGKILL), so the cleanup hung on `wait`. `scripts/with-swtpm.sh` now stops swtpm with `swtpm_ioctl --unix <sock>.ctrl -s`
  (package swtpm-tools, checked up front) and keeps the signal as fallback. Script test: stubs `swtpm_ioctl` too, and uses
  `set -m` so the SIGINT case is real (background jobs in a script start with SIGINT ignored).
- Verified: `WITH_SWTPM_REQUIRE=1 scripts/test-with-swtpm.sh` passes, sync check passes, the three `with-swtpm` verify commands
  behave, `pkg-config --exists tss2-esys` ok, `just quick` green. The TCTI needed no extra package.
- Next session: nothing left; the loop runs the verify.
