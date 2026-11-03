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

### 2026-11-03 — F104 — attempt 3 (findings fix)
- Done: NEXT_FINDINGS 1: `with-swtpm.sh` keeps the caller's stdin (`exec 3<&0`, `"$@" <&3 3<&- &`); new test case
  `echo hello | with-swtpm cat` (failed before the fix). Finding 2: the wait for swtpm after the signal fallback is bounded
  (5 s), warns, and the state is removed anyway. Finding 3: stray swtpm from the earlier run is not from current code.
- Verified: `WITH_SWTPM_REQUIRE=1 scripts/test-with-swtpm.sh` passes, `just quick` green.
- Next session: nothing left; the loop runs the verify.

### 2026-11-03 — F105 — attempt 1
- Done: `custodio-it` gets `src/swtpm.rs` (std only, so no regular dependencies) and the target `tests/swtpm_fixture.rs` (9 tests).
  `Swtpm::start/tcti/tool/tool_ok/extend_pcr/restart/clear/pid/state_dir`; stop = `swtpm_ioctl -s` on the control socket,
  `Child::kill` after 2 s as fallback, bounded 5 s wait with `try_wait`; Drop removes the state dir (also on panic).
  Missing tool: error names the tool and package (checked with `PATH` holding only tpm2_* and swtpm_ioctl symlinks).
- Decisions: `tss-esapi` is `=8.0.0-alpha.4`, `default-features = false`, dev-dependency. Why: 7.x only knows `swtpm:host=,port=`
  (`NetworkTPMConfig`), not `swtpm:path=<unix socket>`, so with 7.7 the context fails with an IO error; 8.0 alpha adds
  `TpmSimulatorConfig::Unix`. It pulls `paste` (RUSTSEC-2024-0436, unmaintained proc-macro): commented ignore in `deny.toml`.
  `sha2` added as dev-dependency (PCR chain in the test). Clear evidence compares `-C o` (TPM2_Clear changes the owner seed only).
  swtpm serves one client at a time: drop a `tss-esapi` Context before running a tool on the same instance.
  Tools leave objects in the TPM's few slots: tests run `tpm2_flushcontext -t` after createprimary/readpublic.
- Next session: nothing left if `just quick` and the verify pass.

### 2026-11-03 — F106 — attempt 1
- Done: probe `crates/custodio-it/examples/tpm-probe.rs` (`parent [--tcti]`, read-only, exit 1 when the TPM is unreachable or the
  owner hierarchy unusable, 2 on usage) and `## F106` in `docs/findings.md` with the swtpm experiments (persist, restart via
  `swtpm_ioctl -i` + `tpm2_startup -c` inside `with-swtpm`, clear, owner password `0x9A2`, foreign occupant, load error `0x1DF`).
  Decision: B, primary recreated each use from the ECC P-256 TCG SRK template. `just quick` green, verify passes.
- Not done: hardware TPM run (F111). Template fields beyond the TCG deltas, and "systemd never evicts on removal", are marked inferred.
- Next session should: nothing left; the loop runs the verify.

### 2026-11-03 — F107 — attempt 1
- Done: `tpm-probe mechanisms [--tcti]` (`examples/tpm_probe/mechanisms.rs`): every mechanism both ways on transient keys, verified by
  the `openssl` CLI (never the probe's own padding), negative controls, capability queries, a second-connection `decrypt` experiment;
  exit 1 when a served signature does not verify, 2 on usage. `custodio_it::tpm_filter::TpmFilter` (std only): a proxy in front of
  swtpm that removes algorithms/curves from `GetCapability` and answers `TestParms`/`Sign`/`RSA_Decrypt` with the spec's `TPM_RC_*`
  for a lacking item; tests in `tests/tpm_filter.rs`. `## F107` in `docs/findings.md` ends with `Decision: (b)`.
- Findings: swtpm 0.7.1/libtpms 0.9.2 has no profile; PSS salt = hash length for SHA-256/384/512; (a) cannot serve `CKM_RSA_PKCS`
  with a non-`DigestInfo` payload or other salts; (b) serves all, bytes equal (a) for PKCS; P-256 needs SHA-256 only with the
  truncated hand-over; `decrypt` lets another TPM holder decrypt, `TPM2_Duplicate` still refused (0x124).
- Not done / inferred: hardware TPM run (F111); scheme and curve `TPM_RC_*` codes of the filter are from the spec (only the hash
  code 0x1C3 is measured); null-scheme decrypt on a TPM lacking PSS not run. Lasting choice (b) is for the person in F111, so not
  yet in `docs/decisions.md`. Departures to flag: `decrypt` usage on RSA keys; add "root can also decrypt" to the threat model.
- Next session should: nothing left; the loop runs the verify.

### 2026-11-03 — F107 — attempt 2 (findings fix)
- Done: NEXT_FINDINGS 1: a TPM that refuses `TPM2_Sign` PSS prints `outcome=lacks rc=<code>` per salt and the probe goes on.
  Finding 2: a refused `sign|decrypt` template prints `key: rsa2048 sign|decrypt refused <rc>`, every (b) case is `lacks` with that
  code (`way_b_refused`), (a), capabilities and the sign-only half of the `decrypt` experiment still run. Notes: the 36-byte payload is
  labelled "stand-in" (SHA-256 bytes); the ECC `TestParms ... SHA-1` line is gone; findings text updated to match.
- Also: `just quick` was red from attempt 1 (file size over 5000 tokens, inline tests in `tpm_filter.rs`): `mechanisms.rs` split into
  `mechanisms/support/wayb/caps` modules, filter tests moved to `src/tpm_filter/tests.rs`. `just quick` green, probe exit 0, filter tests 3/3.
- Not verified: the two refusal paths were not run against a TPM that refuses (swtpm accepts both); they are straight error branches.
