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

### 2026-11-03 — F108 — attempt 1
- Done: `## F108` in `docs/findings.md`, run in the debian13 container under rootless podman (booted `degraded`: only kernel mounts and
  `systemd-modules-load` fail). `Decision: route 2` (swtpm on a unix socket, test-only drop-in in `/run/systemd/system/custodio.service.d/`).
- Route 1 (vtpm proxy): no `/dev/vtpmx`, no `tpm_vtpm_proxy` module, no root; needs a host change (load the module, pass the device in).
  Not needed, so no `BLOCKED.md`; a real `/dev/tpmrm0` stays for F109 (device questions) and F111.
- Facts for F109: a host AppArmor profile `swtpm (enforce)` confines swtpm in the container: socket and state only under `/tmp` and `/var/tmp`,
  and it cannot be signalled (stop with `swtpm_ioctl -s`). The unit's `PrivateTmp` is passed with `BindReadOnlyPaths=/tmp/f108-tpm`; the TCTI
  needs `<sock>.ctrl` next to the socket, both `mode=0666` for the dynamic user. The shipped sandbox let `tpm2_getcap` through (33 algorithms).
  The F107 filter has no CLI: a scratch wrapper (not committed) ran it; F109 should add an example to `custodio-it`.
- Evidence in the finding: PCR 16 extend equals the precomputed value, read by the shell and by the unit; restart gives PCR zero (as expected)
  with a persistent handle and its name unchanged; clear removes it and changes the owner seed; drop-in negative control and `dpkg -L` = 0
  against the real deb. Other targets are inferred, with the F109 check for each.
- Not done: other targets, SELinux, hardware. `just quick` green, the `verify` passes.

### 2026-11-03 — F109 — attempt 1
- Done: `## F109` in `docs/findings.md`, run as real units under each of the six e2e containers' own systemd (stand-in (a) `/dev/null` as
  `/dev/tpmrm0`, (b) a `root:tss 0660` regular file). `Decision:` keep `PrivateDevices=yes`, add `DeviceAllow=/dev/tpmrm0 rw`,
  `BindPaths=-/dev/tpmrm0`, `SupplementaryGroups=tss`; score 0.7 (threshold 1.0), `PrivateDevices=no` would be 0.8. No `BLOCKED.md`.
- Findings: plain `BindPaths=` makes the unit fail 226/NAMESPACE without a TPM, hence the `-`; a missing `tss` group fails the unit (216/GROUP),
  so the packages must depend on `tpm-udev`/`tpm2-tss` (or sysusers `g tss -`); owner is `tss:tss` on the Debian family, `root:tss` elsewhere;
  group access works under `PrivateUsers=yes` on all six.
- Not verified (left to F147): `DeviceAllow=` effect (the control C0 still opens in rootless containers, so *inferred*), a real node's owner,
  SELinux on fedora44/alma10. Nothing in `data/`, recipes or Containerfiles changed; applying the Decision is for a later feature.

### 2026-11-03 — F110 — attempt 1
- Done: `## F110` in `docs/findings.md`, run as a real probe unit (shipped text, F109 directives, static `custodio` uid) on the six e2e containers, plus the dev container
  (`unshare -m --map-root-user --map-users=auto`, `systemd-socket-activate -a --fdname=varlink`, `setpriv` uid 42, `just with-swtpm` for the explicit-device TPM cases). Six `Decision:` lines.
- Findings: scope `user` + Varlink works without polkit on 257/259/262 (no `--user`/Varlink on ubuntu2404 255); system scope or another uid needs polkit; the Varlink daemon picks the key
  (`auto`) and the PCR mask itself (PCR 7 on 255/257, empty on 259/262); `withKey` (259+) in user scope yields an unscoped or null credential, so never send it; `--tpm2-pcrs=` = no PCR (all six);
  `tpm2` = TPM alone, `host+tpm2` = both. A container never uses the TPM through the daemon (`running in a container`), so the Varlink TPM case is *inferred* from source and left to F147.
- Deviations (pending, `SPEC_DEVIATIONS.md` `## F110`): debian13, alma10 (PCR 7 on a TPM machine, not changeable per call), ubuntu2404 (TPM-alone only). Not security rules of CLAUDE.md.
- Not done / not run: strace inside the unit (needs `ptrace`; run as the uid with `setpriv` instead), strace in the dev container (not installed; the evaluator's note said it was), real TPM, SELinux.
- Next session should: nothing left; the loop runs the verify. F120 uses the Decisions and the read-back guard.

### 2026-11-03 — F115 — attempt 1
- Done: `creds` module in custodiod (`creds.rs` access-point trait + two errors, `creds/systemd.rs` real client, `creds/header.rs` PCR read-back guard);
  host-bound over Varlink, TPM-bound via CLI with explicit `--tpm2-pcrs=`; decrypt returns secrecy/zeroize memory. Three files added to the `mutants` recipe.
- Evidence: `just quick` green; `cargo test -p custodiod --test creds` 12/12; `just mutants-diff F115`: 213 mutants, 149 caught, 64 unviable, 0 missed; each of the three files has caught mutants.
- This session fixed two clippy errors in `creds/systemd/tests.rs` (underscore binding, slicing) and rustfmt.
- Not verified: Varlink+TPM (daemon refuses a TPM in a container) is left to F147, as the contract says.
