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

### 2026-11-08 — F150 — attempt 1
- Done: `docs/findings/F150.md` (+ index), `scripts/vm-host-check.sh`, `scripts/test-vm-host-check.sh` (in `test-scripts`), `just vm-host-check`,
  Containerfile VM packages (+gpgv), `run.sh` `--device /dev/kvm --group-add keep-groups` when the host has the device. `just quick` green; self-test passes.
- Decisions: host facts and runner are **inferred** (docs only); the "host change needed" step is `[-]`: no host change is known until the person pastes `ls -l /dev/kvm; id`.
  Unconfirmed: `-accel help` listing kvm, `gpgv` package name on trixie (the check will show).
- Not done: the rebuild (a person's); `just vm-host-check` passes only on the rebuilt container. BLOCKED.md written.
- Next session should: after the rebuild, run `just vm-host-check`; mark host facts **verified** from the pasted output; fix the finding if KVM is absent.

### 2026-11-08 — F150 — attempt 2
- Done: container rebuilt (crun); `just vm-host-check` exits 0 here (nine OK lines). Evaluator notes checked: the self-test already uses a regular-file KVM stub and exact `MISSING <label>:` matches; the finding now says its first evidence block is the pre-rebuild container.
- Not done: nothing; the loop runs the `verify`.

### 2026-11-08 — F151 — attempt 1
- Done: `docs/findings/F151.md` (+ index): image/checksum URLs, serial, retention (oldest listed serial 2026-04-23), verified download with negative controls, QEMU command line, serial-console channel with `cloud-localds` seed, guest facts, `has-tpm2` before/after, power cycle with control. All contract steps ticked; `verify` greps pass, `just quick` green.
- Decisions: channel = serial console on a unix socket (no `ssh` in the container); seed tool `cloud-localds`.
- Known: `libtss2-rc0t64` alone leaves `has-tpm2` `partial`; esys and mu are also needed (tpm2-tools pulls them). One idle `swtpm` (pid 32088, from my first failed start) cannot be killed from the tool sandbox (`Permission denied`); it ends with the container. No qemu left; the `/tmp` dir is removed.
- Next session should: nothing for F151; the loop runs the `verify`.

### 2026-11-08 — F152 — attempt 1
- Done: `docs/findings/F152.md` (+ index): 10 guest boots, each with fresh `swtpm` state. Route 1 (`tpm-filter`) cannot sit under QEMU as built (`CMD_SET_DATAFD` carries an fd); with a throwaway adapter it hides capabilities only. Route 2 (`swtpm` 0.10.2 custom profile, unpacked from Debian forky `.deb` in `/tmp`) really lacks: no `0x159` RSA_Decrypt, or `rsa-min-size=3072`; P-256 via `ecc-min-size=384`. Kernel TPM, `systemd-creds` (root and `--user`) and the ECC parent pass; systemd's SRK flips ECC→RSA when P-256 goes. `rsa-min-size=3072` + P-256 removed breaks systemd. `Decision:` is route 2; container/CI add the four forky `.deb` (sha256 in the finding). All contract steps ticked; `verify` greps pass, `just quick` green. No `BLOCKED.md` (RSA gets `encrypted-tpm` without breaking the kernel or systemd).
- Decisions: none lasting beyond the finding.
- Known: two idle `swtpm` (pids 32088, 96049) cannot be killed from the tool sandbox; they end with the container. The service's own capability code was not run in the guest (tpm2-tools issued the same queries).
- Next session should: nothing for F152; the loop runs the `verify`. The VM-harness feature reads the finding (profile files, `ecc-min-size=384`, never combine with `rsa-min-size=3072`).

### 2026-11-08 — F152 — attempt 2
- Done: NEXT_FINDINGS fixed in `docs/findings/F152.md` (+ index line). (1) The api.md reading is corrected: curve and parent rows are "yes" for RSA too, so r2e/r2g (and r1b/r1c) make both key types *lacks*. (2) New boot r2h (fresh state, `swtpm` 0.10.2 profile with `Commands` minus `0x15d` `TPM2_Sign`): P-256 lacks via `command Sign`, RSA stays ready, and the kernel TPM, `systemd-creds` (root and `--user`, SRK ECC), the ECC parent and a child create/load all pass. The Decision now says P-256 gets `encrypted-tpm` by removing `Sign`, never `ecc-min-size=384`. (3) The Leftovers section quotes the real `pgrep` output and the `kill` error. The "TPM parent" decision is named. `verify` greps pass, `just quick` green.
- Known: the two idle `swtpm` (32088, 96049) still cannot be killed from the sandbox. A profile with both `RSA_Decrypt` and `Sign` removed was not booted (marked inferred).
- Next session should: nothing for F152; the loop runs the `verify`.

### 2026-11-08 — F153 — attempt 1
- Done: `docs/findings/F153.md` (+ index): 259.9 source (Ubuntu patches touch no credential file), header table with offsets (id 0, TPM section 48, pk and scoped sections after, scoped header = flags only), nine key ids; 259.9 credentials made in the F151 guest (root CLI, `--user`, Varlink, null, PCR 7, pk forms) and 257.13 in the dev container, all read back and decrypted (pk forms need a signature); negative control; differences from F110 (default mask 0 vs 0x80; CLI `--user` never sends `withKey`, so with a TPM it gets `ef4ac136...`). Decision: live `systemd-creds` in the guest. All steps ticked, `verify` greps and `just quick` pass.
- Known: scoped+pk id and 259 host-scoped-with-daemon are **inferred**. Pids 32088 and 96049 (swtpm) remain from earlier features.
- Next session should: nothing for F153; the loop runs the `verify`.

### 2026-11-08 — F154 — attempt 1
- Done: `nfpm.yaml` (.deb Depends `libtss2-rc0t64` with comment; Pre-Depends `systemd (>= 257)`, comment gives the Varlink reason), `package_expected.py` (`TSS_DLOPEN`, `SYSTEMD`),
  `check_tss_deps.py` now requires every `TSS_DLOPEN` package in the .deb's Depends only (Pre-Depends/Recommends do not count). New helper op `recommends-add`; the
  existing `predep-add` covers the predepends case. `test-check-packages-deps.sh`: three direct `$TSS` cases (removed, recommends only, predepends only), `deb-systemd-too-old` (255),
  `deb-systemd-unversioned`; 255 strings moved to 257. `test-deb-lifecycle-real.sh`: dpkg without `--force-depends` on a status with systemd 255 refuses (output names systemd and 255,
  no custodio files); a 257 root installs. `just quick`, both verify scripts green; the real lifecycle suite passed (~6 s alone).
- Decisions: the lifecycle root's dpkg status lists every other Depends/Pre-Depends name as installed (version 999), so only systemd decides.
- Not done: the contract's evidence wording ("would pass if the script ignored TSS_DLOPEN" should read "would fail") is left as is; contract text is not edited without an amendment.
- Next session should: nothing; the loop runs the `verify`.

### 2026-11-08 — F155 — attempt 1
- Done: `creds/systemd.rs` has only the Varlink route: `SystemdCreds::new(socket)` / `system()`; the CLI run, launcher, `tpm_args`, `Failure`, the route chooser are gone (`decrypt` still reads the header first, so a bad header is `CannotDecrypt` without touching the socket). `header.rs` and `seal` untouched. Unit tests: fake-socket cases assert `Encrypt` scope `user` with no `withKey`, and exactly one `Decrypt` for a TPM header and a host header.
- Tests: removed `descriptor.rs`, `sign_kinds/real.rs`, the `MissingLauncher` row, `the_tpm_command_line_*`, `tpm_bound_round_trip`, `cleared_tpm_cannot_decrypt`. Rebuilt: `TpmClearedUnderCredential` → `TpmCredentialLost` (`MemoryCreds::tpm()` + decrypt fails `CannotDecrypt`), `concurrent_kinds` and `tpm_lifecycle` on `MemoryCreds::tpm()` (`World::clear_tpm` also fails decrypts), `creds.rs` guard cases on a header the test builds (null key from the root CLI as a test tool only).
- Evidence: `just quick` green; `creds` test 10 passed; `just coverage-gate` exit 0, `creds/systemd.rs` 97.63% lines, 100% functions, worst CRAP in the repo 28.1 (< 30); `just mutants-diff F155` exit 0 (3 caught, 8 unviable). Leftover grep clean (only the root-CLI PCR-7 control in `tpm_lifecycle/world.rs` names `--tpm2-device`, a test tool). `docs/install.md` untouched.
- Not run: step 1's environment probe as a separate command; `creds` tests rely on it (host-scoped id from Varlink, no TPM in the daemon namespace) and pass.
