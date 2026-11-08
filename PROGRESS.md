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

### 2026-11-08 — F156 — attempt 2
- Done: `e2e/targets/ubuntu2404`, the `refusal-only` mechanism (`run.sh`, `guest.sh`, `select.sh` phase `refusal`), `e2e/refusal*.sh`, `scripts/test-e2e-refusal.sh` (and its `justfile` line), the workflow matrix entry and its "On 24.04" comment are gone; the host/target/lifecycle/m3/oldpath/select self-tests and `e2e-host-fixtures.sh` follow (the unknown-target message lists `alma10 arch debian13 fedora44 ubuntu2604`). `docs/install.md`: systemd 257 floor, Ubuntu 24.04 unsupported and refused, dbus-broker section gone, `libtss2-rc0t64` with the `dlopen` reason. `test-docs-install.sh` reads the floor from `packaging/nfpm.yaml`, checks the sentences, the 24.04 entry/section and the rc paragraph (outside the lists), with 8 new controls. `manual-acceptance.md` section 14 is marked no longer applicable (history kept in git); `test-docs-manual.sh` follows.
- Reference check: `grep -rIn 'ubuntu2404\|refusal-only' e2e scripts .github justfile` now finds only `lib/bus-fixtures.sh:89`, `test-bus-check.sh` (fake os-release), `test-check-budgets.sh` (its own fixture) and `test-docs-manual.sh` (the n/a part). Kept comments: `nfpm.yaml:24`, `package_expected.py:66` reworded to "Ubuntu 24.04". `budgets.tsv` untouched. `grep ubuntu-2404-switching` finds only the contract.
- Decision: the bus-check message still says "on Ubuntu 24.04: install dbus-broker" (contract: text unchanged).

### 2026-11-08 — F156 — attempt 3
- Done: NEXT_FINDINGS fixed. `scripts/test-ci-e2e.sh` has a `ghost-target` control (adds `ubuntu2404` to the e2e matrix; the script must report the unknown target); passes.
- Kept references (named): `scripts/lib/bus-fixtures.sh` and `scripts/test-bus-check.sh:155` (fake os-release for the bus check), `scripts/test-check-budgets.sh:11-12` (its own fixture), `test-docs-manual.sh` (the n/a part). `budgets.tsv` untouched.

### 2026-11-08 — F157 — attempt 1
- Done: `e2e/vm/credread.py` (stdlib only, from F153's tables), `e2e/vm/mkcreds.sh` (7 live `systemd-creds` 257.13 fixtures in one swtpm session, each checked to decrypt), `scripts/test-vm-credread.sh` (in `just test-scripts`; ~1 s). Told-apart table, `--expect-tpm-bound`/`--systemd-version`, distinct reasons, cuts (cut points from the file's own sizes, TPM section asserted to end at 344), corrupted `iv_size`/blob size, non-base64, unknown id, negative control (mask check sed-patched out). `just quick` green; the script passes.
- Rules: file is text if all bytes are printable ASCII/whitespace and then must strictly decode as base64 (else `malformed`); otherwise raw. Empty `--tpm2-pcrs=` gives mask 0 on 257.13 (checked). Dropped the redundant "mask ignorable" `--expect` variant beyond the one negative control.
- Next session should: nothing; the loop runs the `verify`.

### 2026-11-08 — F158 — attempt 1
- Done: `e2e/vm/image.sh` + `just vm-image`; `scripts/test-vm-image.sh` (in `just test-scripts`, ~2 s, offline). Pin: one dated serial `20261105` (decisions.md); no listing is ever made, so a cache hit uses the cache after re-verifying it, and a 404 names the serial. Cache `~/.cache/custodio/vm-image/release-<serial>/`, refused if inside the repo (realpath); failing cache files are removed by fixed name inside that directory only.
- Real run: first `just vm-image` downloaded and verified (18 s), serial 20261105, sha256 ee808a4a…8ddc; second run with `VM_IMAGE_BASE=file:///nonexistent` used the cache (0.3 s), same serial and checksum.
- Found: the dev container has `gpg` but **no `gpg-agent`**, so `gpg` cannot generate keys or sign. The test uses `scripts/lib/openpgp_ed25519.py` (stdlib, throwaway keys from fixed seeds, valid for `gpgv`) instead of a gpg test key. Dropped the redundant "good run with the other keyring" control (evaluator note 1); the `gpgv`-removed copy is accepted by the badsig and other-key fixtures.

### 2026-11-08 — F158 — attempt 2
- Done: NEXT_FINDINGS fixed. `scripts/test-vm-image.sh` runs the seven refusals, good, two-serial and missing-serial runs at once (`wait`, results checked after), and the two mutant runs too (~1 s). Amendment (committed alone) records the signer `scripts/lib/openpgp_ed25519.py`; `docs/findings/F158.md` (+ index) records the missing `gpg-agent`. `badsig` is commented as not the pure signature control (`badsig2` is). `image.sh` places with an existence check and `mv -T`.

### 2026-11-08 — F159 — attempt 1
- Done: `e2e/vm/vm.sh` (commands `start MODE | wait | run | put | get | cycle | stop`, interface in its header), `e2e/vm/chan.py` (serial-console channel, stdlib), `e2e/vm/swtpm-path.sh`
  (which swtpm: `$VM_SWTPM`, else `/opt/swtpm/usr/bin/swtpm` if present, else PATH; version/`--profile` check), `e2e/vm/lacking-rsa.json` (F152 commands minus `0x159`),
  stubs in `scripts/lib/vm-fakes/` (qemu with a fake guest, swtpm), `scripts/test-vm-launch.sh` (+ `scripts/lib/vm-launch-controls.sh`, split for the 5000-token limit),
  `scripts/test-vm-modes.sh`, both in `just test-scripts`. `harness/Containerfile` unpacks swtpm 0.10.2 (four `.deb`, `sha256sum -c` before `dpkg-deb -x`) into `/opt/swtpm`,
  never over 0.7.1 (existing swtpm users untouched). `vm-host-check.sh` has a new `swtpm-profile` line (MISSING on 0.7.1: `just vm-host-check` fails until the rebuild); its test extended.
  Amendment (committed alone) takes the evaluator's notes. `docs/findings/F159.md`: unpacked swtpm needs both lib dirs; a restart on the same state must omit `--profile` (PTM_INIT 0x9).
- Timings: `test-vm-launch.sh` 9.5 s, `test-vm-modes.sh` 0.6 s; `just quick` green; `test-vm-host-check.sh` passes.
- Step 6 (real, foreground): `/dev/kvm` opens read-write (python probe). `vm.sh start full` reached the login in 13 s; `run` output exact (no escape junk); 300 KB `put`/`get` `cmp` equal;
  after `apt-get install tpm2-tools` a persistent handle `0x81010001` (name `000b11529b6b…0b4f0b`) was identical after `cycle` (11 s); `stop` 1.8 s; `pgrep -a 'qemu|swtpm'` against a snapshot
  taken before: nothing new (only the F151/F152 idle ones). Checkpoint evidence for `lacking`: with swtpm 0.10.2 unpacked to a temp prefix (`VM_SWTPM_PREFIX`), `vm.sh start lacking` booted
  (so `PTM_INIT` accepted the profile), `tpm2_getcap commands` had no `TPM2_CC_RSA_Decrypt` (0) and `TPM2_CC_Sign` (1) before and after `cycle`, P-256 listed, `tpm2_testparms rsa2048` ok; stop clean.
  The temp copy is deleted. The first rebuilt container still needs `just vm-host-check` → exit 0.
- Known: a power cycle restarts swtpm without `--profile` (see finding). `BLOCKED.md` asks for the container rebuild.

### 2026-11-08 — F159 — attempt 1 (after the container rebuild)
- Done: container rebuilt with swtpm 0.10.2 under `/opt/swtpm`; `BLOCKED.md` removed. `just vm-host-check` exit 0 (all OK, including `swtpm-profile`).
- Evidence rerun: `just quick` exit 0; `scripts/test-vm-launch.sh` exit 0 (9.5 s); `scripts/test-vm-modes.sh` exit 0 (0.6 s).
- Checkpoint evidence: with the rebuilt container's swtpm, `swtpm socket --tpm2 --profile file=e2e/vm/lacking-rsa.json --print-info 1` (run through `vm_swtpm_run`, which sets both lib dirs) prints the TPM spec JSON, so the profile parses; the earlier real `lacking` boot reached `PTM_INIT` (see attempt 1 above).
- Next session should: nothing for F159; the loop runs the `verify`.

### 2026-11-08 — F160 — attempt 1
- Done: `e2e/vm/{cases.list,omitted.list,skip.list}`; `CHECK_VM=1` in `check-cases.sh` (VM run = swtpm unless lacking; tpmbound run accepted, tpmbound skipped refused whatever the skip list says; no change without the flag);
  `scripts/test-e2e-vm-cases.sh` (2 s). `e2e/vm/judge.sh` (the five `vm-*` cases: `vm_collect_install` right after the install, live judges after the setup and after the cases, `vm_finish`);
  `e2e/guest.sh` VM mode (`E2E_VM=1`: no install, no tpm_setup/teardown, `E2E_DIR`, `E2E_PKG_DIR`, `E2E_PKG_NEXT_DIR` overridable; key fixtures moved unchanged to `e2e/guest-fixtures.sh` to stay under 5000 tokens);
  `case_group vm-*` in `select.sh`; driver `e2e/vm/run.sh` and recipes `e2e-vm`, `e2e-vm-cases`, `e2e-vm-check` (mode/names refused before `e2e-packages`);
  `scripts/test-e2e-vm-host.sh` + `scripts/lib/e2e-vm-host-guest.sh` + `scripts/lib/e2e-vm-stub/` (good, failure paths, recipes, guest, vm-only, controls; 2 s). Both new scripts are in `test-scripts`.
- Decisions: "reaches the TPM" signal = the running service has no `CUSTODIOD_TEST_SWTPM_TCTI` and holds `/dev/tpmrm0` open (`ls -l /proc/PID/fd`); NOT yet shown reliable in a real guest (the service may open the device per call) — step 5 must check and adapt `vm_judge_via_device`.
  Guest layout: `/pkg`, `/pkg-next`, `/e2e` (tar of the tree), `/e2e-target` (debian13 files + the VM list as `cases.list`), the docs/scripts the container mounts. The guest gets `E2E_SELECT` = the selected VM cases always.
  Test record fields: `step_<name>=seconds`; step `setup` = guest install+service+import phases; case groups sign/noplain/pcr/fallback/tpmclear/upgrade only when a case of the group was selected.
- Steps 1-4 ticked; step 6 partly run (`just quick` green, the four scripts and every `test-e2e-*.sh` green at this commit).
- Not done: step 5 (the real probe: `vm.sh start full`, copy, `apt-get`, has-tpm2, judges in a real guest, copy time). Needs `just package` (cargo build) and a network route in the guest; no time left in this session. Unticked in the contract.
  Note the driver guest `run` goes through the serial channel as `ubuntu` with sudo; `sudo` presence and the `tar`/`mv` placement of the files are unproven in a real guest.
- Next session should: do step 5 (probe), adjust the judges/driver from what it shows, then tick step 5 and run step 6 (`just quick`, the four scripts, `test-e2e-host.sh`); record the seconds (2 s each here).

### 2026-11-08 — F160 — attempt 2
- Probe (step 5, partly): `vm.sh start full` works (boot 14 s, image check 19 s, stop 90 s with a defunct qemu left until reaped). Guest has network (`curl archive.ubuntu.com` 200). Serial `put`: 300 KB in 20.7 s, 1.5 MB in 101 s (about 15 KB/s); the real `.deb` is 4.5 MB (x2) → over 10 min of copy, over the 5 min limit of the contract → `BLOCKED.md` with the options. Not probed: install, has-tpm2, judges, the TPM signal.
- Fixed: `e2e/vm/run.sh` guard named `p11-kit` and `polkitd` as test tools but the real package depends on them (nfpm.yaml); now only pure test tools. `scripts/test-e2e-vm-host.sh`: flaky (1 in 3) because control copies were written into the e2e tree while a good run tarred it; the good runs now launch after every `mkctl`. 6 runs in a row green (about 2 s each).
- Step 5 and 6 stay unticked.

### 2026-11-08 — F159/F160 — after BLOCKED (serial copy too slow): the payload drive
- Applied the person's answer (option 2, simplest form). Contract amendments in their own commit (`docs(F160): amend contracts ...`; F160 trimmed to stay under 5000 tokens).
- `e2e/vm/vm.sh`: `VM_PAYLOAD=FILE` on `start` adds a read-only raw virtio drive `serial=custodio-payload` (guest: `/dev/disk/by-id/virtio-custodio-payload`); the absolute path is kept in `$RUN_DIR/payload.path`, so a `cycle` brings the drive back. A missing/unreadable file or a path with a comma or space is refused before anything starts. No `VM_PAYLOAD`: arguments unchanged. `put`/`get` stay for small files.
- `scripts/test-vm-launch.sh` + `scripts/lib/vm-launch-payload.sh`: scenarios `payload`, `payload_missing` and controls `payload_rw`, `payload_cycle`, `payload_check` (fail without the launcher change, pass with it).
- `e2e/vm/run.sh`: packs `pkg/ pkg-next/ e2e/ e2e-target/ e2e-docs/ e2e-noplain/ e2e-src/` (root-owned, no `__pycache__`) into one tar, starts the VM with `VM_PAYLOAD`, and extracts it with `sudo tar -C / --no-same-owner -xf /dev/disk/by-id/virtio-custodio-payload`. No `vm put` any more. The `copy` step time includes the packing. `scripts/test-e2e-vm-host.sh` + `scripts/lib/e2e-vm-payload.sh`: payload content, no `vm put`, controls `putdeb`, `nopayload`.
- Ran: `just quick` green, `scripts/test-vm-launch.sh`, `scripts/test-vm-modes.sh`, `scripts/test-e2e-vm-host.sh` green. Not run in a real guest: the payload drive and `tar -xf` from it are unproven until step 5.
- Next session should: do F160 step 5 (real probe) with the payload drive: check the by-id link exists in the guest, `tar` of the raw device works with the padded size, then ticks step 5/6.
