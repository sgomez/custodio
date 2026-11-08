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

### 2026-11-08 — F160 — attempt 3 (the real probe)
- Probe: `bash e2e/vm/run.sh full 'vm-*'` in a real guest passes (35 s: image 0, boot 14, copy 0, install 7, tools 2, setup 11, teardown 1; `has_tpm2=yes (exit 0)`, kernel 7.0.0-42-generic, systemd 259.9); no qemu/swtpm left (only a defunct qemu until reaped). The payload drive works (`tar -xf /dev/disk/by-id/virtio-custodio-payload`). `lacking` not run by hand.
- Real faults the stubs could not show, fixed: (1) QEMU refuses `serial=` on a raw `-drive`: now `-drive if=none,id=payload` + `-device virtio-blk-pci,serial=custodio-payload` (vm.sh, launch test). (2) `target/packages` held a pre-F154 `.deb` (has-tpm2 `partial`, exit 16): `just e2e-packages` rebuilt it; with libtss2-rc0t64 it is `yes`. (3) systemd colors in the record: `SYSTEMD_COLORS=0`. (4) `su -l` inside the ttyS0 login keeps that session (no new logind session): the guest run goes through `systemd-run --pipe --wait -E XDG_SESSION_CLASS=user`. (5) polkit-1 PAM accepts any password (as the container image does), written in the tools step. (6) no-recommends judge now reads only the apt history blocks that installed the package under test (the image build installed with recommends). 
- "Reaches the TPM" signal: the service does NOT hold `/dev/tpmrm0` open between calls, and `socket:` matches dbus. Reliable signal: no `CUSTODIOD_TEST_SWTPM_TCTI` in the service's environ (production code opens `/dev/tpmrm0` on every call otherwise, `tpm/open.rs`) and no swtpm/`.sock` path among its fds; an open device is accepted, not required. Fixtures updated.
- Step 6: `just quick` green (2m48s); `test-e2e-vm-cases.sh` 3 s, `test-e2e-vm-host.sh` 2 s, `test-e2e-skips.sh` <1 s, `test-e2e-host.sh` 13 s, `test-vm-launch.sh` 9 s: all exit 0.
- Next session should: nothing; the loop runs the `verify`.

### 2026-11-08 — F160 — attempt 4 (NEXT_FINDINGS)
- Fixed: the good-run payload check in `scripts/test-e2e-vm-host.sh` now fails the test (`r=$(ck_payload) || bad`). Removed the dead `chkc` and two no-op `|| true` lines. `just quick` green; the three verify scripts exit 0.
- Not done (notes, non-blocking): `noflag`/`dpkgi` controls still check the log, not the good-run check.

### 2026-11-08 — F161 — attempt 1
- Done (step 1 only): `e2e/vm/lacking-rsa.json` drops `0x15d` too; `scripts/test-vm-modes.sh` `ck_profile` requires both `0x159`/`0x15d` absent; controls keep_sign, drop_other, ecc384, rsa3072, drop_alg, keep_decrypt (old drop_sign flipped into keep_sign). `vm.sh` header updated. Real `lacking` guest probe in `docs/findings/F161.md`: has-tpm2 yes, root systemd-creds, ECC parent+child work, `tpm2_sign` refused; P-256 stays `encrypted-tpm`. `--user --with-key=tpm2` fails in full mode too (systemd rule).
- Timings: `test-vm-modes.sh` passes (<10 s); guest boot+apt probe ~2 min. VM stopped, no qemu/swtpm left.
- Note for the Cost section: the step-1 probe was a separate guest boot (~1 min of commands), not shared with step 5.
- Next session should: steps 2-6 (kind judgements first, `test-e2e-vm-kinds.sh` failing first).

### 2026-11-08 — F161 — attempt 2
- Done (step 2): `tpmkind.py --mode swtpm|full|lacking` (no flag = container, unchanged); `fallback.py --mode none|full|lacking`; `tpmkind_judge` in `tpmkind-lib.sh` (shared by `tpmkind-run.sh` and the self-test);
  `tpmkind-run.sh` VM branch (`E2E_VM=1`: swtpm→full, lacking→lacking + reader); `tpmkind-user.sh` waits (`TK_READ`) so root reads the credentials before the deletes; `e2e/vm/credrec.py` + `e2e/vm/cred-lib.sh`
  (`vm_read_credential ID`, reused by F162/F163); `check-cases.sh` VM rules (tpm-kind-* never skipped in a VM run, vm-silent-* never skipped in lacking); the five ids in `e2e/vm/cases.list`;
  `scripts/test-e2e-vm-kinds.sh` (in `just test-scripts`). Container scripts `test-e2e-tpm-kind.sh` (mutant sed adapted to `KIND`), `-skips`, `-vm-cases` pass.
- Placeholder: `scripts/test-e2e-vm-silent.sh` exits 1 until step 4 (it is already in `just test-scripts`, so `just quick` is red until then).
- Done (step 3): `fallback-run.sh` VM branch (`E2E_VM=1`: tpmbound cases run in swtpm=full and lacking, host cases not reported, reader on both keys in lacking via `FB_READ` hold in `fallback-user.sh`);
  `test-e2e-fallback.sh` VM section (judgements per mode with controls; the VM branch run with a stub `su` on fixtures, wrong mode in both directions, a failing reader, a control copy with an unjudged `case_run`).
  Fixtures for stored records/credentials: `scripts/lib/e2e-vm-cred-fixtures.sh`. `test-e2e-fallback.sh` and `test-e2e-vm-kinds.sh` exit 0.
- Next session: step 4 (`test-e2e-vm-silent.sh` first, then `e2e/vm/silent.sh`, ids in cases.list/skip.list, `case_group`/`phase_runs` before `vm-*`, guest.sh VM lacking), then probes (5, 6), `just quick`, timings.

### 2026-11-08 — F161 — attempt 3
- Done (step 4): `e2e/vm/silent.sh` (root side; skips the five `vm-silent-*` cases outside the lacking VM mode), `e2e/vm/silent-lib.sh` (`vs_hide`/`vs_restore`/`vs_restore_ok`/`vs_install_trap`/`vs_problems`; hiding = `dpkg-divert --local --rename` of every `libtss2-rc.so.*` file of the `libtss2-rc0*` package, then `ldconfig`, `systemctl daemon-reexec`, `systemctl restart custodio` and wait for Ping; restore = the reverse; an EXIT/TERM/INT/HUP trap restores on any outcome and a failed restore fails the run), `e2e/vm/silent.py` (hiding/restored/absent/reader judges; the import, state, journal (`binding_mismatch`), noweaker and kind judges are `tpmfail.py`'s), `e2e/vm/silent-user.sh` (alice's import/delete + API list + `custodio list`).
  Wiring: ids in `e2e/vm/cases.list`, `skip.list` (full mode), `case_group vm-silent-*` before `vm-*`, `phase_runs vm-silent` (owed_group-gated), guest.sh step after tpm-kind. `test-e2e-vm-cases.sh` lists `vm/silent.sh` as a case script; `test-e2e-vm-host-guest.sh` leaves `vm-silent-*` out of the full-mode guest ids; `test-e2e-vm-kinds.sh` controls adapted (the ids are now in cases.list).
  `scripts/test-e2e-vm-silent.sh` (2 s): judgements with ~40 controls, stubbed hide/restore (failed judge, success, TERM, HUP, failing restore, no-trap control), skip report, wiring.
- Seconds: vm-kinds 2, fallback 4, vm-silent 2; `just quick` green (2m54s).
- Not yet done: steps 5-6 real guest probes (hiding, `has2` output while hidden, `binding_mismatch` seen, service starts without the library, reader on the credentials, `just e2e-vm-cases`). The judgements assume the hidden import's journal outcome is `storage_failure` (as `tpmfail-*`); the real guest may show another outcome.
- Next session: step 5 (hand probe in a `lacking` guest), step 6 (`just e2e-vm-cases lacking ...` and full), then `just quick` and the three verify scripts with their seconds.

### 2026-11-08 — F161 — attempt 4 (real-guest probes, steps 5 and 6)
- Real faults found by the `lacking` guest and fixed: (1) `vs_libs` took the first `libtss2-rc0*` match, the not-installed `libtss2-rc0` (`un`): now only `ii` packages. (2) The real `systemd-analyze has-tpm2` prints its verdict and then the library list on stdout: `vs_has2` keeps the first line (exit status kept). (3) A diverted file renamed to `lib*.so.*.hidden-by-e2e` next to the library was taken by `ldconfig` as the library and the soname link came back (has-tpm2 stayed `yes`): the diversion now goes to `/var/lib/custodio-e2e-hidden/hidden-<name>` (`VS_HIDDEN_DIR`); the stub `dpkg-divert` of `test-e2e-vm-silent.sh` refuses a `lib*.so*` target (control for this fault). `VS_LIBS=` (empty) now means "no library", not "ask dpkg".
- Real facts: with the library hidden `systemd-analyze has-tpm2` says `partial`, exit 16; `custodiod` restarts and answers Ping without it; the hidden RSA import fails with `CredentialsUnavailable`, the journal entry has `binding_mismatch`, the state is unchanged, no key of any kind; restored: `encrypted-tpm`, reader ok (mask 0x0, host+tpm2-scoped) for RSA and P-256 (tk-*, fb-* keys).
- Runs: `just e2e-vm-cases lacking 'tpm-kind-*' 'fallback-tpmbound-*' 'vm-silent-*'` passed (1m41s; tpm-kind 22 s, vm-silent 19 s, fallback 21 s); `full 'tpm-kind-*' 'fallback-tpmbound-*'` passed (1m22s). No qemu/swtpm left. `just quick` green (3m18s). Seconds: test-e2e-vm-kinds 2, test-e2e-fallback 4, test-e2e-vm-silent 2.
- Next session should: nothing; the loop runs the `verify`.

### 2026-11-08 — F161 — attempt 5 (NEXT_FINDINGS)
- Finding 1: `tpmkind-run.sh` and `fallback-run.sh` now record `reader: the keys were never imported, the credentials were not read` when `imported` never appears; control in both self-tests (stub `su` without `imported`; run fails).
- Finding 2: `test-e2e-vm-kinds.sh` runs `tpmkind-run.sh` with `E2E_VM=1` on fixtures (stub `su`/`journalctl`) in both modes: good evidence, wrong mode both ways, PCR-mask credential (names `tk-ec`), no stored credential, never imported; a control copy without the reader call passes the PCR state. The text greps on mode mapping, the reader call and `TK_READ` are gone.
- Finding 3: `test-e2e-vm-silent.sh` now runs `silent.sh` itself (copy of the e2e tree, stubs for su/journalctl/find/sha256sum/reader): a failed session, TERM/INT/HUP while hidden (library back, `--remove` and restart logged), and a no-trap copy that leaves the diversion.
- Not done (non-blocking note): `absent_problems` with one empty list; an empty API list can be legitimate when no key exists, so it is left as is.
- `just quick` green; vm-kinds, fallback, vm-silent, tpm-kind, skips, vm-cases scripts exit 0.

### 2026-11-08 — F162 — attempt 1
- `sign.py`/`noplain.py` get the kind rows `vm-full` (tpm/tpm) and `vm-lacking` (encrypted-tpm/encrypted-tpm); the container rows are unchanged. `sign-run.sh`/`noplain-run.sh` map `E2E_VM=1` swtpm→vm-full, lacking→vm-lacking (+ reader on both keys), refuse anything else (`none`). Sign: alice waits (`SG_READ`, `imported`/`read-done`) between import and signing while root reads the credentials; noplain: root reads after both imports, before the deletes. `NP_CHECK`/`NP_STATE_DIR` override the scan script and state dir (defaults are the real paths). `guest.sh` passes `E2E_VM` to both runners.
- Real fault found by a control: `kind` judges on a missing list file crashed silently and the run passed (never imported); both `kind_problems` now return a problem when the list cannot be read.
- Self-tests: `scripts/lib/e2e-sign-alice.py` is the `su` stub of sign (real openssl signatures from the run's own p12; no openssl stub). Sections run 12-14 runs in parallel: good full/lacking/container, wrong kinds, reader failure, no credential, never imported, bad signature, leak planted in state (noplain, real `check-no-plaintext.sh`), `none` in a VM, control copy without the reader call, VM accounting with `CHECK_VM=1`. Seconds: test-e2e-sign 6, test-e2e-noplain 2.
- Real guest: `just e2e-vm-cases lacking 'sign-*' 'noplain-*'` passed (1m34s; sign 30 s, noplain 22 s), `full` passed (1m28s; sign 29 s, noplain 22 s). No qemu/swtpm left. Module path `/usr/lib/custodio/libcustodio_pkcs11.so` (guest.sh:18) is what the guest used. `just quick` green (3m21s).
- Next session should: nothing; the loop runs the `verify`.

### 2026-11-08 — F162 — attempt 2 (NEXT_FINDINGS)
- Finding 1: `scripts/test-e2e-sign.sh` compares `sign.jobs()` with a fixed table written in the test (RSA-PKCS per hash, md5sha1, arbitrary, too-long; PSS salts 0/hash/max/over with 222/206/190; composed RSA; ECDSA; composed ECDSA). Controls: a copy of `sign.py` without the max salt job and one without the RSA-PKCS mechanism both differ from the table.
- Notes: noplain reader grep now matches `np-ec: the credential ... did not pass the reader`; redundant sign grep dropped; the `sign-run.sh` wait loop breaks once `imported` exists.
- Seconds: test-e2e-sign 6, test-e2e-noplain 2; `just quick` green.

### 2026-11-08 — F163 — attempt 1
- Done (step 1): real `lacking` guest probe, `docs/findings/F163.md`. Route A (`tpm2_clear` in the guest) works; PCR extend of 0 and 7 works; PolicyPCR fails after extension; PCRs after `vm.sh cycle` equal the first reading (deterministic); `systemd-creds` re-encrypts after the clear. Contract amended with the settled rows (the amendment is in the same commit as the step tick; evaluator should review it). Not probed: `full` mode PCR values (same OVMF). Guest needs `apt-get update` before `tpm2-tools` installs. No qemu/swtpm left.
- Next session should: step 2 (`scripts/test-e2e-pcr.sh` VM sections first, with the equality judge), then steps 3-6.

### 2026-11-08 — F163 — attempt 2 (NEXT_FINDINGS)
- Fixed the three findings: ran the `full` PCR probe (same PCR values before extension and after `vm.sh cycle` as `lacking`), listed the commands in `docs/findings/F163.md`, added the index line; contract Scope rows settled (PCR 0 and 7, route A only, first reading carried in the state file) and a control for "neither extended nor first reading" added to step 2 and the evidence. No qemu/swtpm left (one defunct qemu zombie only).
- Next session should: step 2 (`scripts/test-e2e-pcr.sh` VM sections first), once the evaluator approves the amendment.

### 2026-11-08 — F163 — attempt 3
- Done (step 2): `pcr.py` gets the VM modes `vm-full` (kind tpm) / `vm-lacking` (kind encrypted-tpm), `boot OLD NEW`, an optional KIND for `enumerate`/`sigs`, `PCR_INDEXES` (VM: 0,7). New `e2e/pcr-vm.sh` (`pcr-run.sh` execs it when `E2E_VM=1`): `PCR_HALF=first` (first reading, control, import, reader in lacking, extend 7 and 0, service restart, rounds base/ext/restart; reports `pcr-extended-signs`) and `PCR_HALF=second` (after the cycle: PCRs equal the first reading, boot id changed, same keys/kinds, round cycle, delete; reports the other two). Files live in `PCR_DIR` (default `/var/tmp/custodio-e2e-pcr`, survives the cycle); TCTI `device:/dev/tpmrm0`. `pcr-user.sh` gets `PCR_DIR`, `PCR_KIND`, `PCR_NOSIGN`.
- Self-test: `scripts/test-e2e-pcr.sh` VM section on fixtures (`scripts/lib/e2e-pcr-stub.py` is a directory TPM + stub `su`/`systemctl`), 21 scenarios in parallel (good full/lacking, wrong kinds, reader failing/absent/missing-call control, no extension, pid, bad signatures, dropped key, kind change, cycle keeping/other PCRs/same boot/no cycle, second half alone). Measured 18 s (above the 2-4 s estimate; Python stub starts dominate).
- Not done: step 3 (`run.sh`/`guest.sh` split around `vm.sh cycle` with a stub `vm.sh`; `check-cases.sh` for `pcr-*` in VM), steps 4-6.
- Next session should: step 3, then 4, 5, 6.

### 2026-11-08 — F163 — attempt 4
- Done (step 3): `e2e/vm/run.sh` runs the guest twice when a `pcr-*` case is selected: `E2E_PCR_HALF=first` (the whole selection; `guest.sh` runs the pcr first half last, after lifecycle, so the pcr keys do not disturb the other groups), `vm.sh cycle` (step `cycle`), then `E2E_PCR_HALF=second` with only the pcr ids (`guest.sh` exits right after the service is up; no import or fixtures repeated). A failed half skips the cycle; a failed cycle dies ("power cycle of the guest failed"); VM stopped by the existing trap. The `pcr` phase seconds of both invocations are one record step. Without a pcr case nothing changes. `check-cases.sh` already refused skipped `pcr-*` under `CHECK_VM`; the self-test now proves it for both modes with a skip list (plus a format control).
- Stub: `scripts/lib/e2e-vm-stub/vm.sh` gets `cycle`, `STUB_FAIL_CYCLE`, `STUB_FAIL_HALF`, and reports pcr cases per half. `scripts/test-e2e-pcr.sh` driver section (9 runs in parallel, controls: driver without the cycle, driver without the second half). `test-e2e-pcr.sh` now 18 s; vm-host, vm-cases, skips, vm-kinds scripts exit 0.
- Not probed in a real guest yet (step 6): the second invocation after a real `vm.sh cycle`.
- Next session should: step 4 (tpm-clear), then 5, 6.

### 2026-11-08 — F163 — attempt 5
- Done (step 4): `tpmclear-run.sh` has a VM branch (`E2E_VM=1`; swtpm → kind tpm, lacking → encrypted-tpm, `none` refused): no second swtpm, no drop-in, no filter; `tpm2_clear`/primary name go to the guest's `device:/dev/tpmrm0` (`TC_VM_TCTI`); the reader (F157) runs on each key after every import in lacking. The judges take the kind; the container path is unchanged. Test hooks `TC_STATE_DIR`, `TC_SCAN`. `guest.sh` passes `E2E_VM` to it.
- `scripts/test-e2e-tpmclear.sh` VM section on fixtures (`scripts/lib/e2e-tpmclear-stub.py`: a seed TPM that `tpm2_clear` changes, real openssl signatures, keys lost per seed): 19 runs in parallel; good full/lacking, wrong kinds, reader failing/missing/control copy, mode none, no clear, sign after clear, no/wrong/secret journal entry, other text, lost key, kind change, failing delete; TCTI log proves no other TPM; `CHECK_VM` accounting. Measured 7 s total.
- Not probed in a real guest: the sign failure of an `encrypted-tpm` key after the clear may not be `KeyLost`/`key_lost` (step 6 will show; if it differs, record it in the finding and amend).
- Next session: step 5 (upgrade-kinds), then 6.

### 2026-11-08 — F163 — attempt 6
- Done (step 5): `upgrade-kinds.sh` VM branch (`E2E_VM=1`: swtpm → `vm-full` kind tpm, lacking → `vm-lacking` kind encrypted-tpm in `upgradekinds.py`); new step `reader` (lacking only: `vm_read_credential KEY UID` on alice's ec1/rsa1 and bob's bobonly/rsa1; `credrec.py`/`cred-lib.sh` take an optional UID because rsa1 is owned twice), called by `upgrade.sh` before the install and again in `tpmbound`, which a VM reports run (container: skipped as before). `guest.sh` passes `E2E_VM` to `upgrade.sh`; the install is still the target's `install.sh` (`dpkg -i`).
- `scripts/test-e2e-upgradekinds.sh` VM section: both modes good, wrong kind per phase, journal of another kind, PCR-bound credential refused by the reader, control copy without the reader call, no credentials, full not calling the reader, mode none refused, `CHECK_VM` accounting; `upgrade.sh` order check for `kinds reader`.
- Payload check (evidence "N depends on libtss2-rc0t64"): `e2e/vm/run.sh` reads the REAL `.deb`s it packs (`target/packages`, `target/packages-next`): different versions, both with `libtss2-rc0t64` in Depends; the test is in `scripts/test-e2e-vm-host.sh` (`f-nodep` control), fake debs of that test and of `test-e2e-pcr.sh` now carry the dependency.
- Not probed in a real guest: steps 5/6 real runs (`dpkg -i` of N+1 in the VM, the reader on the credentials after the upgrade).
- Next session: step 6 (real-guest probes for `tpm-clear-*`, `upgrade-kinds-*`, `pcr-*`; then `just quick` and the three verify scripts with seconds).
- (attempt 6, end) `just quick` had been red from the file-size gate (5000 tokens): the VM sections of `test-e2e-pcr.sh` and `test-e2e-upgradekinds.sh` moved to `scripts/lib/e2e-pcr-vm-section.sh` and `scripts/lib/e2e-upgradekinds-vm-section.sh` (sourced), `guest.sh` comments shortened below the limit. The three self-tests exit 0 after the split; the last full `just quick` was started at the end of the session and its result is not recorded: run it first next session.

### 2026-11-08 — F163 — attempt 7 (step 6 in progress)
- `just quick` green at the start (3m24). Real `lacking` run `just e2e-vm-cases lacking 'pcr-*' 'tpm-clear-*' 'upgrade-kinds-*'` (1m32): `tpm-clear-*` pass; `upgrade-kinds-before/-kept` pass after a fix: in the guest systemd 259 keeps the state of the `PrivateUsers=yes` service owned by 65534 on disk (probed with a test unit), so `upgrade.sh` takes the expected owner from the state directory when `E2E_VM` is set (`compare_state` still proves it is unchanged).
- OPEN: in the combined run, after `tpm-clear-*`, `upgrade-kinds-signs` fails: `pkcs11-tool -m RSA-PKCS` on `rsa1` ends in `C_SignUpdate ... CKR_OPERATION_NOT_INITIALIZED` (data.bin is 32 bytes, as always). `'upgrade-kinds-*'` alone passes (35 s phase) and `sign-rsa-pkcs` alone passes, so something left by the tpm-clear/pcr steps changes how pkcs11-tool signs. Not yet understood. `pcr-*` outcome of that run not yet read; `full` not run yet.
- (attempt 7, end) Reproduced with `just e2e-vm-cases lacking 'tpm-clear-*' 'upgrade-kinds-*'` (tpm-clear before upgrade-kinds is enough). On failure `upgrade-user.sh` now also prints the token's mechanisms and objects (diagnostic): they are normal (RSA-PKCS, PSS, SHA*-RSA-PKCS listed; private key and cert present), yet pkcs11-tool calls `C_SignUpdate` for the 32-byte input instead of `C_Sign` (the sign-rsa-pkcs cases get `C_Sign`). Ideas: compare the module's token/mechanism info for `sg-rsa` vs `rsa1`, run the same pkcs11-tool call by hand in a guest after `tpm2_clear`; check whether the earlier tpm-clear leaves state the module reads (state dir, TPM handles) that changes a flag pkcs11-tool uses. Not in a real guest yet: `pcr-*` result, `full` mode, the three verify scripts' seconds.

### 2026-11-08 — F163 — attempt 8 (step 6 still open)
- Diagnosed the OPEN failure of attempt 7: `upgrade-kinds-signs` after `tpm-clear-*` is a real `KeyLost` from the service (`com.rfirma.Custodio1.Error.KeyLost: the stored key can no longer be used`, journal `signing failed after approval ... key rsa1`), not a pkcs11-tool quirk: pkcs11-tool only retries a failed one-shot `C_Sign` with `C_SignUpdate`, whose `CKR_OPERATION_NOT_INITIALIZED` hid the cause. Ruled out: TPM lockout (`inLockout 0`, counter 0), a systemd SRK cache file (none in `/var/lib/systemd`).
- So alice's `rsa1` (sealed by `systemd-creds` after the clear, or made before it: not yet known which) cannot be unsealed after the service restart that follows the clear. Next: find out whether alice's `rsa1` is imported before or after the clear in the combined run (`upgrade-accts.sh` import time vs `tpmclear-run.sh`), and whether a key imported after `tpm2_clear` still signs after `systemctl restart custodio` (add that to the tpm-clear re-import step on fixtures + real guest). If post-clear credentials do not unseal after a restart, that is a product finding (record in `docs/findings/F163.md`, amend/deviation as CLAUDE.md says); if the seeds predate the clear, order the groups so `upgrade` runs on keys made after it or have `tpmclear-run.sh` leave no pre-clear keys.
- Diagnostics kept: `upgrade-user.sh` prints the D-Bus Sign error on failure; `upgrade.sh` prints the service journal tail on a failed sign round. Real `pcr-*` outcome and `full` mode still not run; no qemu/swtpm left.

### 2026-11-08 — F163 — attempt 9 (step 6 done)
- Cause of the `upgrade-kinds-signs` KeyLost: alice's `rsa1`/`ec1` are imported by the setup, before `tpm-clear-*`; the VM clear (the guest's own TPM) makes them unusable, and `upgrade` uses them. Fix: `guest.sh` keeps the setup p12 files in `$work/setup-keep` (VM only); `tpmclear-run.sh` (VM, when that directory exists) runs `tpmclear-user.sh restore` at the end (alice deletes the lost keys and imports them again), plus the reader in `lacking`. Not covered by a fixture: proven by the real runs only.
- Real guest, `pcr-* tpm-clear-* upgrade-kinds-*`: `lacking` passed (167 s), `full` passed (165 s), all ten ids ok, no qemu/swtpm left.
- `just quick` green. Verify scripts: test-e2e-pcr 18 s, test-e2e-tpmclear 7 s, test-e2e-upgradekinds 10 s, all exit 0.

### 2026-11-08 — F163 — attempt 10 (review findings fixed)
- Finding 1: `scripts/test-e2e-tpmclear.sh` has VM fixtures with `setup-keep` (stub `restore` in `e2e-tpmclear-stub.py`): rsa1/ec1 deleted and imported again in order, the reader runs on them in `lacking` (a bad ec1 credential fails), a failing restore delete or import fails the run, a run without `setup-keep` does not restore. Mutants (restore call removed, reader call removed) are caught.
- Finding 2: probed in a real `lacking` guest (systemd 259.9): the state is owned 65534:65534 on disk, mode 700; recorded in `docs/findings/F163.md` (a real on-disk owner; the service accepts it; SPEC has no numeric owner rule; a person may confirm). `upgrade.sh` pins 65534 in a VM. Real `lacking 'upgrade-kinds-*'` passed after the change (1m13).
- Finding 3: debug leftovers removed from `upgrade-user.sh` and `upgrade.sh`.
- Notes: contract amended (dpkg -i, payload test in `test-e2e-vm-host.sh`, measured costs); the no-op line in the pcr driver section became two assertions.
- `just quick` green (2m55). Verify scripts: pcr 21 s, tpmclear 9 s, upgradekinds 10 s, all exit 0.

### 2026-11-08 — F163 — attempt 11 (amendment revised)
- The VM upgrade now installs N+1 with `apt-get install -y --no-install-recommends` (`e2e/vm/install-pkg.sh`, `E2E_INSTALL` set by `guest.sh` in a VM), like N; the container keeps `install.sh`. Real `lacking 'upgrade-kinds-*'` passed (upgrade phase 35 s). Contract Scope/Cost/step 5/amendment now agree (no `dpkg -i`, no `apt upgrade`, measured seconds).
- Owner pin 65534: judge fixtures in the upgradekinds VM section (65534 accepted, another owner refused). Not covered by a fixture: `upgrade.sh` itself choosing 65534 in a VM (real runs only).
- `guest.sh` comment shortened (size gate). `just quick` green; test-e2e-upgradekinds and test-e2e-upgrade exit 0.
