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

### 2026-11-12 — F170 — attempt 2
- Done: docs/findings/F170.md and its index line. Probes ran in the e2e VM (Ubuntu 26.04, systemd 259.9) and the ubuntu2604 container; polkit 123 to 127 sources read.
- Results: `PrivateUsers=yes` shows peers as 65534; `identity` keeps real uid below 65536 and score 0.7 (so no BLOCKED.md); `no` gives 0.8; p2p server `ANONYMOUS`; polkit 124+ accepts `{pidfd, uid}` from an owner caller, and does not check the claimed uid, so unmapped uid must be refused before polkit.
- Not done / known issues: identity under polkit not run (no polkit in VM, inferred); polkit 128 not read; systemd 257 behaviour inferred from its man page.
- Next session should: nothing for F170; the socket feature reads the Decision lines.

### 2026-11-12 — F171 — attempt 1
- Done: docs/findings/F171.md and its index line, all five contract steps ticked. Probed in the e2e VM (image release-20261105).
- Results: image ships snapd 2.77.1 and AppArmor `Y`; Firefox 9181 / core26 / glibc 2.43 (ceiling 2.39), install 50 s, 1.22 GB; cache via `snap download` + `snap ack` + `snap install ./f` works offline (19 s) and tampering is rejected, but the decision is not to cache; label `snap.firefox.firefox (enforce)` via SO_PEERSEC, `/proc/self/attr/current` is denied in the snap; accept only that label; profiles in `~/snap/firefox/common/.mozilla/firefox/`.
- Not done / known issues: hook labels inferred from profile names (hooks cannot be started under `--shell`); second-boot payload copy inferred (host cannot fetch 1.2 GB through the guest; tested same-guest with the store blocked via proxy). BLOCKED.md skipped: the base is not older than the module supports.
- Next session should: nothing for F171; the VM snap feature reads the Decision lines.

### 2026-11-12 — F171 — attempt 2
- Done: fixed the evaluator finding. Ran the second-boot cache test: `bare_5.snap` + `.assert` (4 KB each) through `VM_PAYLOAD` to a fresh guest, store blocked; `snap install ./bare_5.snap` before `snap ack` is refused, after it installs (**verified** in the finding). Decision line now says the route is tested with bare, big snaps inferred; no-cache reason is snapd behaviour, not the transfer limit.
- Not done / known issues: the 1.22 GB snaps were not carried to a fresh guest (inferred).
- Next session should: nothing for F171.

### 2026-11-12 — F172 — attempt 1
- Done: docs/findings/F172.md and its index line, all five steps ticked. `modutil` measured on NSS 3.110 (dev container); packages and p11-kit checked in fedora44, alma10, archlinux and ubuntu26.04 containers; Mozilla source read by a subagent (no browser run).
- Results: `modutil` keys entries by library path (a second add of the same library renames; same name with another library fails rc 22); update = delete then add; the write is not atomic (unlink then rename of `pkcs11.txt`), so the command keeps a backup; lock rule needs symlink PID and host plus an fcntl probe on `.parentlock` (naive "exists" shown wrong both ways); p11-kit rule: `/etc/crypto-policies/back-ends/nss.config` lists `library=p11-kit-proxy.so`, loaded by libnss3 itself into every database.
- Not done / known issues: Floorp/Waterfox NSS source and Thunderbird's XDG path inferred; modutil 3.120/3.133 add semantics not re-run (only fresh-db listing); Arch Firefox profile patch inferred.
- Next session should: nothing for F172; the registration features read the Decision lines.

### 2026-11-12 — F172 — attempt 2
- Done: fixed NEXT_FINDINGS. Atomicity Decision is now a scratch-copy + `rename(2)` swap of `pkcs11.txt` (fixture run: `-add` leaves `cert9.db`/`key4.db` identical, configdir kept verbatim, SIGKILL on the copy leaves the profile intact). SPEC conflicts named (Safety met by the swap; "in place" not kept by delete+add). Dropped the "skip without cert9.db" rule; Thunderbird NSS and Floorp root marked unknown/inferred. `just quick` green.
- Not done / known issues: Floorp `MOZ_APP_PROFILE` not read; Thunderbird NSS on Debian/Arch unknown.
- Next session should: nothing for F172.

### 2026-11-12 — F172 — attempt 3
- Done: fixed NEXT_FINDINGS. Re-ran the second add with Custodio's module: `-add two` of the same library gives rc 22 (rename only for `p11-kit-proxy.so`); the register Decision now reads `library=` itself before `-add`. A deleted library file does not block `-list`/`-delete`. Swap proven with the three-file copy; a profile without `pkcs11.txt` (or a database file) uses `modutil` directly, since the swap would leave `configdir='sql:SCRATCH'` (fixtures run). Ignore the attempt 1 "keeps a backup" line: replaced by the swap.
- Not done / known issues: as in attempt 2.
- Next session should: nothing for F172.

### 2026-11-12 — F173 — attempt 1
- Done: `snap_socket` module (name `snap-firefox` -> `/run/snap.firefox`; `check_dir` opens with NOFOLLOW and judges type, write bits, then owner; refused listeners stay open and unserved; served ones accept and close), wired in `main.rs` after `start`. Units: `data/custodio-firefox.socket`, `data/tmpfiles.d/custodio-snap.conf`, service `PrivateUsers=identity` (score 0.7). Gates: `check-snap-sockets.sh` + test, `just security-ceiling` (0.7, control in `test-check-unit-hardening.sh`), `snap-sockets` in `system-gates`. Maintainer scripts of all four formats enable/restart the socket and stop it before the service (`scripts/lib/socket-scripts.sh` shared by the three static tests, with fixtures). Lists: nfpm, `package_expected.py`, namcap, `lifecycle-lib.sh`. `just quick` and `system-gates` green.
- Decisions: fd adoption through the `sd-listen-fds` crate (no deps, its `unsafe` is inside it; custodiod keeps `forbid(unsafe_code)`); `listen_names` checks LISTEN_PID/FDS/FDNAMES itself first. The test seam is the Cargo feature `test-seam` (env `CUSTODIOD_TEST_SNAP_DIR`), enabled only by a self dev-dependency, `compile_error!` in release builds; `check-snap-sockets.sh` checks it is not a default feature. Write bits are judged before the owner so a user-owned 0775 tempdir reports "group". An unnamed/other-named descriptor is closed, so a waiting client sees ECONNRESET (the binary test asserts that, no sleeps). `test-relabel.sh` needed no change (it bans only restorecon/chcon/semanage/setfiles/systemd-tmpfiles; the scripts call only systemctl). systemd creates the socket's parent directory on first start, so install does not call tmpfiles. The `mutants` recipe file list gained `snap_socket.rs`.
- Not done / known issues: Arch `post_upgrade` runs before the daemon-reload hook, so a changed socket unit is read at the next socket restart. `just mutants-diff F173` full run: only the `|` flag mutants and one `>` boundary survived; fixed, narrowed rerun pending. `just e2e debian13` not yet run.
- Next session should: check the narrowed mutants rerun, run `timeout 1700 just e2e debian13`, tick the last step.

### 2026-11-12 — F173 — attempt 2
- Done: (the uid-map drop-in lives in `e2e/tpm-lib.sh`, called from `tpm_setup`/`tpm_teardown`, since guest.sh hit the size limit; `just quick` and `just e2e debian13` re-run green on this commit) `just mutants-diff F173` clean (58 mutants: 53 caught, 5 unviable). `just e2e debian13` passes on this commit. The rootless container cannot write the identity uid map, so `e2e/guest.sh` probes it and, only there, adds a `PrivateUsers=yes` drop-in (container run only, VM unaffected). The drop-in is removed before the final "no test drop-in" check. `just quick` green. Last step ticked.
- Not done / known issues: Arch `post_upgrade` ordering as in attempt 1.
- Next session should: nothing for F173.

### 2026-11-13 — F173 — attempt 3
- Done: fixed NEXT_FINDINGS. (1) Maintainer scripts never `restart` the socket: systemd refuses to start a socket while its service is active, so on upgrade of a running service deb/rpm stop the service, `start` the socket, then `systemctl restart` the service; Arch (its gate bans restart/start of the service) stops the service and starts the socket, leaving the service for the socket to start. `scripts/lib/socket-scripts.sh` now requires `start`. `upgrade.sh` and `upgrade-m3.sh` check `custodio-firefox.socket` is active after the install (this caught the bug twice: M3 upgrade and the deb service left stopped by `deb-systemd-invoke`). (2) Contract amended (commit alone) for the container uid-map fallback and the socket check; the probe is now a unit file (systemd-run cannot parse `identity`) and the drop-in applies only on "Failed to set up user namespacing", any other probe failure fails the run. Root-run note added to the other-owner test. `test-relabel.sh` needed no change (step 7's amendment was not needed).
- Not done / known issues: Arch upgrade with a running service leaves it stopped until the next connection (checkpoint e2e on archlinux may expect it running; fix there if so). Mutants rerun after these edits: the Rust code is unchanged since the clean 58-mutant run.
- Next session should: nothing for F173; run the archlinux e2e at the checkpoint.

### 2026-11-13 — F173 — attempt 4
- Done: fixed NEXT_FINDINGS. Arch `post_upgrade` now stops a running service, starts the socket and starts the service again, so it keeps running; the restart hook still follows the reloads. The Arch static gate allows that one `systemctl start custodio.service || true` in `post_upgrade` only, with controls (service left stopped, started before the socket, the same line in another script). Deb starts/stops the socket and the service through `deb-systemd-invoke`; rpm `%post` no longer starts the socket twice. `scripts/lib/socket-scripts.sh` takes the invoker. Contract amended (probe text, evidence wording, upgrade order). The three static script tests and `test-relabel.sh` pass.
- Not done / known issues: Rust unchanged since the clean mutants run. `scripts/test-*-lifecycle.sh` (package gates) were not run; their recorded-call expectations may need the socket calls at the checkpoint. The Arch e2e is not run here.
- Next session should: run `just quick`, `just e2e debian13` if the loop did not.

### 2026-11-13 — F173 — attempt 5
- Done: fixed NEXT_FINDINGS (deb upgrade left the service stopped: `deb-systemd-invoke` refuses to start a static unit that is not running, and it was just stopped). `packaging/deb/postinst` now ends with `systemctl restart custodio.service`; stops and the socket start still go through `deb-systemd-invoke`. Contract amended (own commit). `test-deb-scripts-static.sh`, `test-relabel.sh`, `just quick` green; `just e2e debian13` passes on this commit (607 s). Rust unchanged since the clean mutants run.
- Not done / known issues: package lifecycle gates and Arch e2e not run (checkpoint).
- Next session should: nothing for F173.
