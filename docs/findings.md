# Findings

Research the project relies on: what a tool, library, distribution or client does, proven by its
source or by a command run. One file per feature, `docs/findings/<id>.md`; this page is the index.

Rules:

- A feature writes its findings in its own file, headed `## <id>`. A later feature that finds one
  wrong corrects that file and its index line, and says so in its own file; it never leaves two
  files that contradict each other.
- Conclusion first: what holds, marked **verified** (source read, command run) or **inferred**,
  with the versions. Then the evidence: the command and the lines of output that prove it, never
  the whole output. Many cases go in a table or one line each.
- A manual acceptance run records the date, the machine, the versions and, per step, pass or fail
  with the line that shows it.
- A file stays under 5000 tokens (`scripts/check-files.sh`, in `just quick`), and so does this
  page. Condense; do not split a file to get under the limit.
- Each file has one line below: `- [<id>](findings/<id>.md) — topic: the conclusion still valid`.
  When a finding stops holding (the code, a version or a later finding changed it), fix the file
  and its line. Delete a file only when nothing cites it (`git grep <id>`).
- Not here: decisions (`docs/decisions.md`), how a feature is built (commit), progress
  (`PROGRESS.md`).

## Index

- [F18-always-authenticate](findings/F18-always-authenticate.md) — `CKA_ALWAYS_AUTHENTICATE` per client: no client reliably logs in per signature, so the attribute stays false and `C_Sign` itself asks polkit every time.
- [F18-dbus-in-clients](findings/F18-dbus-in-clients.md) — D-Bus inside NSS/Firefox/LibreOffice: a connection per call, no thread left behind, `pthread_atfork`, so the module is fork- and thread-safe without zbus help.
- [F18-versions](findings/F18-versions.md) — minimum polkit/bus versions: polkit 124+ on a bus with `ProcessFD`; Debian 13, Ubuntu 25.10+, Fedora 41+, RHEL/Alma 10, Arch; 24.04 only with dbus-broker.
- [F21](findings/F21.md) — SoftHSMv2 multi-part signing: raw mechanisms reject `C_SignUpdate`/`C_SignFinal` with `CKR_OPERATION_NOT_INITIALIZED`; Custodio keeps `CKR_OPERATION_ACTIVE` for `C_Sign` after update.
- [F28](findings/F28.md) — pkcs11-tool login and sign flow: input > 1024 bytes goes multi-part, and a denied one-shot composed sign retries multi-part (polkit asked twice); deny tests sign > 1024 bytes.
- [F30](findings/F30.md) — M1 open questions: no signing client sends `CKU_SO` (keep `CKR_SESSION_READ_ONLY_EXISTS`); caller detail only from bus/pidfd, never `/proc`; refused calls: aggregate.
- [F33](findings/F33.md) — acceptance 11 (rFirma 0.17.0, ubuntu2604): RSA main window and P-256 site flow pass; P-256 main window fails because rFirma hard-codes SHA256withRSA.
- [F34](findings/F34.md) — acceptance 12 (LibreOffice, ubuntu2604): RSA and P-256 pass with a dedicated NSS db and CA trusted `C,C,C`; no PIN dialog, only polkit's.
- [F35](findings/F35.md) — acceptance 13 (journal audit after F33/F34): pass; one entry per action, a refused mechanism leaves no entry, `-o verbose` shows the four `CUSTODIO_*` fields.
- [F36](findings/F36.md) — nfpm 2.48 names and dependencies: Arch needs version `X_rc.N` with empty prerelease; rpm depends on `dbus` (not `dbus-daemon`); deb `dbus-system-bus`.
- [F37](findings/F37.md) — glibc ceiling: 2.39 (Ubuntu 24.04, Alma 10); shipped ELFs need at most `GLIBC_2.34`; rpm lists no directories, deb/Arch list parents `0755 root root`.
- [F38](findings/F38.md) — package linters: lintian 2.122.0, rpmlint 2.8.0 (Fedora container only), namcap 3.6.0 (Arch container only); remaining findings are listed literally in `packaging/lint/*.txt`.
- [F41](findings/F41.md) — polkit 124 and `ProcessFD`: polkit 124 (and Ubuntu's 124-2ubuntu1.24.04.4) takes the pidfd from `ProcessFD`; without the key it falls back to an unpinned PID.
- [F42](findings/F42.md) — failing pre-install scripts: dpkg and rpm abort the install; pacman does not, only an alpm PreTransaction hook with `AbortOnFail` can (and not on first install).
- [F44](findings/F44.md) — rpm scriptlets and rpm-ostree: measured `rpm -U` order and `$1`; nfpm cannot write `Requires(pre)`; rpm-ostree never runs removal scriptlets (deviation).
- [F45](findings/F45.md) — e2e in the dev container and per-target images: needs subuid ranges, `SYS_ADMIN`, `unmask=/proc/*`; journald persistent on all images; target quirks (p11-kit-proxy, logind, su-l).
- [F48](findings/F48.md) — Debian/Ubuntu images ship `policy-rc.d` that blocks restarts; Containerfiles remove it; the new binary is checked by device:inode.
- [F49](findings/F49.md) — rpm owns no directory unless told: nfpm `type: dir` entries for rpm; scriptlet output reaches each package tool; apt `remove` leaves state `rc`.
- [F53](findings/F53.md) — `just e2e all` and `check-slow` on a host with podman: pass on six targets; exposure 0.6, mutants none missed, CRAP 30, glibc 2.34.
- [F54](findings/F54.md) — acceptance 12 (Firefox TLS client auth, fedora44, SELinux): pass via p11-kit-proxy; `ausearch` needs `--input-logs` over ssh; Firefox "remember" pitfalls.
- [F55](findings/F55.md) — acceptance 13 on bazzite (rpm-ostree layered): pass; key files show uid 65534 on disk because of the idmapped `DynamicUser` mount (expected).
- [F56](findings/F56.md) — acceptance 14 on omarchy: package and polkit pass; Arch's NSS loads no p11-kit-proxy, so Firefox needs `modutil -add` per profile (decided: documented).
- [F57](findings/F57.md) — acceptance 15 on ubuntu2404: install refused on dbus-daemon 1.14; after switching to dbus-broker 35 everything checked works, nothing broke.
- [F58](findings/F58.md) — Arch alpm hooks: sysusers, catalog, daemon-reload and `dbus-reload` are hooks already; restart via own hook after `dbus-reload`; account in `pre_*` (dbus-daemon inotify).
- [F61](findings/F61.md) — SELinux relabel after the binary move: tmpfiles `Z /var/lib/private/custodio - - -` restores labels only, at boot (and at dnf transaction end); Arch has no old path.
- [F62](findings/F62.md) — SELinux domain after the move, fedora44 and bazzite: pass; `/usr/libexec` runs in `unconfined_service_t`, key files back to `var_lib_t`; ECDSA verify needs `--signature-format openssl`.
- [F67](findings/F67.md) — reading the flatpak app-id: (c) find the pidfd's pid in `cgroup.procs` of the caller's `app.slice` scopes; never loosen the unit; parse `app-flatpak-<E>-<N>.scope` strictly.
- [F68](findings/F68.md) — detection through `xdg-dbus-proxy`: with `--talk` identical to host; without it "not allowed" is indistinguishable from "not installed"; never branch on one error name.
- [F89](findings/F89.md) — CLI polkit agent: no side-effect-free "agent exists" check; run `pkttyagent --fallback --process=PID,START` under `setpriv --pdeathsig=KILL` (needs util-linux).
- [F90](findings/F90.md) — packages for `setpriv`/`pkttyagent`: util-linux (Essential on Debian, explicit on rpm/Arch) and polkit/polkitd.
- [F91](findings/F91.md) — `busctl call` drops the D-Bus error name; e2e reads it with Gio `call_sync` (`Gio.DBusError.get_remote_error`).
- [F97](findings/F97.md) — pkttyagent with real PAM: with `pam_unix` in `polkit-1` the right password passes and a wrong one fails; `pam_permit` images prove nothing.
- [F101](findings/F101.md) — M3 acceptance 14 (client API with busctl, ubuntu2604): pass; on a fresh install `NameHasOwner` is false until bus activation.
- [F102](findings/F102.md) — M3 acceptance 15 (test flatpak, fedora44): pass after `fa76c48` (gdbus; the runtime has no busctl); journal pid is `xdg-dbus-proxy`, app-id state `read`.
- [F103](findings/F103.md) — M3 acceptance 16 (Firefox, LibreOffice, second account, fedora44): pass; `modutil -add` fails on Fedora (`CKR_CRYPTOKI_ALREADY_INITIALIZED` via p11-kit-proxy), harmless.
- [F106](findings/F106.md) — TPM parent: primary recreated each use from the ECC P-256 TCG SRK template; no persistent SRK or NV write; store the parent name next to the blob and compare before `Load`.
- [F107](findings/F107.md) — TPM mechanism parity: way (b) (service pads, `TPM2_RSA_Decrypt` raw) serves every RSA mechanism at the cost of `decrypt`; P-256 needs SHA-256 only; `TpmFilter` simulates lacks.
- [F108](findings/F108.md) — TPM in e2e containers: `swtpm` on a unix socket under `/tmp` (state `/var/tmp`) reached through a test-only `/run` drop-in; host AppArmor confines `swtpm`; no vTPM proxy.
- [F109](findings/F109.md) — `/dev/tpmrm0` under the unit: keep `PrivateDevices=yes`, add `DeviceAllow=/dev/tpmrm0 rw`, `BindPaths=-/dev/tpmrm0`, `SupplementaryGroups=tss` (0.7); package must provide `tss`.
- [F110](findings/F110.md) — `systemd-creds` without root: Varlink `user` scope, no `withKey`, read back PCR mask at byte 48 and refuse nonzero/null; 255 and 257 are deviations; Decrypt error = cannot decrypt.
- [F111](findings/F111.md) — F106/F107 probes on an STM hardware TPM: SHA-512 absent (way (b) still `ready`), P-256 primary 494 ms, RSA 3.7 s, `0x81000001` held by a foreign key.
- [F113](findings/F113.md) — `TPM2_Import` wrap: outer wrap to the P-256 parent (ECDH seed, KDFa, AES-128-CFB, HMAC) with no session and no new crate; imported keys cannot be duplicated.
- [F117](findings/F117.md) — test children and `swtpm`: TSS TCTI sockets leak into forked children (no CLOEXEC); spawn through `closed_fds`; AppArmor blocks signals to `swtpm`; the service's `systemd-creds` spawn is fixed in F118.
- [F118](findings/F118.md) — descriptors of the `systemd-creds` child: a plain `Command` leaks every inherited descriptor; `/usr/bin/bash -c` closes them before `exec` without `unsafe`.
- [M01-acceptance](findings/M01-acceptance.md) — M0/M1 manual run (ubuntu2604): rFirma passes with its own fixes; Firefox snap cannot load the module; Mozilla .deb needs manual registration.
- [acceptance-6-fingerprint](findings/acceptance-6-fingerprint.md) — acceptance 6 with libfprint's virtual device (ubuntu2604): pass; each signature asks for the finger again, unmatched falls back to password.
- [F131](findings/F131.md) — e2e TPM: the F108 route works in the final harness on every target (swtpm and none; lacking on debian13); the unit is checked in a transient unit built from its own properties.
- [F134](findings/F134.md) — sign-* e2e: pkcs11-tool cannot do PSS with this module (no public key object), so `e2e/p11-pss.py` calls it; salts 0/hash/max sign, max+1 and a 246-byte RSA-PKCS payload give CKR_DATA_INVALID; `lacking` (RSAPSS removed) leaves both keys `tpm`; no container can give `encrypted-tpm` (systemd's creds daemon skips the TPM in any container, no override in 257)
- [F135](findings/F135.md) — noplain-* e2e: state dir `/var/lib/private/custodio`, one file per key; `check-no-plaintext.sh` runs unchanged in the container via a read-only mount of both script files
- [F136](findings/F136.md) — tpm-dup-* e2e: reading records with tpm2-tools, second swtpm start/stop, the exact tpm2_readpublic/duplicate/load outputs (0x99D, 0x1DF integrity)
- [F137](findings/F137.md) — pcr-* e2e: root extends PCRs and restarts swtpm (startup-clear resets them) and the service from the guest; a PCR-7-policy object fails with 0x99D after the extension, the keys do not
- [F139](findings/F139.md) — injected failures: a stopped systemd-creds.socket gives CredentialsUnavailable; a stale socket TpmFailed/tpm_device; a failing capability query TpmFailed/tpm_error
- [F140](findings/F140.md) — signing after a TPM clear: KeyLost / CKR_DEVICE_ERROR with a journal entry, keys listed and deletable; a second swtpm isolates the clear; one pkcs11-tool run makes two Sign calls
- [F143](findings/F143.md) — tpm-slots-* e2e: TPM2_PT_HR_TRANSIENT_MIN is the reported minimum (3 in swtpm); a handle left loaded shows in handles-transient; only no-leak is the leak proof
- [F144](findings/F144.md) — journal-kind-* e2e: old-format files placed + restart give the purge entries; a flipped record byte gives key_lost, a missing TPM path or stopped credential socket gives temporarily_unavailable, in every mode
- [F145](findings/F145.md) — M4 manual steps: tpm-record-check.sh (authPolicy empty, TPM_RC_POLICY_FAIL, controls), tpm2_pcrextend PCR 7 substitute, check-no-plaintext exits; list prints no weaker sentence
- [F146](findings/F146.md) — parallel e2e flakes: the host's inotify instance limit (128) runs out with 6 containers; bus reloads fail, names stay activatable; run.sh needs 32 per run + 64
