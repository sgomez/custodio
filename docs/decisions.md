# Decisions

Choices SPEC.md leaves open that a later session might undo without knowing why. An entry goes
here only if all three hold:

1. SPEC.md does not decide it.
2. A reasonable alternative was rejected.
3. Someone could undo it by mistake without this note.

Not here: what a feature builds or how its files are laid out (code and commit), fixes (commit),
research (`docs/findings/`), open work (issues). When a decision changes, edit its entry instead of
adding one that contradicts it. The file stays under 5000 tokens (`just quick`): drop entries that
no longer apply rather than let it grow.

Format: a title and three short bullets, a couple of lines each:

```
## YYYY-MM-DD — Title
- Decision:
- Why:
- Rejected:
```

## 2026-10-27 — Lints declared per crate in custodiod
- Decision: `custodiod/Cargo.toml` has its own `[lints.clippy]` (pedantic plus `unwrap_used`,
  `expect_used`, `panic`, `indexing_slicing`) instead of `workspace = true`.
- Why: Cargo cannot extend `workspace.lints` per crate; the restriction lints are for the service.
- Rejected: all deny lints in the workspace (would bind every crate).

## 2026-10-27 — Supply chain policy
- Decision: `deny.toml` denies duplicate versions (justified `skip` entries only), yanked crates,
  wildcards, unknown registries and git sources; permissive licences plus MPL-2.0; OpenSSL banned.
- Why: the most conservative reading of SPEC; EUPL-1.2 compatibility.
- Rejected: warning on duplicates; GPL-family licences.

## 2026-10-27 — Key store refuses instead of repairing
- Decision: a state dir or key file whose mode is not exactly 0700/0600, whose owner is not the
  service, or that is a symlink is rejected, not fixed. Keys are written to a temp file and
  `hard_link`ed into place.
- Why: a loosened mode may mean the key was exposed, so a person should look; `hard_link` is atomic
  and never overwrites.
- Rejected: auto-chmod (hides exposure); `rename` (overwrites silently).

## 2026-10-27 — `.p12` import
- Decision: `p12-keystore` parses the file; the leaf certificate is the one whose public key equals
  the key's, not the one `localKeyId` points to.
- Why: pure Rust (OpenSSL is banned); `localKeyId` is attacker-controlled input.
- Rejected: `pkcs12` with `rsa`/`p256` directly (more code); trusting `localKeyId`.

## 2026-10-27 — RSA crate and RUSTSEC-2023-0071
- Decision: `rsa` pinned to `=0.10.0-rc.19`, RUSTSEC-2023-0071 (Marvin) ignored in `deny.toml` with
  its justification. PSS offers SHA-256/384/512, not SHA-1.
- Why: no fixed release exists; each signature needs a polkit approval, so timing samples cannot be
  gathered at scale; blinding is on; a same-uid attacker is out of scope.
- Rejected: OpenSSL (banned); `sad-rsa` (unknown fork); no RSA (SPEC requires it).

## 2026-10-27 — polkit fails closed
- Decision: only `is_authorized == true` signs; a challenge, a denial, a bus error, a malformed
  reply or no polkit are refusals. The `Authorizer` trait is async.
- Why: fail closed; a blocking trait would stall the D-Bus service's executor.
- Rejected: pid/uid subjects (racy; SPEC wants polkit to resolve the pidfd).

## 2026-10-27 — D-Bus mechanisms as PKCS#11 numbers
- Decision: `Sign` takes `CKM_*` numbers for mechanism and hash, checked before any key is read.
- Why: the module passes them through unchanged; numbers leave less to parse than names.
- Rejected: string mechanism names.

## 2026-10-27 — Import password only from the terminal
- Decision: `custodio import` reads the password from `/dev/tty` with echo off; no option, stdin or
  environment variable, and no `rpassword`.
- Why: argv and the environment leak through `/proc` and shell history; `rpassword` uses `unsafe`.
- Rejected: reading stdin when piped (invites passwords in files).

## 2026-10-27 — PKCS#11 module: a connection per call
- Decision: each call opens and drops its own system-bus connection; the one mutex is never held
  across D-Bus and is held across `fork`. Unsupported functions return `CKR_FUNCTION_NOT_SUPPORTED`;
  denial is `CKR_FUNCTION_FAILED`; without the service `C_GetSlotList` returns no slots.
- Why: fork and thread safety inside Firefox and LibreOffice (`docs/findings/F18-dbus-in-clients.md`);
  consumers keep their other modules when the service is down.
- Rejected: a persistent connection; NULL entries in the function list; `CKR_FUNCTION_CANCELED`.

## 2026-10-27 — `CKA_ALWAYS_AUTHENTICATE` stays false
- Decision: `C_Sign` itself asks polkit on every signature; the attribute stays false.
- Why: NSS logs in per signature only with an application password callback, and Firefox logs in
  with `CKU_USER` (`docs/findings/F18-always-authenticate.md`).
- Rejected: `true` (clients that skip the login still reach `C_Sign`; those that log in prompt twice).

## 2026-10-27 — The `fuzzing` feature never ships
- Decision: under `fuzzing` the module signs through a fake that never asks polkit; `lib.rs` has a
  `compile_error!` for a release build with it, and `lint-fuzz` checks that the error fires.
- Why: fuzzing through the function list against the real backend is slow and nondeterministic.
- Rejected: fuzzing against the D-Bus backend.

## 2026-10-27 — Own CRAP scorer
- Decision: `crates/crap` scores functions from the llvm-cov JSON, threshold 30; only
  `ffi/fuzzing.rs` is excluded. Coverage has no minimum.
- Why: no maintained Rust CRAP tool reads llvm-cov output; SPEC wants coverage as a report.
- Rejected: a Python script with a token heuristic; a coverage target.

## 2026-10-27 — Static `custodio` user
- Decision: `data/sysusers.d/custodio.conf` creates a static `custodio` account; the unit keeps
  `DynamicUser=yes`, which reuses it.
- Why: dbus-daemon and dbus-broker resolve `<policy user=…>` when they load, so with a purely
  dynamic user nobody could own the bus name.
- Rejected: a group or `at_console` bus policy (broader).

## 2026-10-27 — Fixes for a live systemd
- Decision: `custodiod` canonicalizes `STATE_DIRECTORY`; the polkit action declares
  `org.freedesktop.policykit.owner` = `unix-user:custodio`; `postinst` ignores reload failures.
- Why: `DynamicUser=` makes the state dir a symlink; polkit refuses `CheckAuthorization` on another
  user's subject otherwise; reloads fail in a chroot.
- Rejected: relaxing the store's symlink check; running as root (SPEC forbids).

## 2026-11-07 — CI
- Decision: required checks `ci`, `e2e`, `just mutants (diff)`, `e2e-vm`, one workflow each (ruleset
  "main: pull requests"); actions pinned by SHA, tools to `mise.toml`; every PR runs all of them
  (`e2e-vm` starts the VM only on a milestone PR), a weekly job sweeps every mutant.
  `just signoff ci|mutants` runs a check locally, pushes and signs off (gh-signoff): CI skips it.
  A milestone PR must be signed off by `just release` (after `check-slow`); e2e still runs.
- Why: a milestone's mutants diff (882) passed the 30-minute timeout; e2e alone found a product bug
  that local runs did not; coverage and memory-safety after the merge were no gate.
- Rejected: a skip label (no proof anything ran); sharding a milestone's diff; tagging before CI;
  requiring the `e2e-vm <mode>` jobs (skipped, so never reported, on an ordinary PR).

## 2026-10-28 — Truncation of SHA-384/512 digests for P-256 happens in the service
- Decision: the module passes the full digest for `CKM_ECDSA_SHA384/512`; the service's
  `CKM_ECDSA` truncates it to the leftmost 32 bytes (FIPS 186, SEC 1).
- Why: the service owns the curve; the module stays a thin mapper and the interface is unchanged.
- Rejected: truncating in the module (a second place that knows the P-256 order).

## 2026-10-28 — Multi-part sign: a conflicting call ends the operation
- Decision: `C_Sign` after `C_SignUpdate`, and a second call on a session while a part is being
  hashed, return `CKR_OPERATION_ACTIVE` and end the operation; later calls give
  `CKR_OPERATION_NOT_INITIALIZED`. The hash state is dropped, never half-used.
- Why: a caller racing itself must not sign a message it did not intend. SoftHSMv2 returns
  `CKR_OPERATION_NOT_INITIALIZED` for the first case (`docs/findings/F21.md`); ours tells more.
- Rejected: keeping the operation open (a retry could sign another message); SoftHSMv2's code.

## 2026-10-28 — Repeated login and reported session state
- Decision: `C_Login` with `CKU_USER` or `CKU_CONTEXT_SPECIFIC` returns `CKR_OK` every time;
  `C_GetSessionInfo` reports `CKS_RO_PUBLIC_SESSION` before and after any login. `CKU_SO` gives
  `CKR_SESSION_READ_ONLY_EXISTS`, another user type `CKR_USER_TYPE_INVALID` (`docs/findings/F30.md`).
- Why: no client sees a login error; a login keeps no state, so nothing can go stale.
- Rejected: `CKR_USER_ALREADY_LOGGED_IN` on a repeat (breaks clients that log in per operation);
  `CKS_RO_USER_FUNCTIONS` after a login (per-session state and a logout rule).

## 2026-10-28 — Audit: own journal writer, whole entries, never blocking
- Decision: `audit::JournalSink` writes the Native Journal Protocol itself over a non-blocking
  `UnixDatagram`. An entry over `MAX_DATAGRAM` is `AuditError::TooLarge`, never truncated or sent
  by `memfd`; a busy journal is `Io(WouldBlock)` and the signature is refused. Without bus
  credentials an entry omits `CUSTODIO_UID`/`CUSTODIO_PID` and says `uid unknown pid unknown`.
- Why: no dependency to vet and no `unsafe`; a cut entry is a wrong record; a stuck journal must
  not hang a signature; nothing may be invented.
- Rejected: a journald crate; truncation or `memfd`; blocking or dropping the entry; uid/pid 0.

## 2026-10-28 — Miri runs only the ffi tests
- Decision: `just miri` runs `ffi::` tests only; the other modules `#![forbid(unsafe_code)]`, and
  `unsupported.rs` stubs touch no pointer.
- Why: the RSA/ECDSA tests took over 14 minutes under Miri; ASan still runs all of them.
- Rejected: every test under Miri; no Miri. Widen the filter if a module gains `unsafe`.

## 2026-10-30 — Package version scheme and the place of the service binary
- Decision: the version comes from the workspace: `X.Y.Z-pre` is `X.Y.Z~pre-1` (.deb), release `1`
  with `~pre` (.rpm), `X.Y.Z_pre` pkgrel 1 (Arch). The binary is at `/usr/libexec/custodio/custodiod`
  in the .deb and .rpm and `/usr/lib/custodio/custodiod` in Arch (`packaging/parity-exceptions.txt`);
  one `data/custodio.service`, with `ExecStart` derived per format by `scripts/derive-units.sh`.
  The D-Bus activation file keeps `Exec=/bin/false`.
- Why: from `/usr/lib/custodio` (`lib_t`) Fedora runs the service in `init_t` and its key files get
  `init_var_lib_t` (F54, F55); from `/usr/libexec` (`bin_t`) it is `unconfined_service_t`. Arch has
  no `/usr/libexec`. A real `Exec=` would start the service outside the unit's hardening.
- Rejected: `/usr/lib/custodio` everywhere; `/usr/libexec` on Arch; two unit files; an `Exec=` in
  the activation file; an SELinux policy module (out of scope).

## 2026-10-30 — The install-time ProcessFD check refuses when it has no tool to ask with
- Decision: `packaging/bus-check.sh` asks with `busctl`, else `dbus-send`. A bus socket with
  neither tool is refused with a message to install one; only an absent socket (or nothing
  listening) is "no bus" and installs with a notice.
- Why: installing silently would hide a bus without ProcessFD; the rpm and Arch scripts have no
  pre-dependency, so the deb's `Pre-Depends: systemd` is not relied on.
- Rejected: a missing tool as "no bus"; a tool of our own (nothing can be added for a script that
  runs before the package); pre-depending on dbus.

## 2026-10-30 — The deb pre-depends on systemd and creates the account in preinst
- Decision: `systemd` is in the deb's `Pre-Depends`, not `Depends`. `preinst` creates the account
  with `systemd-sysusers -` from the embedded sysusers text (`scripts/check-sysusers-sync.sh`), on
  `install` and `upgrade`; if that fails, nothing is unpacked.
- Why: dpkg unpacks the bus policy before `postinst` and `dbus-daemon` may load it at once; in one
  transaction `Depends` may not be unpacked when `preinst` runs. Debian policy 7.2 allows this case:
  do not drop it as lint hygiene.
- Rejected: a `useradd` fallback (a second account definition); the account in `postinst`; skipping
  it without the tool. Move `systemd` back to `Depends` only if `preinst` stops needing it.

## 2026-10-30 — Deb scripts: restart marker in /run, notice on stderr, purge as remove
- Decision: `preinst upgrade` creates `/run/custodio-restart-after-upgrade` if the service is
  active; `postinst configure OLD` restarts once only if it exists, and removes it. The removal
  notice goes to stderr on `remove` and `purge`. `postrm remove|purge` stops the service again if
  it is active after the reloads.
- Why: the marker is the only state from `preinst` to `postinst` and must not be under the state
  directory; maintainer stdout can carry debconf's protocol; the second stop covers a D-Bus
  activation between `prerm` and the removal of the files.
- Rejected: `try-restart` in `postinst` (restarts a service started after `preinst`); the marker
  under `/var/lib`; one notice per transaction (another marker).

## 2026-10-30 — Rpm scriptlets: account in %pre from stdin, restart by marker, no systemd macros
- Decision: `%pre` runs the F42 check, `systemd-sysusers -` with the embedded line, and on upgrade
  notes `is-active` in the `/run` marker; the new `%post` reloads, updates the catalog and restarts
  once if the marker exists. No `user()` provide, `%posttrans`, `Requires(pre)` (nfpm cannot write
  it) or `%systemd_*`/`%sysusers_*` macro (nfpm leaves them unexpanded). `%preun 0` stops; `%postun 0`
  reloads, stops again if active, and prints the notice on stderr.
- Why: the old package's `%preun`/`%postun` run after the new `%post`, so only the new package can
  decide; `%systemd_postun_with_restart` is a try-restart that does nothing in a chroot; a `user()`
  provide would create the account before the F42 check. `rpm-ostree uninstall` runs no scriptlet:
  a deviation (`docs/milestones/M2/SPEC_DEVIATIONS.md`, F44).
- Rejected: `%posttrans` (its `$1` cannot tell install from upgrade); `systemd-update-helper`
  (absent in a chroot, enables on install); a `useradd` fallback.

## 2026-10-30 — Arch: hooks do the reloads and the catalog, the account is made in pre_*, a hook restarts
- Decision: the scripts call no `daemon-reload`, bus reload or `journalctl --update-catalog` (the
  system hooks do). `pre_install`/`pre_upgrade` create the account after the F42 check. The restart
  on upgrade is the PostTransaction hook `zz-custodio-restart.hook` (`try-restart`); `pre_remove`
  stops the service.
- Why: a script runs before all PostTransaction hooks, so a reload there is a second call and a
  restart would precede the daemon reload (`docs/findings/F58.md`).
- Rejected: `enqueue-marked` with `Markers=needs-restart` (runs before `dbus-reload`); reloads in
  `post_*`; a marker file; a `useradd` fallback.

## 2026-11-01 — Firefox without the p11-kit proxy: registration by hand in M2
- Decision: where the system NSS does not load `p11-kit-proxy.so` (Arch, Debian), `docs/install.md`
  documents `modutil` per profile; the packages register nothing in Firefox. Settled by the
  milestone approver after F56.
- Why: only Fedora's NSS reads a system policy file that loads the proxy (`docs/findings/F56.md`).
- Rejected: an enterprise policy (one file, would override the administrator's); a `custodio`
  command that edits profiles (left in `docs/milestones.md`, "Firefox without p11-kit").

## 2026-11-01 — A refused sign for a key the caller does not have leaves no journal entry
- Decision: `Sign` for an id the caller does not own (missing, or another uid's) fails as
  `NoSuchKey` before polkit and writes no entry. A failed credentials lookup still writes the
  entry without caller.
- Why: another uid's id must be indistinguishable from a missing one; an entry would turn probing
  of ids into journal noise.
- Rejected: an entry per `NoSuchKey`; following the credentials-failure behaviour.

## 2026-11-03 — TPM parent: a primary recreated from the ECC P-256 SRK template
- Decision: the parent of every TPM key is a transient primary in the owner hierarchy, created on
  each use from the TCG SRK template frozen in code (ECC P-256, AES-128-CFB, SHA-256 name) and
  flushed by the end of the call. No persistent object, no NV index. Approved by the person in F111.
- Why: no NV write, provisioning or shared handle; on the F111 TPM `0x81000001` held a foreign key.
  Accepted cost: about 0.5 s per creation on a discrete TPM, so per signature under F114.
- Rejected: a persistent SRK at `0x81000001`; the RSA 2048 template (3.7 s on hardware); keeping
  the primary loaded across calls (possible later if latency matters).

## 2026-11-03 — TPM RSA keys: the service pads, the TPM does the raw operation
- Decision: TPM RSA keys carry `sign|decrypt`; a signature is `TPM2_RSA_Decrypt` with the null
  scheme over a block the service builds (PKCS#1 v1.5 or EMSA-PSS with the requested salt), checked
  with the public key before it is returned. P-256 uses `TPM2_Sign` with the digest truncated to 32
  bytes and SHA-256. A TPM lacking any F107 item for a key type makes that type use the encrypted
  kind, and `custodio import` says why. Approved by the person in F111.
- Why: every mechanism is served as with the encrypted kind; `TPM2_Sign` gives only the hash-length
  PSS salt and no non-`DigestInfo` payload, and the F111 TPM lacks SHA-512.
- Rejected: `TPM2_Sign` only (fewer mechanisms); fewer mechanisms than the encrypted kind.
  Accepted: root controlling the machine can also decrypt with a TPM RSA key.

## 2026-11-03 — The test-only TPM socket variable
- Decision: `custodiod` reads one variable, `CUSTODIOD_TEST_SWTPM_TCTI`, only as
  `swtpm:path=<absolute path>` (no comma). Unset, it opens `/dev/tpmrm0` and nothing else. A missing
  socket is *absent* (the e2e "no TPM" case); any other value is an *error*, never a fallback:
  malformed, `device:`/`mssim:`/`tabrmd:`, a relative path, a non-socket, a refused connection.
  `TPM2TOOLS_TCTI`, `TSS2_TCTI`, `TPM20TEST_TCTI` and `TCTI` are not read. Nothing in `data/` or
  `packaging/` sets it (a check counts it).
- Why: F108 runs the real package against a software TPM through a drop-in that is not shipped, and
  SPEC says no configuration of the shipped unit can substitute a TPM; one narrow variable cannot
  name a device, a network address or another daemon.
- Rejected: reading `TPM2TOOLS_TCTI`/`TSS2_TCTI` (every `tpm2-tools` session sets them); a
  compile-time test feature (e2e runs the packaged binary); `device:` values.

## 2026-11-05 — The storage kind sits next to the key type in the replies
- Decision: `ImportP12` returns one struct `(key type, kind)` of two strings (`(ss)`); `ListKeys` returns
  `a(sssay)`: id, key type, kind, certificate. The kind is a string, never a number.
- Why: the out signatures changed, so a client written for M3 (`s`, `a(ssay)`) fails to read the
  new replies; the kind goes beside the key type so the old fields keep their positions and
  a new client reads both together.
- Rejected: a separate `GetKind` call (a second round trip, and a race with a delete); a dict
  (`a{sv}`) reply (nothing in this API uses variants); appending the kind after the certificate.

## 2026-11-08 — VM image pinned to one dated serial
- Decision: `e2e/vm/image.sh` pins serial `20261105` (`release-<serial>/`); a cache hit is verified, never refreshed.
- Why: a run record names one image, and a moving "newest" would change results between runs.
- Rejected: the newest release by signature (needs a listing; the image can change under a run).
