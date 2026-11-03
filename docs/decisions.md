# Decisions

Choices SPEC.md leaves open that a later session might undo without knowing why. An entry goes
here only if all three hold:

1. SPEC.md does not decide it.
2. A reasonable alternative was rejected.
3. Someone could undo it by mistake without this note.

Not here: what a feature builds or how its files are laid out (code and commit), fixes (commit),
research (docs/findings.md), open work (issues). When a decision changes, edit its entry instead
of adding one that contradicts it.

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
- Why: Cargo cannot extend `workspace.lints` per crate, and the restriction lints are for the
  service only.
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
- Why: a loosened mode may mean the key was already exposed, so a person should look; `hard_link`
  is atomic and never overwrites.
- Rejected: auto-chmod (hides exposure); `rename` (overwrites silently).

## 2026-10-27 — `.p12` import
- Decision: `p12-keystore` parses the file; the leaf certificate is the one whose public key equals
  the key's, not the one `localKeyId` points to.
- Why: pure Rust (OpenSSL is banned); `localKeyId` is attacker-controlled input.
- Rejected: `pkcs12` with `rsa`/`p256` directly (more code); trusting `localKeyId`.

## 2026-10-27 — RSA crate and RUSTSEC-2023-0071
- Decision: `rsa` pinned to `=0.10.0-rc.19`, and RUSTSEC-2023-0071 (Marvin) ignored in `deny.toml`
  with its justification. PSS offers SHA-256/384/512, not SHA-1.
- Why: no fixed release exists; each signature needs a polkit approval, so timing samples cannot be
  gathered at scale, blinding is on, and a same-uid attacker is out of scope.
- Rejected: OpenSSL (banned); `sad-rsa` (unknown fork); no RSA (SPEC requires it).

## 2026-10-27 — polkit fails closed
- Decision: only `is_authorized == true` signs; a challenge, a denial, a bus error, a malformed
  reply or no polkit are all refusals. The `Authorizer` trait is async.
- Why: fail closed; a blocking trait would stall the D-Bus service's executor.
- Rejected: pid/uid subjects (racy; SPEC wants polkit to resolve the pidfd).

## 2026-10-27 — D-Bus mechanisms as PKCS#11 numbers
- Decision: `Sign` takes `CKM_*` numbers for mechanism and hash, checked before any key is read.
- Why: the module passes them through unchanged, and numbers leave less to parse than names.
- Rejected: string mechanism names.

## 2026-10-27 — Import password only from the terminal
- Decision: `custodio import` reads the password from `/dev/tty` with echo off; no option, stdin or
  environment variable, and no `rpassword`.
- Why: argv and the environment leak through `/proc` and shell history; `rpassword` uses `unsafe`.
- Rejected: reading stdin when piped (invites passwords in files).

## 2026-10-27 — PKCS#11 module: a connection per call
- Decision: each call opens and drops its own system-bus connection; nothing survives a call, and
  the one mutex is never held across D-Bus and is held across `fork`. Unsupported functions are
  stubs returning `CKR_FUNCTION_NOT_SUPPORTED`; denial is `CKR_FUNCTION_FAILED`; without the service
  `C_GetSlotList` returns no slots.
- Why: fork and thread safety inside Firefox and LibreOffice (docs/findings.md); consumers keep
  their other modules when the service is down.
- Rejected: a persistent connection; NULL entries in the function list; `CKR_FUNCTION_CANCELED`.

## 2026-10-27 — `CKA_ALWAYS_AUTHENTICATE` stays false
- Decision: `C_Sign` itself asks polkit on every signature; the attribute stays false.
- Why: NSS logs in per signature only with an application password callback, and Firefox logs in
  with `CKU_USER`, so the attribute cannot force a prompt (docs/findings.md, section 1).
- Rejected: `true` (clients that skip the login still reach `C_Sign`; those that log in prompt
  twice).

## 2026-10-27 — The `fuzzing` feature never ships
- Decision: under the `fuzzing` feature the module signs through a fake that never asks polkit.
  `lib.rs` has a `compile_error!` for a release build with the feature, and `lint-fuzz` checks that
  error fires.
- Why: fuzzing through the function list against the real backend is slow and nondeterministic.
- Rejected: fuzzing against the D-Bus backend.

## 2026-10-27 — Own CRAP scorer
- Decision: `crates/crap` scores functions from the llvm-cov JSON, threshold 30; only the fuzz
  harness `ffi/fuzzing.rs` is excluded. Coverage itself has no minimum.
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
- Why: `DynamicUser=` makes the state dir a symlink the store would reject; polkit refuses
  `CheckAuthorization` on another user's subject otherwise; reloads fail in a chroot.
- Rejected: relaxing the store's symlink check; running as root (SPEC forbids).

## 2026-10-28 — CI
- Decision: one required `ci` check; actions pinned by SHA and tools to `mise.toml` versions; jobs
  by build family with caches keyed on toolchain and lockfiles; PRs run lint, test and mutants on
  the diff, main adds coverage and nightly, a weekly job sweeps every mutant. No pre-push hook.
- Why: one serial job took 20 minutes; floating versions and caches broke CI or missed
  without any change in the repository.
- Rejected: a job per recipe (same artifacts rebuilt); every mutant on every push; `check-slow`
  before each push (repeats CI).

## 2026-10-28 — Truncation of SHA-384/512 digests for P-256 happens in the service
- Decision: the module passes the full SHA-384/512 digest for `CKM_ECDSA_SHA384/512`; the
  service's `CKM_ECDSA` truncates it to the leftmost 32 bytes (FIPS 186, SEC 1).
- Why: the service owns the curve and already does it (`ecdsa_long_digest_standard_result`);
  the module stays a thin mapper and the D-Bus interface does not change.
- Rejected: truncating in the module (a second place that must know the P-256 order, and a
  caller of raw `CKM_ECDSA` would still reach the service's truncation).

## 2026-10-28 — Multi-part sign: a conflicting call ends the operation
- Decision: `C_Sign` after `C_SignUpdate`, and a second call on a session while a part is being
  hashed, return `CKR_OPERATION_ACTIVE` and end the operation; later calls give
  `CKR_OPERATION_NOT_INITIALIZED`. The hash state is dropped, never half-used.
- Why: SPEC ends an operation on any failure but a small buffer; a caller racing itself must not
  be able to sign a message it did not intend. SoftHSMv2 returns `CKR_OPERATION_NOT_INITIALIZED`
  for the first case (docs/findings.md); the project keeps the more telling code.
- Rejected: keeping the operation open after the conflict (a retry could sign a different
  message); copying SoftHSMv2's code for the first call.

## 2026-10-28 — Repeated login and reported session state
- Decision: `C_Login` with `CKU_USER` or `CKU_CONTEXT_SPECIFIC` returns `CKR_OK` every time, never
  `CKR_USER_ALREADY_LOGGED_IN`; `C_GetSessionInfo` keeps reporting `CKS_RO_PUBLIC_SESSION` before
  and after any login or logout. `CKU_SO` gives `CKR_SESSION_READ_ONLY_EXISTS` (every session is
  read-only), another user type `CKR_USER_TYPE_INVALID`. Interim: settle it by the manual
  acceptance clients (SPEC open question).
- Why: the most tolerant choice that keeps the M0 tests green; no client sees a login error and
  the reported state is never an error. A login keeps no state, so nothing can go stale.
- Rejected: `CKR_USER_ALREADY_LOGGED_IN` on a repeat (breaks clients that log in per operation);
  reporting `CKS_RO_USER_FUNCTIONS` after a login (needs per-session state and a logout rule).

## 2026-10-28 — Own native-journal writer instead of a crate
- Decision: `audit::JournalSink` writes the Native Journal Protocol itself (about 20 lines of encoding).
- Why: no new dependency to vet under cargo-deny, and no `unsafe` (`UnixDatagram` only).
- Rejected: a journald crate (supply chain, and most use `memfd` or `libsystemd`).

## 2026-10-28 — Oversize audit entry is an error
- Decision: an entry whose encoding exceeds `MAX_DATAGRAM` gives `AuditError::TooLarge`; it is never
  truncated and never sent through `memfd`/`SCM_RIGHTS`.
- Why: a cut entry is a wrong audit record; entries are small by construction (typed fields).
- Rejected: truncation; `memfd` passing for large entries.

## 2026-10-28 — Non-blocking journal send
- Decision: the datagram is sent with a non-blocking socket; a busy journal gives `Io(WouldBlock)`.
- Why: a stuck journal must not hang a signing request; the caller (F25) turns the error into a refused
  signature.
- Rejected: blocking send, or retrying and dropping the entry.

## 2026-10-28 — Audit entries may have no caller
- Decision: `Entry::without_caller` entries omit `CUSTODIO_UID`/`CUSTODIO_PID` and say `uid unknown pid unknown`.
- Why: the bus gave no credentials and nothing may be invented.
- Rejected: uid/pid 0, or refusing without an entry.

## 2026-10-28 — Miri runs only the ffi tests
- Decision: `just miri` runs `ffi::` tests only. `module`, `composed`, `token`, `backend`, `fake` and the
  crate tests all `#![forbid(unsafe_code)]`. `unsupported.rs` allows `unsafe` but its stubs only return
  `CKR_FUNCTION_NOT_SUPPORTED` without touching their pointers, and it has no tests.
- Why: the pure-Rust RSA/ECDSA tests took over 14 minutes under Miri and made `just check-slow` too slow;
  Miri only checks `unsafe` code. Miri no longer covers those safe tests; ASan still runs all of them.
- Rejected: running every test under Miri; skipping Miri. Widen the filter if a module gains `unsafe`.

## 2026-10-30 — Package version scheme and the place of the service binary
- Decision: the version comes from the workspace; `X.Y.Z-pre` becomes `X.Y.Z~pre-1` (.deb), release `1` with `~pre` (.rpm)
  and `X.Y.Z_pre` with pkgrel 1 (Arch, which forbids `-` in pkgver and where nfpm drops the prerelease). `just package
  version=...` overrides it so a test can build an N+1 package. The D-Bus activation file keeps `Exec=/bin/false`, so only the
  unit starts the service and there is one unit source and one activation file. Since F61 the service binary is at
  `/usr/libexec/custodio/custodiod` in the .deb and the .rpm and at `/usr/lib/custodio/custodiod` in the Arch package
  (`packaging/parity-exceptions.txt` lists the difference); the unit's `ExecStart` follows each path, derived per format from
  `data/custodio.service` by `scripts/derive-units.sh` (SPEC's open question "Arch and `/usr/libexec`" was settled by the approved
  feature list as option (b): one source, per-format path).
- Why: on Fedora `/usr/lib/custodio` is labelled `lib_t`, so systemd leaves the service in `init_t`, systemd's own domain, and the
  key files it writes get `init_var_lib_t` (seen in F54 and F55). From `/usr/libexec` (`bin_t`) it runs in `unconfined_service_t`,
  as SPEC expects. Arch has no `/usr/libexec`, and its guidelines ask for `/usr/lib/<pkg>/`. The activation file stays on
  `/bin/false`: a real `Exec=` there would start the service outside the unit's hardening.
- Rejected: `/usr/lib/custodio` for all three (the first choice of M2; wrong SELinux domain on Fedora); `/usr/libexec` in the Arch
  package too (against Arch's rules); two unit files (they would drift apart); an `Exec=` in the activation file; an SELinux policy
  module to fix the domain (out of scope in SPEC).

## 2026-10-30 — The install-time ProcessFD check refuses when it has no tool to ask with
- Decision: the check (`packaging/bus-check.sh`) asks with `busctl`, else `dbus-send`. A bus socket that exists with neither tool
  installed is refused, with a message to install one; only an absent socket (or nothing listening) is "no bus" and installs with a notice.
  The deb's `Pre-Depends: systemd` (next entry) puts `busctl` on the system when `preinst` runs, but this check does not rely on it and
  is not changed for it: it still tries `busctl`, then `dbus-send`, and refuses when it has neither.
- Why: a deb `preinst` can rely on Essential packages only unless it pre-depends, so neither tool was guaranteed when this was decided; installing
  silently would hide a bus without ProcessFD, which the check exists to catch. The rpm and Arch scripts have no pre-dependency at all.
- Rejected: treating a missing tool as "no bus" (silent install); querying the bus with a tool of our own (nothing may be added to the
  package for a script that runs before it). `Pre-Depends` on systemd for this check alone was rejected here because of the dependency gate
  and the minimal-install goal; that reason no longer holds, since F43 pre-depends on systemd for another reason and `systemd` was already a
  dependency, so `Pre-Depends` changes when it is installed and not what gets installed. Pre-depending on dbus is still rejected: nothing needs it.

## 2026-10-30 — The deb pre-depends on systemd and creates the account in preinst
- Decision: `systemd` is in the deb's `Pre-Depends` (and no longer in `Depends`; rpm and Arch lists are unchanged). `preinst` creates the
  `custodio` account with `systemd-sysusers -`, from the sysusers text embedded in the script (`scripts/check-sysusers-sync.sh` keeps it equal
  to `data/sysusers.d/custodio.conf`), on `install` and on `upgrade`. If the tool is missing or fails, `preinst` fails and nothing is unpacked.
- Why: dpkg unpacks the bus policy before `postinst`, and `dbus-daemon` may load it at once, so the account must exist before; and dpkg
  guarantees `Depends` only for `postinst`, so in one transaction (debootstrap, image builds) `systemd` may not be unpacked when `preinst`
  runs. Debian policy 7.2 discourages `Pre-Depends`; this is the case it allows. Do not drop it as lint hygiene.
- Rejected: a `useradd`/`adduser` fallback in `preinst` (a second account definition to keep in sync with the sysusers file, and different
  uid choice); creating the account in `postinst` (the policy would name a missing user); skipping account creation when the tool is missing.
  A later session may move `systemd` back to `Depends` only if `preinst` stops needing `systemd-sysusers`.

## 2026-10-30 — Deb scripts: restart marker in /run, notice on stderr, purge as remove
- Decision: `preinst upgrade` notes that `systemctl is-active` said active by creating `/run/custodio-restart-after-upgrade`; `postinst
  configure OLD` restarts once (`deb-systemd-invoke restart`) only if it exists, and removes it. Without it (an upgrade from the cargo-deb package
  needs none: the new `preinst` runs first) the service is left alone. The removal notice goes to stderr, on `remove` and on `purge`
  (printed twice when an installed package is purged). `postrm remove|purge` stops the service again if it is active after the reloads.
- Why: the marker is the only state that survives from `preinst` to `postinst`, and it must not be under the state directory; stdout of
  maintainer scripts can carry debconf's protocol; the second stop covers a D-Bus activation between `prerm` and the removal of the files.
- Rejected: `try-restart` in `postinst` (restarts a service that was started after `preinst`, and cannot tell a stale state); the marker under
  `/var/lib` (state directory); one notice per transaction (needs another marker).

## 2026-10-30 — Rpm scriptlets: account in %pre from stdin, restart by marker, no systemd macros
- Decision: `%pre` runs the F42 check, then `systemd-sysusers -` with the sysusers line embedded in the scriptlet (kept equal to the sysusers
  file by `scripts/check-sysusers-sync.sh`), then on an upgrade notes `is-active` in `/run/custodio-restart-after-upgrade`; the new `%post`
  reloads, updates the catalog and restarts once if the marker exists. The rpm has no `user()` provide, no `%posttrans`, no `Requires(pre)`
  (nfpm cannot write it; the plain `Requires: systemd` orders it), and no `%systemd_*` or `%sysusers_*` macro (nfpm leaves them unexpanded).
  `%preun 0` stops the service; `%postun 0` reloads, stops it again if active, and prints the notice on stderr (as the deb).
- Why: the old package's `%preun`/`%postun` run after the new `%post`, and the old package may have none (the first nfpm rpm replaces the M1 rpm),
  so only the new package's own scriptlets can decide; `%systemd_postun_with_restart` marks for a try-restart by a file trigger at the end of
  the transaction and does nothing in a chroot or an image build, and the same `try-restart` was rejected for the deb (F43). A `user()`
  provide would make rpm create the account before the F42 check.
- Rejected: `%posttrans` for the restart (its `$1` cannot tell install from upgrade, and it would restart after the old files are removed); the
  helper `systemd-update-helper` (absent in a chroot, enables and presets on install); a `useradd` fallback (see the deb entry).
- Not decided here: the notice for `rpm-ostree uninstall` (no scriptlet of the removed package runs there): decided as a deviation, see the F44 entry in `SPEC_DEVIATIONS.md`.

## 2026-10-30 — Arch: hooks do the reloads and the catalog, the account is made in pre_*, a hook restarts
- Decision: the scripts call no `daemon-reload` (`30-systemd-daemon-reload-system` does), no bus reload (`dbus-reload`) and no `journalctl --update-catalog`
  (`25-systemd-catalog`). `pre_install` and `pre_upgrade` create the account with `systemd-sysusers -`, after the F42 check. The restart on upgrade is the
  PostTransaction hook `zz-custodio-restart.hook` (`systemd-hook restart` = `try-restart`); `pre_remove` stops the service on removal.
- Why: a script runs before all PostTransaction hooks, so a reload in it would be a second call and a restart in it would precede the daemon reload; the
  sysusers hook also runs after the bus policy is unpacked. `try-restart` needs no marker, so nothing is written (docs/findings.md, "F58").
- Rejected: `enqueue-marked` with `Markers=needs-restart` (runs before `dbus-reload`, needs a script to set the property); reloads repeated in `post_*`;
  a marker file as in the deb; a `useradd` fallback.
- Not covered: `pacman --noscriptlet` and `pacman -U` into a `--root` without hooks run no scripts or hooks, as for any package. A real running systemd is F45.

## 2026-11-01 — Firefox without the p11-kit proxy: registration by hand in M2
- Decision: where the system NSS does not load `p11-kit-proxy.so` (Arch, Debian), `docs/install.md` documents registering the
  module per profile with `modutil`; the packages register nothing in Firefox. Settled by the milestone approver after F56.
- Why: only Fedora's NSS reads a system policy file that loads the proxy (`docs/findings.md`, F56); elsewhere nothing system-wide is read.
- Rejected: an enterprise policy (`/etc/firefox/policies/policies.json` is one file, it would override the administrator's); for
  M2, a `custodio` command that edits the user's profiles (left in `docs/milestones.md`, "Firefox without p11-kit").

## 2026-11-01 — A refused sign for a key the caller does not have leaves no journal entry
- Decision: `Sign` for an id the caller does not own (missing, or another uid's) fails as `NoSuchKey`
  before polkit and writes no entry, the way invalid arguments do. A failed credentials lookup still
  writes the entry without caller, as in M1.
- Why: the lookup precedes polkit so that another uid's id is indistinguishable from a missing one
  (same error, same polkit calls, same journal); an entry would turn probing of ids into journal noise.
- Rejected: an entry per `NoSuchKey` (as M1 had after polkit); following the credentials-failure
  behaviour (that entry exists because the caller is unknown, which is not the case here).

## 2026-11-03 — TPM parent: a primary recreated from the ECC P-256 SRK template
- Decision: the parent of every TPM key is a transient primary in the owner hierarchy, created on each use from the TCG SRK
  template frozen in code (ECC P-256, AES-128-CFB, SHA-256 name) and flushed by the end of the call. The service writes no
  persistent object and no NV index. Approved by the person in F111.
- Why: no NV write, no provisioning step, no shared handle; on the hardware TPM of F111 `0x81000001` already held a foreign
  key. Accepted cost: about 0.5 s per creation on a discrete TPM (494 ms on the STM of F111), so per signature under F114.
- Rejected: a persistent SRK at `0x81000001` (NV write, owner password when set, foreign key, eviction on removal); the RSA
  2048 template (3.7 s per creation on hardware); keeping the primary loaded across calls (possible later if latency matters).

## 2026-11-03 — TPM RSA keys: the service pads, the TPM does the raw operation
- Decision: TPM RSA keys carry `sign|decrypt`; a signature is `TPM2_RSA_Decrypt` with the null scheme over a block the service
  builds (PKCS#1 v1.5 or EMSA-PSS with the requested salt), checked with the public key before it is returned. P-256 uses
  `TPM2_Sign` with the digest truncated to 32 bytes and SHA-256. A TPM lacking any item of the F107 list for a key type makes
  the whole type use the encrypted kind, and `custodio import` says why. Approved by the person in F111.
- Why: every mechanism is served with the bounds of the encrypted kind. `TPM2_Sign` alone gives only the hash-length PSS
  salt and no non-`DigestInfo` payload, and the STM TPM of F111 lacks SHA-512, which this way does not need.
- Rejected: `TPM2_Sign` only (way (a): fewer mechanisms, RSA would lack on TPMs without SHA-512); serving a TPM key with
  fewer mechanisms than the encrypted kind. Accepted: root controlling the machine can also decrypt with a TPM RSA key.
