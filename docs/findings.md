# Findings on the open questions in SPEC.md

Evidence is source reading at the stated versions plus one experiment: the cryptoki test
`signing_leaves_no_helper_threads` (thread counts around `C_Sign`, section 2). Each claim is marked **verified** (read in source or release notes) or **inferred**. Versions
read: NSS `NSS_3_110_RTM` (same as Debian trixie), Firefox `main`/`esr128`/`esr140`,
LibreOffice `main`, zbus 6.1.0 (our `Cargo.lock`), pkcs11-provider and libp11 default branches
(Oct 2026, not the exact distro versions). Distribution data: Repology API, dated 2026-10-27.

## 1. `CKA_ALWAYS_AUTHENTICATE` and `C_Login(CKU_CONTEXT_SPECIFIC)`

| Client | Behaviour | Status |
|---|---|---|
| NSS | `PK11_SignWithMechanism` (`lib/pk11wrap/pk11obj.c`): if the key has `CKA_ALWAYS_AUTHENTICATE`, it calls `PK11_DoPassword(..., contextSpecific=TRUE)` between `C_SignInit` and `C_Sign`; the result is ignored. `PK11_DoPassword` asks the application's password callback first; only with a password (or a protected authentication path) does `pk11_CheckPassword` call `C_Login(CKU_CONTEXT_SPECIFIC)`. | verified |
| NSS tools without a password callback (`certutil`) | No callback means no `C_Login`; NSS calls `C_Sign` anyway. | verified |
| Firefox | With `CKF_PROTECTED_AUTHENTICATION_PATH` it shows its own dialog and runs `PK11_CheckUserPassword(slot, NULL)` on a background task: `C_Logout` then `C_Login(CKU_USER, NULL, 0)` on the slot's default session. It is not `CKU_CONTEXT_SPECIFIC` on the signing session. | verified |
| LibreOffice | `GetPasswordFunction` always shows a password dialog; the typed value is ignored on a protected-path token. Cancel skips the login. | verified; the follow-on `C_Login(CKU_CONTEXT_SPECIFIC)` after a password is inferred |
| OpenSSL pkcs11-provider | `p11prov_sig_init` reads `CKA_ALWAYS_AUTHENTICATE` after `C_SignInit` and calls `C_Login(CKU_CONTEXT_SPECIFIC)`, with no PIN when the token has `CKF_PROTECTED_AUTHENTICATION_PATH`. | verified |
| OpenSSL libp11 engine | `p11_pkey.c`: after `C_SignInit`, `pkcs11_authenticate` when the attribute is set; `C_Login(CKU_CONTEXT_SPECIFIC, NULL, 0)` on a protected path, a PIN prompt otherwise. | verified |

Conclusion: all three honour the attribute, but NSS only when the application cooperates, and
Firefox does it with `CKU_USER` rather than a context login. A pause cannot be assumed
per signature at the login step.

Decision for Custodio: keep `CKA_ALWAYS_AUTHENTICATE = false` (as `token.rs` does) and make
`C_Sign` itself call polkit on every signature. That is correct with every client above, needs no
PIN or login, and is what the spec requires ("every signature calls polkit"). Clients must
tolerate `C_Sign` blocking for as long as the person takes to answer.

## 2. D-Bus client inside third-party processes

- NSS calls `C_Initialize` with `CKF_OS_LOCKING_OK | CKF_LIBRARY_CANT_CREATE_OS_THREADS`
  (`pk11load.c`, verified). A module must not create threads then. Custodio opens a connection
  per call inside `zbus::block_on` and drops it. **Experiment (verified):** the cryptoki test
  `signing_leaves_no_helper_threads` counts `/proc/self/task` in a process that loaded the
  built `.so`: 2 threads (the test harness's own) before the first `C_GetSlotList`/`C_Sign`,
  2 right after `C_Sign` (a full `Connection::system()`, the polkit round trip, the reply), and
  2 two seconds later. No thread is left behind after `C_Sign`. The test samples only before and
  after the call, so a thread started and joined inside `C_Sign` would not be seen; that is
  **not measured** (source reading: our path hands zbus no blocking work). The built `.so` does
  contain zbus's `zruntime` unblock pool (string "failed to spawn a thread for blocking work");
  it spawns threads only for work handed to it, and our call path does not hand it any
  (inferred). A future zbus or a new code path could change that, so the test guards the
  leftover-thread case.
- NSS treats `CKR_CRYPTOKI_ALREADY_INITIALIZED` as success (verified). Modules are called from
  several threads (verified: NSS task queue, main thread, Firefox's background protected-auth
  task); the module is thread-safe (cryptoki integration test `threads`).
- NSS registers no `pthread_atfork` handler for external modules (verified). After a fork,
  `NSS_ContextInit` calls `SECMOD_RestartModules`, which re-initializes a module only if
  `C_GetSlotList` fails (verified). So the module must be correct in a child by itself:
  `ffi.rs` registers `pthread_atfork` and holds the state lock across `fork`; the module keeps
  no connection or thread between calls (no thread left behind: experiment above). The `forks` cryptoki test forks
  while another thread repeatedly calls `get_slots_with_token`, then checks the child does not
  deadlock and can sign. It does **not** fork while a `C_Sign` is in progress (blocked on
  polkit); that case is untested. In it the child would only see a copy of a half-finished
  call on a thread that does not exist in the child, so it is harmless as long as the child
  starts new calls from scratch, which the per-call connection guarantees (inferred).
- Firefox loads user PKCS#11 modules only in the parent process; other processes use
  `NSS_NoDB_Init` (verified). The utility-process option is off by default and Nightly-only
  (verified). Firefox children come from a fork server (inferred: not forked from the
  NSS-initialized parent).
- LibreOffice: `oosplash` starts `soffice.bin` with fork+exec and has no NSS; NSS is loaded in
  `soffice.bin` (verified). Helper processes are fork+exec, so the atfork handlers matter only
  before `exec`.
- zbus has no fork handling (grep, verified); after `fork` only the calling thread exists, so
  holding no connection or thread across calls is what makes this safe (the no-leftover-thread part
  verified by experiment; the rest inferred, partly covered by the `forks` test).
- Not tested: a real Firefox or LibreOffice session. A human should try signing from both once
  a graphical session is available.

## 3. Minimum versions and distributions

Why the minimums: polkit 124 added pidfd support (`pidfd` parameter in `CheckAuthorization`,
polkit NEWS, verified). dbus 1.15.8 added `ProcessFD` to `GetConnectionCredentials` (dbus NEWS,
verified); stable releases are 1.16.0 and later. dbus-broker 34 added it (NEWS, verified). polkit's
own code uses it: `polkitsystembusname.c` calls `GetConnectionCredentials` and reads the
`ProcessFD` key into a pidfd (polkit `main`, read 2026-10-27, verified). polkit 124 does
this too: its source was read at tag `124` and in the Ubuntu 24.04 package (see "polkit 124 and
ProcessFD" below). Releases before 124 were not read. So polkit 124+ on a bus that
exposes `ProcessFD` is enough; on a bus without it polkit falls back to the PID, which is
what makes the older rows unsafe against PID reuse.

| Release | polkit | dbus-daemon / dbus-broker | Meets? |
|---|---|---|---|
| Debian 12 | 122 | 1.14.10 / 33 | No |
| Debian 13 | 126 | 1.16.2 / 37 | Yes |
| Ubuntu 22.04 | 0.105 | 1.12.20 / 29 | No |
| Ubuntu 24.04 | 124 | 1.14.10 / 35 | Only with dbus-broker installed |
| Ubuntu 25.10 | 126 | 1.16.2 / 37 | Yes |
| Ubuntu 26.04 | 127 | 1.16.2 / 37 | Yes |
| Fedora 41 | 125 | 1.14.10 / 36 | Yes (dbus-broker default, inferred) |
| Fedora 42, 43 | 126 | 1.16.x / 36-37 | Yes |
| RHEL/Alma/Rocky 9 | 0.117 | 1.12.20 / 28 | No |
| RHEL/Alma 10 | 125 | 1.14.10 / 36 | Yes with dbus-broker (the default, inferred) |
| openSUSE Leap 15.6 | 121 | 1.12.2 / 28 | No |
| openSUSE Leap 16.0 | 123 | 1.14.10 / 36 | No (polkit) |
| openSUSE Tumbleweed | 128 | 1.14.10 / 37 | Only with dbus-broker |
| Arch | 128 | 1.16.2 / 37 | Yes with dbus-broker (the default, observed in the e2e image) |

"Default bus" is inferred for rows not run; package versions were checked, not each distribution's default. Observed in the e2e images: Fedora 44, Alma 10 and Arch run dbus-broker (see "End-to-end targets Fedora 44 and Alma 10" and "End-to-end target Arch").
Open risk: the end-to-end runs cover Debian 13, Ubuntu 26.04, Fedora 44, Alma 10 and Arch; no other row was run.
RHEL 10 was checked through CentOS Stream 10 and the AlmaLinux 10 repository.

Consequence: supported targets are Debian 13, Ubuntu 25.10 and later, Fedora 41 and later,
RHEL/Alma 10 and Arch. Ubuntu 24.04 works only with `dbus-broker`. Debian 12, Ubuntu 22.04,
RHEL 9 and Leap are out. The only package built is the Debian 13 `.deb`; the end-to-end suite
runs on trixie (polkit 126, dbus-daemon 1.16.2).

## 3a. polkit 124 and ProcessFD (F41, 2026-10-30)

Question (SPEC.md open question): does polkit 124 take the pidfd of a system-bus-name subject from
the `ProcessFD` key of `GetConnectionCredentials`, or fall back to the PID? Read by a subagent.

Sources:
- Upstream tag `124`, commit `82f0924dc0eb23b9df68e88dbaf9e07c81940a5a` ("Release 124"):
  `git clone https://gitlab.freedesktop.org/polkit/polkit.git && git -C polkit checkout 124`.
- Ubuntu noble source package `policykit-1` (binary `polkitd`), version `124-2ubuntu1.24.04.4`
  (Updates and Security, published 2026-09-15). Found with
  `curl -sL "https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedSources&source_name=policykit-1&distro_series=https://api.launchpad.net/1.0/ubuntu/noble&exact_match=true&status=Published"`.
  Files under `https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/policykit-1/124-2ubuntu1.24.04.4/`:
  `policykit-1_124.orig.tar.gz` (sha256 `72457d96a0538fd03a3ca96a6bf9b7faf82184d4d67c793eb759168e4fd49e20`),
  `policykit-1_124-2ubuntu1.24.04.4.debian.tar.xz` (sha256 `9383eaad67e9a33bf0955d8acbd553f041c3b1960c4eed1a9cfabf36024e1716`).
- Ubuntu patch list (`debian/patches/series`): `02_gettext.patch`, `08_chdir_root.patch`,
  `Turn-local-modifications-of-mocklibc-into-patches-and-app.patch`, `debian/01_pam_polkit.patch`,
  `debian/50-default.rules-Replace-wheel-group-with-sudo-group.patch`,
  `debian/Don-t-use-PrivateNetwork-yes-for-the-systemd-unit.patch`, `git-action-directories.patch`,
  `CVE-2025-7519.patch`, `CVE-2026-4897.patch`, `CVE-2026-85498.patch`.
  Of the files cited below only `polkitbackendinteractiveauthority.c` is touched, by
  `git-action-directories.patch` (one hunk near line 291, action directories). No patch touches the
  other cited files and none mentions pidfd or ProcessFD. In `policykit-1_124.orig.tar.gz` (the
  unpatched upstream release tarball) the cited files are byte-identical to tag `124` (`cmp`).

Chain (line numbers at tag `124`):
1. `GetConnectionCredentials` is called: `src/polkit/polkitsystembusname.c`,
   `polkit_system_bus_name_get_creds_sync`, lines 486-530 (call at 516-527, through
   `g_dbus_connection_call_with_unix_fd_list_sync`, so the reply's fd list is received). Verified.
   Only `UnknownMethod` falls back to the PID-only `polkit_system_bus_name_get_creds_fallback` (line 394).
2. The `ProcessFD` key is extracted: same function, lines 565-569 (`g_strcmp0 (key, "ProcessFD")`,
   `g_unix_fd_list_get`), returned through `*out_pidfd` at 580-583. Verified.
3. The pidfd reaches the `PolkitUnixProcess` subject: `polkit_system_bus_name_get_process_sync`,
   lines 636-640 (`pidfd >= 0` → `polkit_unix_process_new_pidfd`);
   `src/polkit/polkitunixprocess.c` `polkit_unix_process_new_pidfd` 815-825, `polkit_unix_process_constructed`
   337-377 (a pidfd it did not open itself is marked `pidfd_is_safe`, 345-346). Verified.
4. The backend's identity check uses the pidfd rather than the pid: `polkit_unix_process_get_pid`
   (`polkitunixprocess.c` 604-617) returns, whenever a pidfd is set, the pid parsed from
   `/proc/self/fdinfo/<pidfd>` (`get_pid_from_pidfd`, 282-334), or -1 if the process is gone; the stored
   pid is not consulted. `polkit_unix_process_get_racy_uid__` (1145-1259) starts from that pid (1169) and
   compares the start time (1253-1257). The backend uses it in `polkitbackendsessionmonitor-systemd.c`
   `polkit_backend_session_monitor_get_user_for_subject` (266-301); `subject_equal_for_authz` in
   `polkitbackendinteractiveauthority.c` (about 3095-3135) compares by pid taken from the pidfd; the
   duktape authority (`polkitbackendduktapeauthority.c` 403-404, 497-510) fails with "Process changed
   pid" if it differs. Verified. Limits: for a bus-name subject, `get_user_for_subject` returns the
   uid from the bus reply with `matches = TRUE` (about line 306) and does not run the racy-uid check;
   the full call path of `check_authorization_sync` was not traced line by line (only the uses above).
   Neither limit changes the claim: every pid the backend derives for the process comes from the pidfd.
5. Key absent: `get_process_sync` takes `polkit_unix_process_new_for_owner (pid, 0, uid)` (639-640)
   with `ProcessID` and `UnixUserID`. In `constructed` (348-359) polkit then opens a pidfd itself with
   `pidfd_open (pid)`; that pidfd is `pidfd_is_safe = FALSE` (racy), so the systemd-unit lookup is
   skipped (`polkitbackendduktapeauthority.c:491`) and the subject is not serialised with a pidfd
   (`polkitsubject.c:322`). It is a visible, non-pinned PID path, not a failure. Verified.
   A failing `g_unix_fd_list_get` (line 568) also degrades to this path (error set, `pidfd = -1`).

NEWS for 124 ("PIDFDs are used if available to track processes") agrees but is not the evidence.

Runtime condition: pinning needs a bus that returns `ProcessFD` (dbus-daemon 1.15.7+ per the source
comment at 509-514, dbus-broker 34+). Ubuntu 24.04 ships dbus-daemon 1.14.10, which most likely does not
(inferred), so there polkit 124 takes the link 5 path unless `dbus-broker` is installed. The table row
in section 3 stays "Only with dbus-broker installed".

Verdict: A

## 4. Manual acceptance run (M01)

Run on 2026-10-27 in an Ubuntu 26.04 GNOME VM (polkit 127, dbus-daemon 1.16.2) with the F16
`.deb`, one imported RSA 2048 key and a test CA. All verified by hand unless marked.

- **rFirma (acceptance 2): passes** with a development build of rFirma that needed two fixes on
  its side: a fallback from `CKM_SHA256_RSA_PKCS` to `CKM_RSA_PKCS` over a `DigestInfo` (we only
  offer raw mechanisms), and no `C_Login` when the token lacks `CKF_LOGIN_REQUIRED` (our
  `C_Login` returns `CKR_FUNCTION_NOT_SUPPORTED`). Each signature showed the polkit dialog, a
  second one asked again, cancelling made the signature fail. Any client that only uses composed
  mechanisms or always calls `C_Login` will fail the same way.
- **Firefox snap (acceptance 3): fails.** Ubuntu's default Firefox cannot see
  `/usr/lib/custodio/` inside its confinement and never loads the module.
- **Firefox `.deb` from Mozilla (acceptance 3): passes**, once the module is registered by hand.
  Neither Firefox build on Ubuntu reads p11-kit `.module` files (both bundle their own NSS), so
  the p11-kit registration is not enough there. We used the enterprise policy
  `SecurityDevices` in `/etc/firefox/policies/policies.json`; shipping that file in the package
  would override an administrator's own policy file.
- **Two dialogs for one page load** in Firefox: two full TLS handshakes with the client
  certificate, so two signatures (the second connection is likely `/favicon.ico`, inferred).
  Correct by design; on a real site with parallel connections and no session resumption the
  person will see several dialogs in a row.
- **Fingerprint (acceptance 6): not verified.** No fingerprint reader available.
- `custodiod` logs nothing per signature; the only trace is polkit's agent helper starting.

## Manual acceptance run (F33, acceptance 11)

Run on 2026-10-29 on Ubuntu 26.04.1 GNOME (Wayland, polkit 127) with `custodio_0.1.0-1_amd64.deb`,
the RSA 2048 and P-256 keys of `docs/manual-acceptance.md` section 1, and the rFirma 0.17.0
release. That release predates the M0 workarounds (rFirma `5117853c` is not in `v0.17.0`).
Each result below was checked against `journalctl -u custodio.service` (key id, outcome, and a
pid that resolved to `/usr/bin/rfirma`).

- rFirma finds the module by itself through `/usr/share/p11-kit/modules/custodio.module`; both
  certificates are listed.
- **RSA 2048, main window: passes.** Every signature showed the polkit dialog, including the second
  one in a row. Cancelling made `C_Sign` fail with `CKR_FUNCTION_FAILED`, logged as `denied`.
- **P-256, main window: rFirma cannot sign.** rFirma 0.17.0 (and `main` as of this run) hard-codes
  `SHA256withRSA` for the main window (`signing/application/cycle.rs`, `ALGORITHM`, ADR-0001), so it
  asks the EC slot for `CKM_SHA256_RSA_PKCS` and gets "no está entre los mecanismos de la ranura".
  Custodio is right to refuse: the slot offers only ECDSA mechanisms.
- **P-256, site flow (`afirma://`, rFirma's `just sede` test page, PAdES): passes.** That flow picks
  the algorithm from the key type (`site/ports.rs`), so it requests ECDSA-SHA256. Two signatures, each with
  the dialog; cancelling returned `AOCancelledOperationException` to the page and was logged
  as `denied`.
- Before the run, `afirma://` was registered to a local debug build of rFirma (`rfirma-dev.desktop`).
  It had to point at the installed `rfirma.desktop` first; check with
  `xdg-mime query default x-scheme-handler/afirma`.

## Manual acceptance run (F34, acceptance 12)

Run on 2026-10-29 on Ubuntu 26.04.1 GNOME (Wayland, polkit 127) with `custodio_0.1.0-1_amd64.deb`,
LibreOffice 26.2.6.3 and the keys of `docs/manual-acceptance.md` section 1. Each result below was
checked against `journalctl -u custodio.service` (uid, key id, outcome, a `soffice.bin` pid).

- LibreOffice used a dedicated NSS database (`certutil -N --empty-password`, then `modutil -add`),
  set in Tools > Options > LibreOffice > Security > Certificate Path. Without it LibreOffice picks
  the Firefox profile's database.
- **RSA 2048: passes.** Certificate listed, polkit dialog on signing, `rsa-sha256` signature valid
  after reopening. Cancelling added no signature, logged as `denied`.
- **P-256: passes.** Same steps; the document holds an `ecdsa-sha256` signature, valid after
  reopening, journal mechanism `ecdsa`. So LibreOffice signs with ECDSA through Custodio.
- **PIN dialog: none.** Only the polkit dialog appeared, for both keys. This contradicts the
  inference in section 1 that `GetPasswordFunction` always shows a dialog; with
  `CKF_LOGIN_REQUIRED` unset NSS does not ask for a password (inferred).
- With the CA trusted as `C,,` the signature showed "at least one certificate could not be
  validated": `certutil -V -u S` reported the issuer as not trusted. `C,C,C` fixed it; the
  manual page now says so.

## Manual acceptance run (F35, acceptance 13)

Run on 2026-10-29 after F33 and F34, by an account in `adm`, with the query of
`docs/manual-acceptance.md` section 7 (`--since today`).

- 11 entries, all `CUSTODIO_UID=1000`; the query without `_UID` returns the same 11.
- rFirma RSA 2048: 2 `signed`, 1 `denied` (one pid, an `app-gnome-rfirma-<pid>` scope). rFirma P-256
  site flow: 2 `signed`, 1 `denied`, mechanism `ecdsa` (one pid). LibreOffice: 1 `signed` and 1
  `denied` per key, a new pid per step (LibreOffice was restarted), each a `libreoffice-soffice`
  AppArmor process.
- One extra `signed` RSA 2048 entry from an earlier rFirma window: a try before the recorded run,
  confirmed by the person.
- rFirma P-256 in the main window left no entry: the module refuses `CKM_SHA256_RSA_PKCS` before
  calling the service.
- `-o verbose` shows the four `CUSTODIO_*` fields in every entry (section 7 marked it unverified).
- **Passes.**

## SoftHSMv2 and multi-part signing (read for F21, `src/lib/SoftHSM.cpp`, develop branch)

- `AsymSignInit` sets `bAllowMultiPartOp = false` for the raw mechanisms (`CKM_RSA_PKCS`,
  `CKM_RSA_X_509`, ...), `true` for the hash-composed ones.
- `C_SignUpdate` → `AsymSignUpdate` with a raw mechanism: `session->resetOp()` (operation ended)
  and **`CKR_OPERATION_NOT_INITIALIZED`**. F21 first named `CKR_FUNCTION_NOT_SUPPORTED`; a person
  chose this code instead, and that `C_SignFinal` with a raw mechanism ends the operation too.
- `C_SignFinal` with a raw mechanism: **`CKR_OPERATION_NOT_INITIALIZED`**, checked in `C_SignFinal`
  itself, without `resetOp()` (the operation stays).
- `C_Sign` after `C_SignUpdate` (composed): `AsymSign` finds `getAllowSinglePartOp()` false,
  calls `resetOp()` and returns `CKR_OPERATION_NOT_INITIALIZED`. F21 returns `CKR_OPERATION_ACTIVE`
  for this call and also ends the operation (a conservative choice of this project, as the
  contract says).
- `C_SignFinal` with a NULL or too-small buffer: sets the length, returns `CKR_OK` or
  `CKR_BUFFER_TOO_SMALL`, keeps the operation (same for `C_Sign`).

## pkcs11-tool login and signing flow (read for F28, OpenSC `src/tools/pkcs11-tool.c` and `pkcs11-spy.c`, master; Debian 0.26 not diffed)

- `--login` runs `login(session, opt_login_type)` right after `C_OpenSession`, so `--login --login-type
  context-specific` sends `C_Login(CKU_CONTEXT_SPECIFIC)` **always**, at session open, before `C_SignInit`.
  The default login type is `CKU_USER`. Anything but `CKR_OK`/`CKR_USER_ALREADY_LOGGED_IN` is fatal.
- In `sign_data()` a second context-specific login happens only for a private key with
  `CKA_ALWAYS_AUTHENTICATE` true, after `C_SignInit` and before `C_Sign`/`C_SignUpdate`. Our keys have none, so
  the context-specific e2e case sees exactly one `C_Login`, before `C_SignInit`. It can pass, so no `BLOCKED.md`.
- Input of at most 1024 bytes (`in_buffer[1025]`): one-shot `C_Sign`. Larger input, or a failing one-shot,
  goes to `C_SignInit` again + `C_SignUpdate` loop + `C_SignFinal`. The mechanism does not matter. Checked
  against 0.26.1 (Debian trixie, read by the attempt-2 reviewer): there is **no size query**; it sets
  `sig_len = sizeof(sig_buffer)` and calls `C_Sign` / `C_SignFinal` once. (The master-based "size query"
  note in the first version of this entry was wrong for the shipped version.)
- Polkit consequence: a denied one-shot `C_Sign` of a composed mechanism falls back to
  `C_SignUpdate`/`C_SignFinal`, and `sign_final` signs again, so polkit is asked twice (`before + 2`). Raw
  `RSA-PKCS` does not, since `C_SignUpdate` fails with `CKR_OPERATION_NOT_INITIALIZED`. Deny cases that must
  ask once sign more than 1024 bytes.
- Spy log format: a blank line, `N: C_Login`, `P:<pid>; T:0x<tid> <date>`, `[in] hSession = 0x1`,
  `[in] userType = CKU_USER` (or `CKU_CONTEXT_SPECIFIC`), the PIN dump (the log shows the PIN in clear), then
  `Returned:  0 CKR_OK` (two spaces).

## M1 open questions: login type, caller detail, refused calls

Answers three open questions of SPEC.md that need no manual client. Read 2026-10-28 by reading
source; nothing from the cloned trees was built or run. Each claim is **verified** (read, with
file and line, tag or commit) or **inferred**. Trees: NSS `NSS_3_110_RTM` (`e0109c37`), LibreOffice
`core` master (`a39fc5e3`), Firefox `gecko-dev` sparse `security/manager` (`5836a062`, the mirror
lags: HEAD dated 2025-07-08), OpenSC tag `0.26.1` (`043343d2`, trixie 0.26.1-2) and HEAD `72406af`,
pkcs11-provider tag `v1.0` (`8f6b9440`, trixie 1.0-3) plus HEAD `ea322ac` and `v1.3.0`, libp11
`libp11-0.4.13` (`f2c785df`) and HEAD `826afc1`, rFirma `sgomez/rfirma` HEAD `0eebe4c5`
(2026-10-27), dbus `dbus-1.16.2` and `dbus-1.14.10`, dbus-broker `v37`, systemd `v257`, Linux
`v6.12` and `v6.17` (`fs/pidfs.c`, `fs/proc`). Distribution data: Repology API and distro
archives, 2026-10-28 (versions agree with section 3, dated 2026-10-27). Debian patch sets of the
client packages were not read.

### M1.1 Does any client send `C_Login(CKU_SO)`?

`CKU_SO` call sites, every non-test hit of a whole-tree grep:

| Tree | Where | What reaches it | Mark |
|---|---|---|---|
| NSS | `lib/pk11wrap/pk11auth.c:450` `PK11_InitPin` (then `C_InitPIN` at :458) | `certutil -N --empty-password` (`certutil.c:3268`), `certutil` `-M/-S/-A/-E` (:3294, needs `PK11_NeedLogin` too), `certutil -W`/`-N` through `SECU_ChangePW2` (`secutil.c:395`), `pk12util` (`P12U_InitSlot`, :326), `modutil -create` (`pk11.c:738`), `modutil -changepw` (`pk11.c:811`), Firefox `nsPK11Token::InitPassword` (`nsPK11TokenDB.cpp:238`); all gated on `PK11_NeedUserInit(slot)` | verified |
| NSS | `lib/pk11wrap/pk11auth.c:375` `PK11_CheckSSOPassword` | no caller in `lib/` or `cmd/`; only exported (`nss.def:459`) | verified |
| NSS | `cmd/pk11mode/pk11mode.c:1695`, `cmd/dbtest/dbtest.c:194` | test tools | verified |
| NSS | `lib/softoken/pkcs11.c:4594,4602`, `lib/ckfw/session.c:651,677` | module side (`NSC_Login`), not a client call | verified |
| OpenSC | `src/tools/pkcs11-tool.c:1062` | `--login-type so`; takes effect only with `-l` or `-p` | verified |
| OpenSC | `pkcs11-tool.c:1367`, `login()` :1916-1962 | `--init-pin` with `-l` or `-p` defaults the login type to SO; PIN from `--so-pin` or prompt | verified |
| OpenSC | `pkcs11-tool.c:1349,1974-2013` `init_token` | `--init-token` calls `C_InitToken` with `--so-pin`; no session, no `C_Login` | verified |
| OpenSC | `pkcs11-tool.c:2071` `change_pin` | `--change-pin` passes `--so-pin` as old PIN to `C_SetPIN`; an SO `C_Login` only with `--login-type so -l` | verified |
| OpenSC | `pkcs11-tool.c:1380-1383` | `--unlock-pin` rejects any login type except context-specific; never SO | verified |
| OpenSC | `pkcs11-tool.c:9561-9565` | the threaded test uses SO only with `--login-type so` | verified |
| OpenSC | `pkcs11-spy.c:855` `C_Login` | passes the type through and logs it; never chooses SO | verified |
| OpenSC | `pkcs11/pkcs11-session.c`, `framework-pkcs15.c` | OpenSC's own module side, not a client | verified |
| pkcs11-provider | no `CKU_SO` outside `pkcs11.h` | `session.c:828` and :613 pass `CKU_USER` and `CKU_CONTEXT_SPECIFIC`; HEAD adds only the vendor `CKU_LUNA_CU` (`provider.c:1343,1527`) | verified |
| libp11 | `p11_slot.c:342` (0.4.13: :238) `pkcs11_login_on_session` | public `PKCS11_login(slot, so, pin)`; the engine itself passes `so = 0` (`util_uri.c:542`) | verified |
| rFirma | no `CKU_SO`; only `User` (`listing.rs:37,125`, `session.rs:100,104`) and `ContextSpecific` (`session.rs:168`) | the one `CKU_SO` string is the fake test module's call logger (`fake-pkcs11/src/calls.rs:15`) | verified |

- `pkcs11-tool` with `--login`, `--sign`, `--list-objects` and no `--login-type so` logs in as
  `CKU_USER`; the default type is -1 (:466) and resolves to `CKU_USER` unless `--init-pin` is set.
  `--sign` and similar raise `opt_login` when the token has `CKF_LOGIN_REQUIRED` (:1346). Verified
  at OpenSC 0.26.1.
- pkcs11-provider calls `C_Login` only when a private object is needed and `check_skip_login` is
  false: with the default behaviour it is skipped when the token lacks `CKF_LOGIN_REQUIRED`
  (`session.c:864-867`, v1.0). With `CKF_PROTECTED_AUTHENTICATION_PATH` it logs in as user with a
  null PIN (:488, :561). Verified at v1.0; HEAD not diffed (inferred).
- NSS and our token, flags `CKF_TOKEN_INITIALIZED|CKF_WRITE_PROTECTED`
  (`crates/custodio-pkcs11/src/ffi.rs:214`; no `CKF_USER_PIN_INITIALIZED`, no `CKF_LOGIN_REQUIRED`,
  no `CKF_PROTECTED_AUTHENTICATION_PATH`): `PK11_NeedLogin` is false (`pk11slot.c:1302,1801`),
  `PK11_NeedUserInit` is **true** (`pk11slot.c:2027-2041`, the flag is clear), and
  `PK11_Authenticate` does no `C_Login` (`pk11auth.c:312,320`). Verified.
- LibreOffice calls `PK11_InitPin` once, on the internal key slot only
  (`xmlsecurity/source/xmlsec/nss/nssinitializer.cxx:415-419`), never on a module token; its
  `PK11_Authenticate` use (`securityenvironment_nssimpl.cxx:268-269`) is user-only and skipped when
  `PK11_NeedLogin` is false. `PK11_ChangePW`/`PK11_CheckUserPassword` are not called. Verified for
  `.cxx/.hxx/.cpp/.h/.mm` only; `.c` files and `external/` were not searched. That NSS signing code
  reaches only `PK11_Authenticate` is inferred (`cryptohi`/`smime` callers not all traced).
- Firefox reaches `PK11_InitPin` only from the Device Manager UI: `Login()` -> `setPassword`
  (`nsNSSComponent.cpp:2175-2201`) -> `InitPassword` (`nsPK11TokenDB.cpp:235-238`) after a "set
  password" dialog, when `PK11_NeedUserInit` is true. Because our token has that property, a user
  who logs in to it by hand in the Device Manager is offered that dialog; signing and client-auth
  paths use `PK11_Authenticate`. Verified in `security/manager`; `toolkit/`, `dom/`, `browser/` and
  the dialog JavaScript were not read (inferred).
- Today `C_Login(CKU_SO)` returns `CKR_SESSION_READ_ONLY_EXISTS` after the session check, and
  anything but user, SO and context-specific returns `CKR_USER_TYPE_INVALID`
  (`crates/custodio-pkcs11/src/ffi/login.rs:20-23`). Verified. Effect on clients: `pkcs11-tool` dies
  on any `C_Login` error other than `CKR_OK`/`CKR_USER_ALREADY_LOGGED_IN` (:1963-1965, verified), so
  `--init-pin` and `--login-type so` fail either way; libp11 fails on both codes (verified); NSS's
  `PK11_InitPin` fails and the Firefox dialog reports an error (inferred).
- The code `CKR_SESSION_READ_ONLY_EXISTS` is the one PKCS#11 gives for an SO login while a
  read-only session exists, which is the only kind of session this module opens
  (`ffi.rs:275`); `CKR_USER_TYPE_INVALID` would say the type does not exist, which is less
  accurate. Inferred from the PKCS#11 specification.

Recommendation: keep `C_Login(CKU_SO)` failing, with `CKR_SESSION_READ_ONLY_EXISTS` as today: no
client path found sends it during signing, and every path that does (administration tools,
Device Manager) fails safely and has nothing to administer on a write-protected token.

### M1.2 Caller detail beyond uid and pid

What `GetConnectionCredentials` returns, per target and shipped version (Repology and distro
archives, 2026-10-28):

| Target | Default daemon | Version | Kernel | `UnixUserID`, `ProcessID` | `ProcessFD` | `LinuxSecurityLabel` | `UnixGroupIDs` | `AdtAuditSessionData` | Mark |
|---|---|---|---|---|---|---|---|---|---|
| Debian 13 | dbus-daemon | 1.16.2 | 6.12 | present | present (6.12 >= 6.5) | with an active LSM (AppArmor expected) | present | absent | versions and key code verified, kernel and LSM inferred |
| Ubuntu 25.10 | dbus-daemon | 1.16.2 | 6.17 | present | present | with AppArmor (inferred) | present | absent | verified (kernel from `linux-image-generic` dependency) |
| Ubuntu 26.04 | dbus-daemon | 1.16.2 | 7.0 | present | present | with AppArmor (inferred) | present | absent | verified |
| Fedora 41+ | dbus-broker | 36 / 37 | 6.11 at GA, later 6.17 | present | present | with SELinux | present | absent | versions verified, default inferred |
| RHEL/Alma 10 | dbus-broker | 36 | 6.12 | present | present | with SELinux | present | absent | inferred (CentOS Stream 10 packages) |
| Arch | dbus-broker (observed; corrected from dbus-daemon) | 37 (dbus 1.16.2 is installed but not running) | rolling (7.x) | present | present | probably absent (no default LSM, inferred) | present | absent | bus daemon observed in the e2e image, rest inferred |

- Key code: dbus-daemon emits `LinuxSecurityLabel` from `getsockopt(SO_PEERSEC)`
  (`dbus-sysdeps-unix.c` ~2074; `bus/driver.c:2009-2016`), `UnixGroupIDs` from `SO_PEERGROUPS`
  (`driver.c:1897`), and `ProcessFD` only if the build has `SO_PEERPIDFD` and the caller connection
  can receive fds (`driver.c:2020-2022`, `dbus-sysdeps-unix.c:2341`). It is not in 1.14.10. NEWS
  "dbus 1.15.8" introduced it. Verified.
- dbus-broker: `ProcessFD` since 34 (NEWS "CHANGES WITH 34"), emitted at `src/bus/driver.c:1434-1440`,
  taken from `sockopt_get_peerpidfd` (`src/bus/peer.c:285`); when the kernel refuses (before 6.5, or
  the peer is already reaped) the key is silently absent. The label is at `driver.c:1415-1430`.
  Verified at `v37`.
- `AdtAuditSessionData` is Solaris-only (the method is `GetAdtAuditSessionData`); neither daemon
  returns it on Linux. Verified.
- Both daemons read the peer credentials once, when the peer connects (`peer.c:255-310`;
  `dbus-transport-socket.c:380`), and `GetConnectionCredentials` returns the stored values. A pid
  or label is therefore that of the process that called `connect()`; after a fork or fd passing
  the socket's creds still name the original process. Verified for the capture, inferred for the
  fork consequence.
- The `ProcessFD` pidfd pins the process, so unlike `ProcessID` it cannot be reused by another
  process, however late the service asks (inferred from pidfd semantics). Kernel minimums:
  `SO_PEERPIDFD` 6.5 (verified, `dbus-sysdeps-unix.c:2342`), `pidfd_open` 5.3, `PIDFD_GET_INFO` 6.13
  (5.3 and 6.13 inferred; the ioctl is absent from v6.12 and present in v6.17, verified).
  Every target's kernel in the table is >= 6.12, so `ProcessFD` is present on all; `PIDFD_GET_INFO`
  only on Ubuntu 25.10+, Fedora with 6.17 updates and Arch.
- polkit already receives that pidfd from the bus (section 3), so authorization is bound to the
  process; `custodiod` today reads only `UnixUserID` and `ProcessID`
  (`crates/custodiod/src/credentials.rs:46-57`, verified).

What the service can use under `ProtectProc=invisible` and `ProcSubset=pid`
(`data/custodio.service`; systemd v257, Linux v6.12/v6.17):

| Candidate | Usable under `ProtectProc=invisible`/`ProcSubset=pid` | Mark |
|---|---|---|
| `/proc/<pid>/exe`, `cmdline`, `cgroup`, `status` | **no**: `invisible` gives ENOENT for another user's pid unless the reader is in `proc_gid` or passes `ptrace_may_access`, which needs `CAP_SYS_PTRACE` (the bounding set is empty); `PrivateUsers=` does not help | verified (`fs/proc/base.c:746-792,2028,3601`; `namespace.c:1429-1440`) |
| pidfd from `ProcessFD`: `/proc/self/fdinfo/<fd>` `Pid:` | **yes**: `/proc/self` is outside the hidden set, `pidfd_show_fdinfo` has no ptrace check, `Pid:` is -1 once the process exited | verified (`fs/pidfs.c` v6.12:61-80; `fs/proc/root.c:206-210`) |
| `pidfd_open(pid)` on `ProcessID` | yes, no permission check, allowed by `@system-service`; but it adds nothing over `ProcessFD` and is open to pid reuse | verified (`kernel/pid.c:629-648`, `seccomp-util.c:763-777`) |
| `PIDFD_GET_INFO` on that pidfd (pid, uid, gid, cgroup id) | yes on kernel >= 6.13 with no `/proc` access; foreign uids show as 65534 under `PrivateUsers=yes`; gives a cgroup id, not a path | verified for v6.17 `pidfs.c:296-403` (no ptrace check), 6.13 and the 65534 munging inferred |
| `pidfd_getfd` | no: not in `@system-service`, and needs ptrace rights | verified (seccomp groups), ptrace rule inferred |
| `LinuxSecurityLabel` from the bus | yes: the daemon reads `SO_PEERSEC`, the service needs no `/proc` | verified (daemon side), service side inferred |
| `UnixGroupIDs` from the bus | yes, same reason | inferred |
| Executable name, command line, cgroup path | **only** through `/proc/<pid>` or `CAP_SYS_PTRACE`/`hidepid=off`/`proc_gid`, all of which loosen the unit | verified (rows above) |

- Options that need loosening the unit (`ProtectProc=default`, `ProcSubset=all`, a `proc_gid`
  group, `CAP_SYS_PTRACE`) are rejected: they expose every process of every user to the one service
  that holds signing authority, which is the exposure the gate measures. Nothing recommended here
  touches `data/custodio.service` or the `justfile`. Inferred (design judgement).
- The exposure gate (SPEC.md:301) is untouched: this feature changes only documents (verified by `git diff --stat`).

Recommendation: add the security label and the group ids when the bus returns them (new optional
audit fields, additive under the compatibility rule of `docs/audit.md`), and request `ProcessFD` and
check its `Pid:` from `/proc/self/fdinfo` against `ProcessID`, logging `authorization_unavailable`
on a mismatch; on kernels >= 6.13 also log the cgroup id from `PIDFD_GET_INFO`. Drop the executable
name, command line and cgroup path: they cannot be read without loosening the unit. Inferred.

### M1.3 Refused calls and journald's rate limit

- Limits: `RateLimitIntervalSec=30s` and `RateLimitBurst=10000` by default; setting either to 0
  disables limiting; the key is the sender's unit (`c->unit`, from its cgroup), not
  `SYSLOG_IDENTIFIER`; messages without a unit are never limited. The window is fixed. Verified
  (`journald-server.c:72-73,1287-1295,2670`; `journald-context.c:312`; `journald-rate-limit.c:175-232`).
- Each unit has five separate pools by priority: emerg/alert/crit, err, warning, notice+info
  (shared), debug. No priority is exempt. So `signed` (6) and `denied` (5) share one pool,
  `authorization_unavailable` (4) has its own, `signing_failed` (3) its own. Verified
  (`journald-rate-limit.c:13-22`). This matches `docs/audit.md`, which has the same priorities.
- A unit can set its own with `LogRateLimitIntervalSec=`/`LogRateLimitBurst=`
  (`/run/systemd/units/log-rate-limit-*:<unit>`, `journald-context.c:474-507`; systemd.exec(5)).
  `custodio.service` sets neither. Verified.
- The burst is scaled by the journal's space: `k = floor(log2(available_bytes))`; for `k <= 20` the
  burst is unchanged, otherwise `burst * (k - 16) / 4` (integer arithmetic). Verified
  (`burst_modulate`, `journald-rate-limit.c:147-173`); the man page table (x2 at 16 MB ... x6 at 1 TB)
  is only approximate. `available` is not the filesystem's free space but
  `limit - used` with `limit = clamp(used + max(0, fs_avail - keep_free), min_use, max_use)`; with
  default settings `max_use` is 10% of the filesystem capped at 4 GiB, so the budget cannot exceed
  4 GiB's step. Verified (`journald-server.c:99-215`).
- Budget for 10000 per 30 s: this machine (about 1.3 TB free, defaults): `max_use` is 4 GiB, so
  `k` is 31-32 and the burst 37500-40000 per pool; a 1 GiB filesystem: about 102 MiB, `k=26`, 25000;
  a 100 MiB filesystem: about 10 MiB, `k=23`, 17500; a nearly full journal (<= 1 MiB left): 10000.
  Computed from the verified formula; the inputs are inferred (journal not inspected here).
- A suppressed window ends with one driver entry written when the sender next logs:
  `Suppressed N messages from custodio.service`, `PRIORITY=6`, `_TRANSPORT=driver`,
  `SYSLOG_IDENTIFIER=systemd-journald`, `MESSAGE_ID=a596d6fe7bfa4994828e72309e95d61e`,
  `N_DROPPED=N`. It is not emitted if the unit never logs again. Verified (`journald-server.c:1211-1250,1301-1306`).
- Measurement: **not measured**. This container has `systemd-run`, `logger` and `journalctl`
  (systemd 257.13) but no running systemd or journald (`/run/systemd` absent, `systemd-run --user`
  fails for lack of a bus), so a transient unit with `-p LogRateLimitBurst=` cannot be started.
  The numbers above come from the source, not a run. Inferred. The measurement should be done in
  the e2e guest, which runs a real journald: `systemd-run --unit=rl-probe -p LogRateLimitBurst=100
  -p LogRateLimitIntervalSec=30s sh -c 'i=0; while [ $i -lt 1000 ]; do logger -t rl $i; i=$((i+1)); done'`
  then count `_SYSTEMD_UNIT=rl-probe.service` entries and the suppression notice.
- What a flood does: refused calls come from local processes with no polkit dialog, so they cost
  an attacker nothing. If each wrote an entry at priority 5 or 6 they would fill the notice+info
  pool shared with `signed` and `denied`; after 10000-40000 entries in 30 s real `signed` and
  `denied` entries are dropped until the window ends. At priority 4 or 3 they would take the pools
  of `authorization_unavailable` or `signing_failed`. Real entries come at human rate (each needs a
  polkit decision), far below the budget, so the loss comes only from the flood. Inferred from the
  pool rules above; whether the bus policy (`data/com.rfirma.Custodio1.conf`) limits who may call is
  not part of this finding.
- Options: **no entry**: no flood risk, but the audit trail has a gap exactly where a probing
  process acts (inferred). **Per-call entry**: complete trail but the flood above; a low priority
  such as debug (7) would use its own pool and spare real entries, at the cost that debug is
  usually filtered out of alerts (inferred). **Aggregate**: the service counts refused calls and
  writes a bounded number of entries; the trail keeps count and who, a flood costs one entry per
  window (inferred).
- An aggregate entry would carry the count, the window start and length, and the uid of the
  caller with the count per uid, for at most a fixed number of uids plus an "others" count; the
  outcome would be a new value (additive under `docs/audit.md`) at priority 5. It needs its own
  timer, armed on the first refusal and firing once per window (say 60 s), because flushing only on
  the next call may never happen; that is at most one entry per window in the shared pool. Inferred.

Recommendation: aggregate.

### Follow-ups (not part of F30)

- Inferred follow-up: decide whether the token should set `CKF_USER_PIN_INITIALIZED` so `PK11_NeedUserInit` is false and
  Firefox's Device Manager does not offer the "set password" dialog (M1.1); check what else the flag
  changes for NSS and pkcs11-tool before doing it.
- Inferred follow-up: request `ProcessFD`, cross-check it against `ProcessID`, add the security label (M1.2).
- Inferred follow-up: implement the aggregate for refused calls with its own timer (M1.3), then rerun the measurement in
  the e2e guest.

## F36: nfpm 2.48.0 package names, pre-release rendering and dependency names

Measured with nfpm 2.48.0 (`nfpm package -f c.yaml -p deb|rpm|archlinux`), `release: "1"`, `arch: amd64`:

- File names: `custodio_<ver>-1_amd64.deb`, `custodio-<ver>-1.x86_64.rpm`, `custodio-<ver>-1-x86_64.pkg.tar.zst`.
- `version: 0.2.0` + `prerelease: rc.1`: deb `0.2.0~rc.1-1`, rpm version `0.2.0~rc.1` release `1`. Both sort
  below `0.2.0-1`. Arch drops the pre-release from `pkgver` (`pkgver = 0.2.0-1` in `.PKGINFO`, file name
  `custodio-0.2.0rc.1-1-...`), so the pre-release would equal the release. The `package` recipe therefore passes
  the Arch package `version: 0.2.0_rc.1` and an empty `prerelease` (`pkgver = 0.2.0_rc.1-1`, no `-` in pkgver).
  `nfpm.yaml` takes `version` and `prerelease` from `NFPM_VERSION` and `NFPM_PRERELEASE`.
- The Arch `.INSTALL` wraps the two script files in `function post_install() {…}` and `function post_upgrade() {…}`;
  it uses `function`, so it is Bash, not POSIX sh. `postupgrade` is set under `overrides.archlinux.archlinux.scripts`.
- `bsdtar -tvf` shows numeric owners `0 0` for files in the Arch package and `root root` for directories.
- The release binaries `NEEDED`: `libgcc_s.so.1`, `libc.so.6`, `ld-linux-x86-64.so.2` (all three ELF files).

Dependency names (read from distro metadata, 2026-10-30):

- deb `dbus-system-bus`: virtual package provided by both `dbus` and `dbus-broker` on trixie (`apt-cache show`);
  `dbus-daemon` provides nothing. Kept. `polkitd` is 126 on trixie, 124 on Ubuntu 24.04, 127 on 26.04.
- rpm `dbus-daemon` is wrong: `dbus-broker` does not provide it (Fedora and Alma 10 metadata), so a `Requires:
  dbus-daemon` would install the reference daemon next to dbus-broker. Replaced by `dbus`, the meta package that
  `polkit` itself requires and that depends on `dbus-broker` when systemd is present. polkit is 125 on Alma 10
  and 126 or newer on Fedora.
- Arch `dbus` is installed with either implementation (`dbus-broker-units` depends on both). Kept. `polkit` is 128.

## F37: glibc ceiling and package parity (2026-10-30)

- glibc of the targets: Debian 13 2.41, Ubuntu 26.04 2.43, Ubuntu 24.04 2.39, Fedora 44 2.43, Alma 10 2.39, Arch 2.44 (rolling;
  build of 2026-09-27). Sources are in `packaging/glibc-ceiling.txt`. The ceiling is 2.39, the oldest (Ubuntu 24.04 and Alma 10).
  The Alma figure comes from a third-party mirror index; no official Alma page was reachable.
- The three shipped ELF files need at most `GLIBC_2.34` when built in the dev container (glibc 2.41), so the build needs no
  change (no old sysroot). The gate keeps it true: a toolchain or dependency bump that raises it fails `just glibc-ceiling`.
- Real listings: rpm lists no directories (`rpm --dump`), deb and Arch list the implicit parents as `0755 root root`; the
  directory rule in `scripts/check_parity.py` follows from that. The three real packages have no difference.
- A fixture ELF must be stripped (`gcc -s`) before byte-patching `GLIBC_2.34`: otherwise the name also sits in `.strtab`.

## F38: package linters, research (2026-10-30)

- lintian: Debian 13 at `snapshot.debian.org/archive/debian/20261020T000000Z/` has lintian 2.122.0 and rpmlint 2.7.0-3. lintian has no
  separate profile or data version: `debian/main` is a profile file inside the package, so `lintian_profile` is the package version.
  `lintian --print-version` prints it. Default `--fail-on` is `error`, so findings are parsed from output, not from the status. Use
  `--tag-display-limit 0`. Lintian needs many Perl modules; it did not run from an extracted .deb without root.
- rpmlint: Fedora 44 has 2.8.0-2.fc44 (koji URL and sha256 in `pins.txt`); trixie has 2.7.0, so outcome (b): rpmlint always runs in the
  Fedora container and the dev image gets no rpmlint. Config loading (2.7 and 2.8): built-in `configdefaults.toml`, then every
  `*.toml` in `$XDG_CONFIG_HOME` and `$XDG_CONFIG_DIRS` (default `/etc/xdg`) `/rpmlint/`, then each `-c` path; `-c` adds and does not
  replace. `CONFIG_DISABLE_AUTOLOADING=1` skips the autoload. The Fedora image loads `fedora.toml` (77 filters, 5 extra checks),
  `scoring.toml`, `users-groups.toml`, `warn-on-functions.toml`; the gate image must remove them. The session header lists the loaded
  files (4-space indented, after `configuration:`). Status 0 with warnings; 64 errors. Summary: `N packages and M specfiles checked; E errors, W warnings, F filtered, ...`.
- namcap 3.6.0-3 (`any`) is in the Arch Linux Archive under `repos/2026/10/20/extra/os/x86_64/`. Line format `pkgname W: message`,
  `Error: ...` lines on stdout, status 0 even with findings. Branch 2 (container only): trixie has no `python3-pyalpm`, and namcap needs
  a real pacman database to resolve dependencies, so a Debian build would report different findings than on Arch.
- Base digests (2026-10-30): see `pins.txt`.

## F38: container runtime in the dev container (2026-10-30)

The session runs as uid 1000 and `dev` has passwordless `sudo` (NOPASSWD); an earlier note here saying there was no sudo was wrong.
There is no podman or docker installed yet. Decision from a person (answer to `BLOCKED.md`): the dev container gets a nested rootless
podman, installed with `sudo` (rootless podman needs subuid/subgid entries for `dev`, and `/dev/fuse` or the vfs storage driver). The
host socket is never mounted. The linters then run in containers as the contract describes, so step 2 (raw findings on the real
packages, the `/usr/lib/custodio/custodiod` outcome, `reports/package-lint-container.txt`) is produced in the dev container.

## F38: raw linter findings on the real packages, before any fix (2026-10-30)

Run in the dev container with the images from `packaging/lint/*.Containerfile` (versions from `pins.txt`: lintian 2.122.0, rpmlint 2.8.0,
namcap 3.6.0-3) on `target/packages` from `just package` (0.1.0-1), `--network none`, package directory read-only. Nothing is fixed or
listed yet. Flags: lintian `--no-cfg --profile debian/main --display-info --display-experimental --pedantic --show-overrides
--tag-display-limit 0`; rpmlint with its defaults (the image has no `/etc/xdg/rpmlint/*.toml`: the "configuration:" list shows only
`configdefaults.toml`); namcap `-i`.

### lintian
```
E: custodio: no-changelog usr/share/doc/custodio/changelog.Debian.gz (non-native package)
E: custodio: no-copyright-file
E: custodio: unstripped-binary-or-object [usr/bin/custodio]   (also usr/lib/custodio/custodiod, usr/lib/custodio/libcustodio_pkcs11.so)
W: custodio: maintainer-script-calls-systemctl [postinst:7]
W: custodio: no-manual-page [usr/bin/custodio]
W: custodio: synopsis-too-long
I: custodio: extended-description-is-probably-too-short
I: custodio: hardening-no-fortify-functions [usr/bin/custodio]   (also custodiod, libcustodio_pkcs11.so)
X: custodio: executable-in-usr-lib [usr/lib/custodio/custodiod]
X: custodio: spelling-error-in-binary onthe on the [usr/bin/custodio]   (also custodiod, libcustodio_pkcs11.so)
```
### rpmlint
```
W: unstripped-binary-or-object /usr/bin/custodio   (also custodiod, libcustodio_pkcs11.so)
E: summary-too-long ...            E: description-line-too-long ...
E: spelling-error ('polkit', ...)  (Summary and %description)
E: no-signature                    E: no-group-tag                 E: no-changelogname-tag
E: explicit-lib-dependency libgcc  W: no-manual-page-for-binary custodio
W: no-documentation                W: invalid-license EUPL-1.2
```
No rpmlint finding has `/usr/lib/custodio/custodiod` as its subject except `unstripped-binary-or-object` (a strip question, not a path one).
### namcap
```
W: ELF file ('usr/bin/custodio') is unstripped.   (also custodiod, libcustodio_pkcs11.so)
W: .INSTALL file runs a command (systemd-sysusers) provided by hooks.
E: File (<each path, also .PKGINFO .MTREE .INSTALL>) is owned by 0:0     <- tar has no user/group names (nfpm writes numeric only)
E: Uncommon license identifiers such as 'EUPL-1.2' require license files below /usr/share/licenses/custodio/
W: Unused shared library '/usr/lib64/ld-linux-x86-64.so.2' by file (usr/bin/custodio, usr/lib/custodio/custodiod)
W: Dependency libgcc detected and implicitly satisfied ...   W: Dependency included, but may not be needed ('gcc-libs' 'polkit' 'systemd' 'dbus' 'p11-kit')
I: Soname 'ld-linux-x86-64.so=2-64' / 'libc.so=6-64' is not specified as provides by glibc yet
I: Link-level dependence (glibc / libgcc) ...   I: Soname dependency 'libgcc_s.so=1-64' provided by libgcc detected and not included
I: Soname depends / Provides / Depends as namcap sees them ...   I: Dependency glibc detected and satisfied
```
Open question (path): namcap draws no finding about `usr/lib/custodio/custodiod` other than the unstripped and ownership ones that apply to
every file. rpmlint none. **lintian's experimental tag `executable-in-usr-lib [usr/lib/custodio/custodiod]` does name the path**: it
suggests `/usr/libexec`, which Arch does not have (decisions.md, SPEC "Arch and `/usr/libexec`"). See BLOCKED.md.

### Nested podman in the dev container (what worked)
`apt-get install podman uidmap`; the dev container maps a single uid (`/proc/self/uid_map`), so `newuidmap` fails with the subuid ranges: empty
`/etc/subuid` and `/etc/subgid`, `~/.config/containers/storage.conf` with `driver = "vfs"` and `ignore_chown_errors`, and
`~/.config/containers/containers.conf` with `default_sysctls = []`, `netns = "host"`, `pidns = "host"`, `utsns = "host"` (the mounts of
`/proc` and `sethostname` are refused otherwise). `--network none` and a read-only mount then work; `--user 1000:1000` does not (only uid 0
exists in the namespace, and that is the unprivileged `dev` outside), so the gate must use `--user 0:0` under rootless podman. Image builds need
`APT::Sandbox::User=root` (apt), a `dpkg-statoverride` for `/var/cache/man` (man-db) and `pacman --disable-sandbox`; the bases are pulled as
`docker.io/library/<name>@digest` (the digests in `pins.txt` are Docker Hub's; registry.fedoraproject.org does not know the Fedora one). The
Debian base has no CA bundle, so the snapshot source is `http://` (apt verifies the signed Release file).

## F38: findings fixed in the packaging, findings listed, and what the gate guarantees (2026-10-30, session 2)

Raw findings are in the section above ("before any fix"). What was done with each; the committed lists in `packaging/lint/*.txt` hold only
the "listed" ones, each with its reason.

Fixed in the packaging: unstripped binaries (`[profile.release] strip = "symbols"` plus `strip --remove-section=.comment` in `just package`;
rustc leaves `.comment`); no copyright file (`packaging/copyright`, DEP-5, in all three packages); no changelog (`packaging/changelog.Debian`,
written with the package version by `just package` and gzipped; also fixes rpmlint's incoherent-version); no manual page (`packaging/custodio.1`,
gzipped by `just package`); synopsis too long, summary too long and description line too long (the first description line is now a short
summary); no `Group` tag (`rpm: group:`); license text missing for Arch (`/usr/share/licenses/custodio/LICENSE` in all three).
Listed (reasons in the lists): lintian `executable-in-usr-lib` (decided by a person), `hardening-no-fortify-functions` x3 and
`spelling-error-in-binary` x3 (Rust; the string "onthe" is in a dependency), `maintainer-script-calls-systemctl`, `extra-license-file` and
`package-contains-documentation-outside-usr-share-doc` (LICENSE under /usr/share/licenses), `initial-upload-closes-no-bugs`; rpmlint
`spelling-error` (polkit), `no-signature`, `explicit-lib-dependency`, `not-listed-as-documentation` x3 / `no-documentation` (nfpm drops
`type: doc` from deb and Arch, which share one file list: tried, the parity gate failed), `manpage-not-compressed bz2`, `invalid-license`,
`no-changelogname-tag`; namcap: owner `0:0` (nfpm writes numeric ids only), `external-hooks`, and the informational dependency lines.

Path `/usr/lib/custodio/custodiod` (the open question from F36): the run with the path as built (`-m`, in `reports/package-lint-container.txt`)
draws ten (linter, tag, subject) findings that name it, all decided by the person's answer (option 1: accept the path and list the findings
as literal pairs): lintian `executable-in-usr-lib`, `hardening-no-fortify-functions` and `spelling-error-in-binary` (`onthe`, from a dependency); namcap
`incorrect-owner` (0:0), `unused-sodepend`, and the bracketed dependency findings `libdepends-missing-provides` (two),
`libdepends-detected-not-included`, `dependency-implicitly-satisfied` and `dependency-detected-satisfied`. rpmlint draws no finding about the path. Each is a literal entry in the committed lists
(see the contract amendment), none is a wildcard over the path.

lintian profile: `debian/main` in lintian 2.122.0 has `Enable-Tags-From-Check: *` and no `Disable-Tags`; with `--no-cfg` nothing else applies.
The gate prints `profile 2.122.0` (the package version, as there is no separate data version).

rpmlint and the distro config: the stock `fedora.toml` (77 filters) hides `no-signature`, `spelling-error` and `manpage-not-compressed` on the same
.rpm; the gate's rpmlint reports them. `reports/package-lint-container.txt` holds the gate run (all three "ran ... container" lines; the rpmlint
line lists only `configdefaults.toml` and the committed empty config) followed by the stock-config run showing `3 filtered`.

Outcomes for the dev image: rpmlint outcome (b) (container only, none installed), namcap branch 2 (container only), lintian installed at
the pin from the snapshot (takes effect when the dev image is rebuilt; until then the host has no lintian and the gate uses the container).
Under the nested rootless podman of the dev container the run uses `--user 0:0` (the unprivileged caller; no other uid exists there).

## F42 — Does pacman stop an installation when `pre_install` fails? (2026-10-30)

No. Tested with the real `pacman -U --noconfirm` (pacman from the pinned Arch image of `packaging/lint/namcap.Containerfile`, rootless
podman, `--user 0:0`) on a hand-made package whose `.INSTALL` defines `pre_install() { ...; return 1; }`: pacman prints
`error: command failed to execute correctly`, goes on, extracts the files, exits 0, and `pacman -Q` lists the package. `pre_upgrade` is
run by the same libalpm call and is not expected to differ (not run separately).

Mechanisms tried for an abort from inside the package:
- A script `kill -INT "$PPID"` (the parent of the scriptlet is `pacman`): pacman prints `Interrupt signal received`, but the transaction still
  completes (exit 0, files extracted). Not an abort.
- A shipped alpm `PreTransaction` hook with `AbortOnFail`: libalpm reads hooks from the hook directories before the transaction starts, so
  the hook of the package being installed is not there yet. It can only protect a later upgrade or reinstall, never the first installation
  (reasoned from the libalpm hook order, not run).

deb and rpm (run in the build session that followed, with the real tools and the fixture packages of `scripts/lib/package-fixtures.sh`):
a failing pre-install script does stop the installation. `dpkg --root R -i` runs `preinst install` before unpacking; exit status 1 gives
`dpkg: error processing archive ... new custodio package pre-installation script subprocess returned error exit status 1`, exit 1, no file
in R and `dpkg -L custodio` says the package is not installed. `rpm --root R -i` runs `%pre` before the payload is written; exit status 1
gives `error: %prein(custodio-0.1.0-1.x86_64) scriptlet failed, exit status 1` and `install failed`, exit 1, no file in R and `rpm -q`
says not installed. An upgrade (`dpkg -i` of a newer .deb: `preinst upgrade`; `rpm -U`: `%pre` with 2) is refused the same way and leaves
the installed version. `scripts/test-install-real.sh` repeats all of this on every `just check`. Setup that works unprivileged: the tools
run as root of a user namespace (`unshare --map-root-user --mount`) and chroot into a small root that holds dash, grep, awk and busctl with
their libraries (`bf_mkroot`); the stub buses are bind-mounted at `/run/bus` there. Without the namespace `dpkg --root` fails on its
chroot and `rpm --root` on its scriptlet chroot. Arch: as above (pacman goes on); the PreTransaction hook of the installed package aborts a
reinstall and an upgrade (`pacman -U` exits 1, files and version unchanged) and sees `DBUS_SYSTEM_BUS_ADDRESS` of the pacman process.


## F44: rpm scriptlets, research (2026-10-30)

Checked on rpm 4.20.1 and nfpm 2.48.0 in the dev container (logging packages under `unshare -r rpm --root`), plus source reading of systemd's
`src/rpm/macros.systemd.in`, `triggers.systemd.in`, `src/update-helper/update-helper.c`, rpm's `lib/order.c` and `lib/psm.c`, and rpm-ostree's
`src/libpriv/rpmostree-scripts.cxx`, `rpmostree-core.cxx`, `rust/src/core.rs` and `docs/treefile.md` (main, Oct 2026). **Verified** unless marked.

- **Order and `$1` across `rpm -U` (verified, measured).** New `%pre` (2), new files, new `%post` (2), old `%preun` (1), old files removed,
  old `%postun` (1), new `%posttrans` (2). Install: `%pre` 1, `%post` 1. Erase: `%preun` 0, `%postun` 0. During the new `%post` and the old
  `%postun` the rpmdb holds both headers, so a version query at the restart cannot tell the new package from the old; the call log order is the
  evidence instead.
- **The Fedora macros (verified in the systemd source).** `%systemd_post` runs `systemd-update-helper install-system-units` on `$1 -eq 1` (it
  enables and presets); `%systemd_preun` runs `remove-system-units` on `$1 -eq 0`; `%systemd_postun` is empty; `%systemd_postun_with_restart`
  only marks the unit (`mark-restart-system-units`) on `$1 -ge 1`, and a file trigger of systemd restarts the marked units at the end of the
  transaction (a try-restart: stopped units stay stopped). `%sysusers_create_compat` is gone; its successor is `%sysusers_create_package`.
  Their decisions are copied, their text is not (nfpm writes the script as it is, so a macro would stay unexpanded). Differences: no enable
  or preset (SPEC: D-Bus activation starts the unit), the restart happens in the new `%post` from a marker (docs/decisions.md).
- **Account before `%pre` (verified).** rpm 4.19+ turns `user(NAME) = BASE64(sysusers line)` provides into a `systemd-sysusers -` call that runs
  before `%pre`; nfpm can write the provide. Not used: it would create the account before the F42 check, and SPEC says the check runs before
  anything changes. On classic rpm the packaged sysusers file is not on disk yet in `%pre`, so the scriptlet pipes the line on stdin (as the deb).
- **nfpm and `Requires(pre)` (verified).** `rpm.requires` has only `post`; `pre:` is "field not found"; a `(pre)` suffix in a name is literal.
  Plain `Requires: systemd` (already there) orders systemd before the package's `%pre` (`order.c`, `addSingleRelation`: every non-weak Requires
  is an edge; the pre flag matters only for breaking loops, and nothing requires custodio). The contract was amended for this.
- **rpm-ostree (verified in source).** It runs `%pre`, `%post`, `%posttrans` and file triggers of packages being added, in bubblewrap on a
  temporary root: no network, no D-Bus, no systemd (`SYSTEMD_OFFLINE=1`), `/run` a fresh tmpfs, `/var` read-only apart from `/var/tmp` and
  `/var/lib/rpm-state`, `/usr` and `/etc` writable. It never runs `%preun`, `%postun` or the triggers of removal ("not running *un scripts for
  removals yet"; only install, update and downgrade are handled). **So `rpm-ostree uninstall` runs no scriptlet of the removed package: the stop
  (it ends with the reboot into the deployment without the package) and the notice SPEC asks for cannot come from the package's scriptlets.**
  No other mechanism that runs at uninstall time exists in the package: see the F44 entry in `SPEC_DEVIATIONS.md`. Users: rpm-ostree runs sysusers once on the whole tree
  before the `%pre` scripts if the image's rpm sets `%__systemd_sysusers`, and turns `useradd` calls of `%pre` into sysusers fragments; a
  shipped `/usr/lib/sysusers.d/custodio.conf` is enough there (inferred; not run: F45 and later).
- **Local finding in the deb (F43), not changed here.** `: > /run/custodio-restart-after-upgrade || true` in `preinst` ends a dash `sh` when the
  redirection fails (a redirection error on a special builtin is fatal, whatever follows `||`); on a read-only `/run` the upgrade would fail.
  The rpm `%pre` writes the marker in a subshell for this reason.

## F58: Arch hooks and install script, research (2026-10-30)

Read in the pinned Arch image of `packaging/lint/namcap.Containerfile` (`podman run --rm --user 0:0 localhost/custodio-f42-arch:<tag> sh -c '...'`):
systemd 262.1-1, dbus 1.16.2-2, dbus-broker 37-3, pacman 7.1.0. Command for the hooks: `cd /usr/share/libalpm/hooks; grep -v '^#' NAME.hook`; for
their command: `cat /usr/share/libalpm/scripts/systemd-hook`; owner: `pacman -Qo FILE`. **Verified** unless marked.

| hook (package) | When | Trigger (Type Path) | Exec (`systemd-hook OP`) |
|---|---|---|---|
| `20-systemd-sysusers` (systemd) | PostTransaction | Install, Upgrade: `usr/lib/sysusers.d/*.conf` | `systemd-sysusers` (no live-systemd check) |
| `25-systemd-catalog` (systemd) | PostTransaction | Install, Upgrade, Remove: `usr/lib/systemd/catalog/*` | `journalctl --update-catalog` (no check) |
| `30-systemd-daemon-reload-system` (systemd) | PostTransaction | Install, Upgrade, Remove: `usr/lib/systemd/system/*` | `systemctl --system daemon-reload` after `systemd_live` |
| `35-systemd-enqueue-marked` (systemd) | PostTransaction | Upgrade: `usr/lib/systemd/system/*` | `systemctl enqueue-marked` after `systemd_live` |
| `dbus-reload` (dbus) | PostTransaction | Install, Upgrade, Remove: `etc/dbus-1/system.d/*.conf`, `usr/share/dbus-1/system.d/*.conf`, `usr/share/dbus-1/system-services/*.service` | `systemd-hook reload dbus.service` = `systemctl try-reload-or-restart dbus.service` (no live check) |

- `systemd_live` is `systemd-detect-virt --chroot` (skip) and `systemd-notify --booted` (skip when not booted); the skip messages say
  "Skipped: Running in chroot." / "Skipped: Current root is not booted.". `systemd-hook` also has `restart UNIT` = `systemctl try-restart UNIT`
  and `reload UNIT`, both "for use by other packages", without the live check.
- **Every call the package needs on install, upgrade and removal for its unit, sysusers file, catalog and bus policy is already a hook:** daemon-reload
  (30, unit path), the bus reload (`dbus-reload`, policy path, also on removal), the catalog (25), `sysusers` (20). The scripts do not repeat any of them.
  The `dbus-broker` and `dbus-broker-units` packages ship no hook (`pacman -Ql dbus-broker dbus-broker-units | grep -i 'hook\|libalpm'` is empty); `dbus.service`
  is what `dbus-reload` reloads on both implementations.
- **Order.** libalpm runs the install script of a package (`pre_*` before unpacking, `post_*` after) before the PostTransaction hooks, and hooks of one phase
  by file name. File names sort 20, 21, 25, 30, 35, `dbus-reload`: so the bus reload comes after the daemon reload, and `35-systemd-enqueue-marked` runs
  BEFORE `dbus-reload.hook` (a restart through the marker would precede the bus reload). The order is proven by the sequence numbers of the real run
  (`scripts/test-arch-lifecycle-real.sh`).
- **`enqueue-marked` needs a marker** set with `systemctl set-property UNIT Markers=needs-restart` (comment in `systemd-hook`), by a script that runs
  while the service is running; `post_upgrade` runs before every PostTransaction hook, so the marker is the only way for a script to ask for a restart that
  comes after the daemon reload, but the marker hook runs before the bus reload. Not used (docs/decisions.md): a hook of this package named after
  `dbus-reload` runs `systemd-hook restart custodio.service` (`try-restart`: only if active, so no state and no marker).
- **Why the account must exist before the policy is unpacked, though sysusers has a hook.** The sysusers hook runs PostTransaction, after unpacking and after
  `post_*`. `dbus-daemon` links `inotify_add_watch` (`grep -a -o 'inotify_[a-z_]*' /usr/bin/dbus-daemon`) and watches its configuration directories, so it
  may load a policy that names the user `custodio` as soon as the file is unpacked, not only at the `dbus-reload` hook (`dbus-broker` has no inotify
  strings; it reloads on request). A policy naming a missing user is a bad configuration. `pre_install`/`pre_upgrade` create the account.
- Hooks are read at the start of the transaction for PreTransaction (F42) and again for PostTransaction, so a PostTransaction hook that a package ships
  runs in the transaction that installs it. (Proven by the real run, same file.)

## F45: a systemd container cannot boot in the dev container (2026-10-31)

The required real run of `just e2e debian13` cannot be made here. Commands and errors:
- `just e2e debian13` (nested rootless podman 5.4.2, single-uid user namespace, `/proc/self/uid_map` maps uid 0 to host 1000 only): the image build
  failed first at `apt-get` (`setgroups 65534 failed`; fixed in the Containerfile with `-o APT::Sandbox::User=root`, as the F38 images do), then at
  `dpkg` configuring the packages (`chown to root:adm of file /var/log/apt/term.log failed (22: Invalid argument)`, exit 1): only uid 0 exists
  in the namespace, so the systemd, dbus and polkit packages cannot be unpacked with their owners.
- Even with an image, systemd needs to be PID 1 of its own PID namespace: `podman run --rm --privileged --pid=private --cgroupns=host --tmpfs /run
  docker.io/library/debian:trixie true` fails with `crun: mount `proc` to `proc`: Operation not permitted: OCI permission denied`; without `--pid=private`
  the container shares the host PID namespace (`echo $$` printed 248867 in it; F38's `containers.conf` sets `pidns = "host"` for this reason).
What would be needed: subuid/subgid ranges for `dev` and a user namespace that can mount `/proc` (or a rootful engine), i.e. a change to the dev
container. The stub-engine test (`scripts/test-e2e-host.sh`) proves the host logic only and is not a substitute.

### F45: what the dev container needs instead of `--privileged` (2026-10-31)
Rootless podman on the host, `--userns=keep-id`, probed one option at a time (nested `podman run` as `dev`):
- With subuid ranges, `newuidmap` fails (`write to uid_map failed: Operation not permitted`) until `--cap-add=SYS_ADMIN`; apparmor, seccomp
  and unmask options alone do not fix it.
- `--pid=private` fails (`crun: mount proc to proc: Operation not permitted`) until `--security-opt=unmask=/proc/*`.
- systemd exits at once (status 255): `/sys/fs/cgroup` is read-only; `--systemd=always` mounts it read-write and systemd reaches `degraded`.
- The guest's `chown` to uids from 1000 fails (`Invalid argument`) with `dev:1:999` alone: keep-id leaves 1-999 and 1001-65536 free, so
  `/etc/subuid` and `/etc/subgid` list both. `pidns = "host"` (F38) keeps systemd from being PID 1, so it is gone; `just package-lint` still passes.
With these, `just e2e debian13` passes (28 cases, dbus-daemon 1.16.2, polkit 126). Every capability stays in the rootless user namespace, and
seccomp and the default device list stay on, which `--privileged` would drop.

### Journald default storage on debian13 and ubuntu2604

Checked 2026-10-31 in the booted e2e images (`custodio-e2e-debian13` from `debian:trixie`, systemd 257.13; `custodio-e2e-ubuntu2604` from
`ubuntu:26.04`, systemd 259.9), after `systemctl is-system-running`, before the Custodio package is installed (`podman run -d --privileged
--cgroupns=host --tmpfs /run --tmpfs /run/lock --tmpfs /tmp <image>`, then `podman exec`):

```
systemd-analyze cat-config systemd/journald.conf | grep -i Storage   # the commented default is the effective value
ls -ld /var/log/journal ; journalctl --header | grep 'File path'
ls -ld /var/log/journal            # in the image, before boot: podman run --rm <image> ls -ld /var/log/journal
```

| target | `Storage=` default | `/var/log/journal` | active journal file |
| --- | --- | --- | --- |
| debian13 | `#Storage=auto` | exists (`drwxr-sr-x root systemd-journal`) | `/var/log/journal/<machine-id>/system.journal` |
| ubuntu2604 | `#Storage=persistent` | exists (same mode and group) | `/var/log/journal/<machine-id>/system.journal` |

- debian13: `auto` stores on disk only if `/var/log/journal` exists, and it does. The directory is already in the image, before boot; the
  `systemd` package's postinst creates it ("Enable persistent journal, in auto-mode, by default on new installs", `mkdir -p`).
- ubuntu2604: systemd 259 defaults to `persistent`, so journald creates the directory itself; the image has it too (the same postinst).
- On both, the run's entries (including those of `custodio.service`) are in `/var/log/journal`, not only in `/run/log/journal`. The catalog check
  and the audit-entry checks pass on `ubuntu2604` (real run) and on `debian13`.
- Limits: these are the minimal images. An installed system can differ: a system installed without the `systemd` postinst running on a new
  install (an image built from a copied root, a container image without that directory), a `Storage=volatile` drop-in, or a read-only
  `/var`. Nothing here was checked on those.
- What it means for the open question "Volatile journal warning" (SPEC): on these two targets the default is not volatile, so the install
  scripts need no warning for it, and the package changes no journald configuration (SPEC section 6). The other targets record their own default.

### End-to-end targets Fedora 44 and Alma 10

Checked 2026-10-31 in the minimal base images (`docker.io/library/fedora:44`, Fedora 44, systemd 259.10; `docker.io/library/almalinux:10`,
AlmaLinux 10.2, systemd 257) built by `e2e/targets/fedora44` and `e2e/targets/alma10`, booted as in `e2e/run.sh`. Results come from those
images, not from an installed system. `docker.io/almalinux/10` does not exist; the image is `almalinux:10`. EPEL is not used anywhere
(`grep -ri epel e2e/targets` is empty; no `BLOCKED.md` asked for it, none was needed).

**Tool sources** (`dnf repoquery --installed --qf '%{name}-%{version}-%{release} from %{from_repo}'` on Fedora; `dnf list installed` on Alma):

| tool | fedora44 | alma10 |
| --- | --- | --- |
| pkcs11-provider | 1.1-3.fc44, repo `fedora` | 1.0-3.el10_0, `@baseos` |
| OpenSC | 0.27.1-2.fc44, `updates` | 0.26.1-1.el10, `@baseos` |
| NSS tools (`nss-tools`) | 3.131.0, `updates` | 3.124.0-5.el10_0, `@appstream` |
| Python D-Bus bindings (`python3-dbus`) | 1.4.0-9.fc44, `fedora` (available) | **absent** |
| GLib D-Bus for Python (`python3-gobject-base`) | 3.56.3, `updates` | 3.46.0-7.el10, `@baseos` |
| polkit | 127-2.fc44.2, `fedora` | 125-4.el10_2.1, `@baseos` |

No skip list entry is needed: both `skip.list` files are empty. Alma's gap was the Python D-Bus bindings:
`dnf list --available python3-dbus` prints `Error: No matching Packages to list`, and `dnf list --available "python3-dbus*"` shows only
`python3-dbus-client-gen`, `python3-dbus-python-client-gen` and `python3-dbus-signature-pyparsing`. The way taken is (1) of the contract: the test
agent `e2e/agent.py` now talks to polkit with GLib's D-Bus (Gio, from `python3-gi` / `python3-gobject-base`, present on every target) and no
target installs `python3-dbus` any more. All approval and denial cases therefore run on Alma. `pkcs11-provider` 1.0 of RHEL 10 passes the
provider cases (`provider-rsa1`, `provider-ec1`, `provider-several-updates`, `provider-deny`).

**Records** (`target/e2e/<t>.record` from the real runs):

| target | `bus-daemon` | version | `bus-reported-process` | polkit |
| --- | --- | --- | --- | --- |
| fedora44 | `dbus-broker` | dbus-broker 37 | `dbus-broker-launch` | 127 |
| alma10 | `dbus-broker` | dbus-broker 36 | `dbus-broker-launch` | 125 |

- Section 3 said "dbus-broker is the default (inferred)" for Fedora and RHEL/Alma 10. Observed: it is the default of both images. Fedora's image has no
  bus daemon, the `dbus` meta package pulls in `dbus-broker`; Alma's image already has `dbus-broker` 36 and `dbus` 1.14.10 (dbus-daemon is NOT installed:
  `rpm -q dbus-daemon` says so). The table in section 3 is right for these two rows; the "inferred" is now observed for the e2e images.
- The bus does not report the broker as its own process. `GetConnectionUnixProcessID` of `org.freedesktop.DBus` returns the pid of
  `dbus-broker-launch` (pid 47 in `ps`), whose child `dbus-broker` (pid 48, `--controller 9`) is the daemon; `systemctl show -p MainPID dbus-broker` is also
  the launcher. `probe.sh` of both targets takes the launcher's `dbus-broker` child and records it as `bus-daemon`, and records what the bus named in
  `bus-reported-process`.

**Differences from the Debian family** that the suite needed (none weakens a check):
- Fedora's and Alma's NSS load every p11-kit module through `p11-kit-proxy` (`/etc/crypto-policies/back-ends/nss.config`), so the Custodio module
  (`/usr/share/p11-kit/modules/custodio.module`) is already in an empty NSS database (`modutil -list` shows its token). `modutil -add` then fails with
  "Unknown PKCS #11 error": the second load in the same process gets `CKR_CRYPTOKI_ALREADY_INITIALIZED` (0x191) from `C_Initialize` (seen with gdb).
  `e2e/user.sh` adds the module by hand only when `modutil -list` does not show it, and checks the listing either way.
- Spy library: `pkcs11-spy.so` is in `/usr/lib64` there; `e2e/composed.sh` searches `/usr/lib` and `/usr/lib64`.
- Alma's container image masks `systemd-logind` (`/etc/systemd/system/systemd-logind.service -> /dev/null`, not from a package); without it `pam_systemd`
  fails ("unit is invalid") and there is no session. `alma10`'s Containerfile removes that link, as a booted AlmaLinux has no such mask.

**Journald default** (booted images, before the Custodio package is installed; commands as in the section above: `systemd-analyze cat-config
systemd/journald.conf | grep -i Storage`, `ls -d /var/log/journal`, `journalctl --header | grep 'File path'`, `podman run --rm <image> ls -d /var/log/journal`
for the state before boot):

| target | `Storage=` default | `/var/log/journal` before boot | after boot | active journal file |
| --- | --- | --- | --- | --- |
| fedora44 | `#Storage=persistent` | exists (in the image) | exists | `/var/log/journal/<machine-id>/system.journal` |
| alma10 | `#Storage=auto` | absent | exists | `/var/log/journal/<machine-id>/system.journal` |

- fedora44: `persistent`, not volatile. alma10: `auto`; the directory is absent in the image but exists after boot with the journal in it, so the journal is
  on disk. Who creates it on Alma was not traced (the `z` lines of `tmpfiles.d/systemd.conf` only set modes).
- `journal-catalog` and the audit-entry cases pass on both (real runs). Nothing in the package changes journald. As for the Debian family, an installed
  system can differ (a `Storage=volatile` drop-in, a read-only `/var`); only the two images were checked.

### End-to-end target Arch

Checked 2026-10-31 in the minimal base image `docker.io/library/archlinux:latest` (systemd 262.1) built by `e2e/targets/arch`, booted as in
`e2e/run.sh`. Results come from that image, not from an installed system.

**Tool sources** (`pacman -Q` / `pacman -Qo` in the booted container): `pkcs11-tool` from opensc 0.27.1-2; `pkcs11-provider` 1.3.0-1;
`certutil` and `modutil` from nss 3.132-1; `openssl` 3.6.5-1; `pgrep` from procps-ng 4.0.7-1; p11-kit 0.26.5-1; polkit 128-1;
python-gobject 3.58.1-1 (the agent uses Gio, so `python-dbus` is not installed). All were installed by `pacman -Syu --noconfirm --needed`
in the Containerfile; none is missing.

**Skip list: empty.** Every tool has a candidate in core/extra, so no case is skipped; the real run reports 29 cases run, 0 skipped.

**Bus daemon and record** (`target/e2e/arch.record`): `bus-daemon=dbus-broker`, `bus-daemon-version=dbus-broker 37`,
`bus-reported-process=dbus-broker-launch`, `polkit-version=128`. `pacman -Q` in the image: `dbus 1.16.2-2`, `dbus-broker 37-3`,
`dbus-broker-units 37-3`, `dbus-units 37-3`; `/usr/lib/systemd/system/dbus.service -> dbus-broker.service`. The base image already has
`dbus-broker`; the Containerfile names no bus package. Section 3 said Arch ran `dbus-daemon` 1.16.2: wrong. Corrected in the table of
section 3 (row "Arch", and "Default bus") and in the "M1.2 Caller detail" table. As on Fedora, the bus names `dbus-broker-launch` as its own process.

**Journald default** (minimal base image): `systemd-analyze cat-config systemd/journald.conf` prints only `[Journal]` (no `Storage=`
set anywhere), so the compiled-in default `auto` applies. `/var/log/journal` exists after boot (`drwxr-sr-x+ root systemd-journal`) and
holds `<machine-id>/system.journal` (`journalctl --header`), `journalctl --disk-usage` says 8M; `/run/log/journal` is empty. So logs are persistent
here. The package changes nothing in journald; `journal-catalog` and the audit-entry cases pass on this default.

**Differences from the other targets, all in the image:**
- Pacman's download sandbox / Landlock did not fail in the dev container's rootless nested podman; no `DisableSandbox` is set anywhere
  (`grep -rn -i sandbox e2e/targets/arch` is empty). `grep -n 'pacman -Sy' e2e/targets/arch/*` shows only `-Syu`.
- Arch's `/etc/pam.d/su-l` has no `pam_systemd`, so `su -l alice` opened no logind session (`e2e: FAIL: no logind session`). The Containerfile appends
  `-session optional pam_systemd.so` to `su-l` (what `system-login` has). Test-image configuration only, not in the package or in `install.sh`.
- `install.sh` runs `pacman -U --noconfirm --needed "$1"` on the mounted file; the sync databases come from the image's full upgrade and were enough (no second refresh).

## F48: the Debian and Ubuntu images block the restart on an upgrade (2026-10-31)
With the stock `debian:trixie` image the upgrade case failed: `dpkg -i` of N+1 printed `/usr/sbin/policy-rc.d returned 101, not running 'restart custodio.service'`
and the service kept running the deleted old binary (pid unchanged, `/proc/<pid>/exe` ended in `(deleted)`). The container images ship that file for Docker
builds; a real machine has none. The Containerfiles of `debian13` and `ubuntu2604` now `rm -f /usr/sbin/policy-rc.d` (image only; the package and `install.sh`
are untouched). With it gone the maintainer scripts restart the service by themselves on all five targets (new `MainPID`, `/proc/<pid>/exe` is the installed
inode). The check of the new binary is by device:inode, because N+1 has the same content as N. `cmp` is not on the rpm and Arch images (no diffutils), so the
case compares with `sha256sum`.

## F60: upgrading from the last cargo-deb .deb (2026-10-31)
- `v0.3.0` is an annotated tag: `git rev-parse v0.3.0` gives the tag object (`0f48354`), the commit is `d870ab2…`. `git archive` takes either, but the pin
  in `scripts/package-old.sh` is the commit id, which `git cat-file -t` reports as `commit`.
- The cargo-deb package and package N are both `0.1.0-1`, which dpkg treats as a reinstall. The case therefore upgrades to N+1 (`0.1.1-1`, F48) and the guest
  proves it greater with `dpkg --compare-versions` before installing.
- The daemon moved: the cargo-deb package has it at `/usr/libexec/custodiod`, the nfpm one at `/usr/lib/custodio/custodiod`. The upgrade case reads the path from
  `ExecStart` of the unit before and after. The old process ends with a deleted exe; the new `MainPID` runs the new path.
- Reproducible: two builds from different empty directories give the same sha256 with `--remap-path-prefix` set for the build directory and `CARGO_HOME` and
  `SOURCE_DATE_EPOCH` set to the pinned commit's time (not tried without the remap).
