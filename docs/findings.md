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

## F49: the rpm owned no directory, so `dnf remove` left three behind (2026-10-31)
The removal case lists the files and the directories of the package file and, after the removal, asks the target's tool whether another package owns each
directory. On fedora44 and alma10 `/usr/lib/custodio`, `/usr/share/doc/custodio` and `/usr/share/licenses/custodio` stayed (empty, owned by no package):
`rpm -qp --qf '[%{FILEMODES:perms} %{FILENAMES}\n]'` listed 14 files and no directory. dpkg and pacman own the parents of the files they list, and left nothing.
Fix in the package: three `type: dir` entries with `packager: rpm` in `packaging/nfpm.yaml`, expected by `scripts/package_expected.py` (`RPM_ONLY_DIRS`) and
checked by the package gate. The case derives the ancestor directories of every listed file for all formats, so it would also catch the next such leftover.
- Scriptlet output reaches the terminal of the removal tool on all five targets (the guest captures stdout and stderr together): apt prints the postrm text after
  `Removing custodio`; dnf (alma10) prints it after `Running scriptlet`; dnf5 (fedora44) prints it under `>>> Scriptlet output:`; pacman prints it after `removing custodio...`.
- On debian13 and ubuntu2604 `apt-get remove` leaves the package in dpkg state `config-files` (`rc`) with no conffiles (`dpkg-query -W -f='${Conffiles}'` is empty) and no file
  on disk; `apt-get purge` moves it to `not-installed`.

## F53: the end-to-end matrix on a host with a container engine (2026-10-31)

Host: Ubuntu 26.04.1 LTS, kernel 7.0.0-38-generic, podman 5.7.0, tree at `3f61252`. Packages 0.1.0-1 (N), 0.1.1-1 (N+1) and the cargo-deb 0.1.0-1 (old).

`just e2e all`: exit 0, "e2e: passed: alma10 arch debian13 fedora44 ubuntu2404 ubuntu2604". Every skip list is empty; 0 cases skipped.

| Target | Cases run | Upgrade | Removal/purge/reinstall | Bus daemon | Polkit |
|---|---|---|---|---|---|
| debian13 | 59 | 12 (N+1 and from cargo-deb) | 18 | dbus-daemon 1.16.2 | 126 |
| ubuntu2604 | 53 | 6 | 18 | dbus-daemon 1.16.2 | 127 |
| fedora44 | 44 | 6 | 9 | dbus-broker 37 | 127 |
| alma10 | 44 | 6 | 9 | dbus-broker 36 | 125 |
| arch | 44 | 6 | 9 | dbus-broker 37 | 128 |
| ubuntu2404 (refusal) | 5 | - | - | dbus-daemon 1.14.10 | 124 |

`journal-catalog` ran on the five install targets. On dbus-broker targets the bus reports `dbus-broker-launch` as its process.

`CHECK_FORCE=1 just check-slow` (check, nightly, mutants, coverage with CRAP, package gates): exit 0. Service exposure 0.6 (threshold 1.0);
mutants 153 caught / 43 unviable and 39 caught / 15 unviable, none missed; worst CRAP 30.0 at threshold 30; parity 3 differences, 3 exceptions;
glibc highest 2.34 (ceiling 2.39); package-lint 62 findings, 62 excepted, 0 stale. Thresholds equal to `v0.3.0` (M1).

The first run failed on alma10 and fedora44 before building: podman sent expired Docker Hub credentials from `~/.docker/config.json`
("unable to retrieve auth token"). Pulling `docker.io/library/{almalinux:10,fedora:44}` with an empty `--authfile` fixed it; nothing in the repository.

## F54: acceptance 12 by hand on fedora44, SELinux enforcing (2026-10-31)

Machine: labvm `fedora44` (libvirt), Fedora Linux 44 (Workstation Edition), kernel 6.19.10-300.fc44.x86_64, dbus-broker 37, polkit 127,
Firefox 150.0-1.fc44 (Fedora package), nss-tools 3.131.0. Package `custodio-0.1.0-1.x86_64.rpm` from F53's `just package`
(sha256 `37aebe41aaaed97007d0aa44cdf51ec7939fd432044e206fb1cfb777dd43a939`). Followed `docs/manual-acceptance.md` §11.

| Step | Result |
|---|---|
| 1 `getenforce` | `Enforcing` at 23:30:31, start of the audit window |
| 2 `sudo dnf install ./custodio-0.1.0-1.x86_64.rpm` | exit 0; creates user and group `custodio` |
| 3 `custodio import` of `rsa2048` and `p256` | both imported (23:31:18 to 23:31:19) |
| 4 Firefox lists the certificates | yes, through p11-kit-proxy; the profile's `pkcs11.txt` holds only the NSS internal module, nothing registered by hand |
| 5 TLS client authentication | `openssl s_server -Verify 1 -www -no_ticket -no_cache`, server certificate from the test CA; the page loads with each key |
| 6 polkit dialog per signature | 4 approved with p256, 2 with rsa2048, each preceded by a polkit agent PAM authentication; 1 cancelled with rsa2048, the connection fails |
| 7 SELinux denials | none from 23:30:31 to the end (`ausearch` below) |
| 8 journal | 7 entries for 7 actions: 6 `signed` (p256 `ecdsa`, rsa2048 `rsa_pkcs_pss_sha256`), 1 `denied` at 00:27:44; uid 1000, pid of the Firefox process; none extra, none missing |

Acceptance 12: pass.

- `custodiod` runs as `system_u:system_r:init_t`, not `unconfined_service_t` as SPEC expects: see F55. No denial is expected from a
  domain that permissive, so the step-7 result says little about how a confined service would fare.
- `ausearch` reads standard input when it is not a terminal (over `ssh host 'sudo ausearch ...'`) and prints `<no matches>`
  for every query; `--input-logs` makes it read the log. Check with a query that must match, such as `-m USER_AUTH`
  (49 hits in the window). The run crossed midnight: `--start` needs a date, which `LC_ALL=C` takes as `10/31/26`; `10/31/2026` is
  rejected. The only AVCs in the log are `systemd-resolved` writes to `io.systemd.Machine` at boot, before the window.
- The lab image registers SoftHSM tokens with p11-kit for another project; Firefox asked for their PIN. The run moved
  `softhsm2.module` out of `/usr/share/p11-kit/modules/`. The test CA was trusted `C,,` in the Firefox profile for the
  server certificate only.
- Firefox's "Remember this decision: For this session" also remembers "Don't send a certificate", and an unanswered selector
  counts as that once the server is restarted: every later attempt fails with `SSL_ERROR_RX_CERTIFICATE_REQUIRED_ALERT`
  without calling the module. Restart Firefox to clear it. The GNOME dock icon on this image starts the Flatpak Firefox
  (159.0), which sees neither the module nor the CA; the run used `/usr/bin/firefox`.

## F55: acceptance 13 by hand on bazzite, the .rpm layered (2026-11-01)

Machine: labvm `bazzite` (libvirt), Bazzite GNOME 44 (`ghcr.io/ublue-os/bazzite-gnome:stable`), SELinux enforcing, dbus-broker 37, polkit 127.
Image 44.20261006.1 (kernel 7.2.8-ogc5.1.fc44) at the start, 44.20261026 (kernel 7.2.11-ogc4.1.fc44) after step 5. Packages from F53's
`just package`: `custodio-0.1.0-1.x86_64.rpm` (sha256 `37aebe41aaaed97007d0aa44cdf51ec7939fd432044e206fb1cfb777dd43a939`, as in F54) and
`custodio-0.1.1-1.x86_64.rpm` (sha256 `31e7973ce5996e308f72a6d938a59398dec2d42bab10394d8a7f1ace5a0d9d36`, `target/packages-next`).
Followed `docs/manual-acceptance.md` §12, on the host, no toolbox.

| Step | Result |
|---|---|
| 1 `getenforce`, `rpm-ostree install ./custodio-0.1.0-1.x86_64.rpm`, reboot | `Enforcing`, window from `11/01/26 07:31:37`; exit 0, no bus-check notice (as `docs/install.md` says) |
| 2 layered, import | `LocalPackages: custodio-0.1.0-1.x86_64` in the booted deployment; user `custodio` created; `rsa2048` and `p256` imported at 07:34:23 |
| 3 signature from the host | dialog each time; approved `rsa2048` (`SHA256-RSA-PKCS`) and `p256` (`ECDSA-SHA256`), both `Verified OK` by OpenSSL; cancelled `rsa2048` fails (`C_SignFinal` `CKR_FUNCTION_FAILED`) |
| 4 `rpm-ostree uninstall custodio --install ./custodio-0.1.1-1.x86_64.rpm`, reboot | `Upgraded: custodio 0.1.0-1 -> 0.1.1-1`; both tokens listed; same three signatures with the same results, no new import |
| 5 `rpm-ostree upgrade`, reboot | real update, 44.20261006.1 to 44.20261026 (323 upgraded, 5 removed, 43 added), `custodio-0.1.1-1` still layered; same three signatures with the same results |
| 6 SELinux, after each reboot and at the end | no AVC names custodio, polkit or the module; `USER_AUTH` 22, 35, 50 hits; AVCs 9, 18, 24, all from `tuned_t` and `unconfined_service_t` (`chcon`, `mac_admin`) and `bootupd_t` (`lsblk` on `/proc/swaps`) at boot |

Journal (base query of `docs/audit.md`): 9 entries for 9 actions, 6 `signed`, 3 `denied`, in order; none extra, none missing.

Acceptance 13: pass.

- Bazzite's Firefox is a Flatpak (out of scope, SPEC "Out of scope"); it was not tried here, F54 saw Fedora's Flatpak Firefox miss
  the module. The client was `pkcs11-tool` on the host (OpenSC, in the image), started in
  the desktop session with `labvm-gui`; over plain ssh there is no polkit agent. Input of 2000 bytes, so `pkcs11-tool` uses
  `C_SignUpdate`/`C_SignFinal` and a cancel asks once.
- The dialogs were answered from the hypervisor with `virsh send-key` (the lab account's password, or Escape to cancel), after a
  screenshot showed the dialog open each time. No person clicked them.
- `custodio import` needs a terminal; the image has neither `script` nor `expect`, so it ran under a Python `pty`.
- `custodiod` runs as `system_u:system_r:init_t`, as on fedora44, not in the "generic unconfined service domain" SPEC expects
  (`unconfined_service_t`). Cause, checked on the VM: `/usr/lib/custodio/custodiod` is labelled `lib_t`, and systemd moves a service
  into `unconfined_service_t` only from an executable such as `bin_t` (`systemd-run /usr/bin/id -Z` prints `unconfined_service_t`);
  from `lib_t` it stays in `init_t`, systemd's own domain. `matchpathcon` gives `bin_t` for `/usr/libexec/custodio/custodiod`.
  Neither domain confines the service, but in `init_t` SELinux sees it as systemd (rules that let confined domains talk to
  systemd apply to it), and "no denial" says little. Not fixed in F55: moving the binary changes the package on every target.
- On disk the state directory and key files belong to uid 65534 (`nfsnobody` on this image), not to `custodio` (956), although
  `custodiod` runs as 956. systemd 259 mounts `/var/lib/private/custodio` into the service idmapped (`idmapped` in the service's
  mountinfo), so inside it the files show as 956. Other processes running as 65534 cannot reach them: `/var/lib/private` is
  `0700 root`. Expected systemd behaviour for `DynamicUser=yes`, not a Custodio defect; the e2e snapshot compares uids before and
  after, so it is unaffected.

## F56: acceptance 14 by hand on omarchy, Firefox and the Quickshell agent (2026-11-01)

Machine: labvm `omarchy` (libvirt), Omarchy 4.0.6 (`ID_LIKE=arch`), kernel 7.2.8-9-omarchy, dbus-broker 37, polkit 128, Firefox 158.0.1-1
(Arch package), nss 3.131.1-1, p11-kit 0.26.5-1, quickshell 0.3.2.r7.g2b4501a-1. Package `custodio-0.1.0-1-x86_64.pkg.tar.zst` from
`just package` after `402a311` (sha256 `17def41f2c21a4b72f36356fc5640ac1839fa54245dc8e04fe055fa712cc9763`). Followed `docs/manual-acceptance.md` §13.

| Step | Result |
|---|---|
| 1 `sudo pacman -U custodio-0.1.0-1-x86_64.pkg.tar.zst` | exit 0; user and group `custodio` (959) created; post-transaction hooks include "Reloading system bus configuration" |
| 2 polkit agent | `quickshell -n -p /usr/share/omarchy/shell` (pid 838, journal tag `omarchy-shell`, "omarchy polkit agent registered" at login); `pgrep -a polkit-gnome` empty |
| 3 import | `rsa2048` and `p256` imported; `pkcs11-tool -L` lists both slots |
| 3 table, row 1: `rsa2048` sign, approve | Quickshell dialog "Authentication is required to sign with a key held by Custodio"; page loads |
| 3 table, row 2: `rsa2048` sign again, approve | dialog again; page loads |
| 3 table, row 3: `rsa2048` sign, cancel (Escape) | `SSL_ERROR_HANDSHAKE_FAILED` |
| also `p256`, twice | dialog each time, both pages load |
| 4 Firefox lists the certificate, TLS client authentication | **only after manual registration** (below); then the selector lists `Custodio test rsa2048` and `Custodio test p256` ("Stored on: rsa2048", "p256"), and TLS client authentication works with each |
| 5 manual registration needed | **yes** |

Journal (base query of `docs/audit.md`, from 09:00): 5 entries for 5 actions: 2 `signed` p256 `ecdsa`, 2 `signed` rsa2048 `rsa_pkcs_pss_sha256`,
1 `denied` rsa2048 at 09:04:11; uid 1000, pid of the Firefox process; none extra, none missing.

Acceptance 14: the package and polkit parts pass; Firefox needs manual registration, so the outcome is for the milestone approver (SPEC open
question "Firefox on Arch and Omarchy").

- **Why Arch's Firefox does not see the module.** Without registration the profile's `pkcs11.txt` holds only the NSS internal module, the
  running Firefox maps `/usr/lib/pkcs11/p11-kit-trust.so` (Arch links `libnssckbi.so` to it, for the built-in roots) and no
  `p11-kit-proxy.so`, and the server's request ends in `SSL_ERROR_RX_CERTIFICATE_REQUIRED_ALERT` with no certificate offered. Arch's nss
  ships no `/etc/pki/nssdb` and no p11-kit proxy configuration, unlike Fedora's (F54). Custodio's `custodio.module` is in
  `/usr/share/p11-kit/modules/`, so p11-kit clients other than NSS see it.
- **Why Fedora's does.** Fedora 44's `libnss3.so` holds the path `/etc/crypto-policies/back-ends/nss.config` (NSS built to read a system
  policy file); that file, from `crypto-policies-20251128-3`, starts with `library=p11-kit-proxy.so`, so every NSS database loads the proxy.
  The `libnss3.so` of Arch and Debian 13 hold no such path and neither system has the file (checked in the e2e images with `grep -a`).
- **Registration used**, with Firefox closed:
  `modutil -dbdir sql:$HOME/.config/mozilla/firefox/<profile> -add Custodio -libfile /usr/lib/custodio/libcustodio_pkcs11.so`
  (`modutil` from Arch's nss; it asks to confirm). `modutil -list` then shows module "Custodio" with tokens `p256` and `rsa2048`. Settings >
  Privacy & Security > Security Devices > Load with the same path should be equivalent (not tried). Per profile, so every new profile
  needs it. Registering `/usr/lib/p11-kit-proxy.so` instead would also expose OpenSC and GNOME Keyring (not tried).
- Omarchy 4's profile lives in `~/.config/mozilla/firefox`, not `~/.mozilla/firefox`.
- SPEC calls the agent "part of `omarchy-shell`"; on 4.0.6 there is no `omarchy-shell` package: the QML is in the `omarchy` package
  (`/usr/share/omarchy/shell`) and runs under `quickshell`, which logs as `omarchy-shell`.
- As in F54, the lab image registers SoftHSM with p11-kit; the run moved `softhsm2.module` out of `/usr/share/p11-kit/modules/` (it made
  no difference to Firefox here, which loads no proxy). The test CA was trusted `C,,` in the profile for the server certificate.
- Client: `openssl s_server -Verify 1 -www -no_ticket -no_cache` on `localhost:4433`, server certificate from the test CA. Firefox's
  session restore reopened the page in a second tab, which made the second `p256` signature. Firefox restarted between keys to drop the
  remembered choice; within one session each reload made a new handshake and a new dialog.
- The dialogs were answered from the hypervisor (`wtype` in the session for the lab account's password, `virsh send-key` for Enter and
  Escape), after a screenshot showed each dialog. No person clicked them.

## F61

- **tmpfiles `Z` with three dashes restores a label and nothing else.** `man tmpfiles.d` (systemd 257, Debian 13): type `Z` "Recursively set the
  access mode, user and group ownership, and restore the SELinux security context of a file or directory if it exists ... Does not follow
  symlinks"; a `-` in the mode, user or group field leaves it as it is. Run here (`systemd-tmpfiles --create --root=ROOT data/tmpfiles.d/custodio.conf`
  on a fixture tree with a 0700 directory, a 0640 file, an old mtime): mode, owner, content, size and mtime unchanged, exit 0, nothing printed;
  with the directory removed, nothing is created (exit 0). `scripts/test-relabel.sh` repeats it, with a control line that has a mode and does change it.
- **Mechanism chosen: a tmpfiles.d line, no scriptlet.** `data/tmpfiles.d/custodio.conf` (`Z /var/lib/private/custodio - - -`) in all three packages.
  `systemd-tmpfiles-setup.service` runs it at every boot, so key files written under `init_t` (`init_var_lib_t`) get the default label back after the
  first boot on the new package, and on an image-based system too: rpm-ostree runs `%post` in a build root with no `/var`, but the booted deployment
  runs the boot service. A `restorecon` in `%post`/`postinst`/the Arch hook was rejected: it runs at the wrong time on rpm-ostree (nothing to label
  in the build root), needs a call-log change in every lifecycle test of the three formats, and could run outside the state directory if
  it were ever widened; the tmpfiles line is one path by construction and cannot create, remove, chown or chmod. With no SELinux, no
  `systemd-tmpfiles` or a chroot, nothing runs. Not proven here: the label itself (no SELinux in the dev container); see "F61" in `docs/manual-acceptance.md`.
- **Limit.** On rpm-ostree the label comes back at the next boot, not at the moment of the upgrade. Until then the restarted service
  (`unconfined_service_t`) reads files labelled `init_var_lib_t`; an unconfined domain is not denied. With dnf it comes back during the
  upgrade: see F62.
- **The old-path fixture** is this tree's `packaging/nfpm.yaml` with the deb and rpm daemon at `/usr/lib/custodio/custodiod` and the unit
  from the source unmodified (`nfpm_edit.py oldpath`), not a pinned old commit: the F48 case upgrades N to N+1 from one tree, and both have the new path.
- **Arch has no old path** (it keeps `/usr/lib/custodio/custodiod`): the `upgrade-oldpath-*` cases are skipped there (`e2e/targets/arch/no-oldpath`,
  skip list); the package level checks and the F48 case cover it.

## Acceptance 6 (fingerprint) with libfprint's virtual device, ubuntu2604 (2026-11-01)

No reader is needed: libfprint ships a `virtual_device` driver for its own tests, enabled by `FP_VIRTUAL_DEVICE=<socket>`. Ubuntu's
`libfprint-2-2` is built with it (the library holds `FP_VIRTUAL_DEVICE` and `virtual-device-listener.c`). `fprintd`, `pam_fprintd` and
the polkit agent are the real ones; only the sensor is simulated.

Machine: labvm `ubuntu2604`, Ubuntu 26.04.1 LTS GNOME, polkit 127, fprintd 1.94.5-4, libfprint-2-2 1:1.95.1+tod1-0ubuntu2, libpam-fprintd 1.94.5-4.
Package `custodio_0.1.0-1_amd64.deb` from `just package` at `15dec13` (sha256 `096cf9421265b761e9e46d41b2874b3be304b540b0453bfeaa1dc967afb50d10`).

Setup, in the VM only:

1. Drop-in `/etc/systemd/system/fprintd.service.d/virt.conf`: `Environment=FP_VIRTUAL_DEVICE=/run/fpvirt/sock`, `RuntimeDirectory=fpvirt`,
   and `ExecStart=/usr/libexec/fprintd --no-timeout`. The unit has `ProtectSystem=strict`, so a socket straight under `/run` is never
   created; without `--no-timeout` fprintd exits when idle and takes the socket with it. The socket exists only while the device is open.
2. `pam-auth-update --enable fprintd`: `pam_fprintd.so max-tries=1 timeout=10` enters `common-auth`, which `/usr/lib/pam.d/polkit-1` includes.
3. Enroll as root over ssh (`sudo fprintd-enroll -f right-index-finger user`); as the user, polkit asks for the password to enroll.
4. A touch is the text `SCAN <id>` written to the socket and the write side closed. Enrollment takes 5 scans; a later `SCAN` with the
   enrolled id matches, any other id does not.

| Step | Result |
|---|---|
| `pkcs11-tool --sign --mechanism ECDSA-SHA256` with key `p256`, started with `labvm-gui` | polkit dialog "sign with a key held by Custodio" asks to swipe the right index finger, no password field |
| enrolled id | signature made, `Verified OK` by OpenSSL |
| a second signature right after | the dialog asks for the finger again; signature made, `Verified OK` |
| unenrolled id | "Failed to match fingerprint", the dialog falls back to the password (`max-tries=1`); Escape: `C_SignFinal` `CKR_FUNCTION_FAILED` |

Journal (`-t custodiod`): 2 `signature made`, 1 `signature denied`, uid 1000, key `p256`; none extra, none missing.

Acceptance 6 passes with a simulated sensor. Not covered: a real reader's driver, and the image matching that `virtual_image` would
exercise. The same setup works for `pkexec`.

## F57: acceptance 15 by hand on ubuntu2404, the switch to dbus-broker (2026-11-01)

Machine: labvm `ubuntu2404` (libvirt), Ubuntu 24.04.5 LTS, kernel 7.0.0-38-generic, GNOME Shell 46.0 on Wayland, polkit 124
(`polkitd 124-2ubuntu1.24.04.4`), systemd 255.4-1ubuntu8.17, opensc 0.25.0~rc1-1ubuntu0.2. Bus before: dbus-daemon 1.14.10; after:
dbus-broker 35 (`35-2ubuntu0.1`, noble-updates/universe). Package `custodio_0.1.0-1_amd64.deb` from `just package` after `402a311`
(sha256 `096cf9421265b761e9e46d41b2874b3be304b540b0453bfeaa1dc967afb50d10`). Followed `docs/manual-acceptance.md` §14.

| Step | Result |
|---|---|
| 1 `sudo dpkg -i custodio_0.1.0-1_amd64.deb` on dbus-daemon | exit 1; `custodio: the system bus does not provide ProcessFD, which custodiod needs to identify its callers.` and the `install dbus-broker and reboot` hint; `getent passwd custodio` empty; no `/var/lib/custodio`, no `/var/lib/private/custodio`; `dpkg -s`: `install ok not-installed` |
| 2 `sudo apt-get install dbus-broker`, reboot | links `/etc/systemd/system/dbus.service` and `/etc/systemd/user/dbus.service` to dbus-broker's units; the `dbus` package stays installed |
| 3 desktop session | autologin, GNOME on Wayland, desktop shown (screenshot); session 1 `seat0` `active` |
| 3 logind | `loginctl list-sessions` lists the session, `active` |
| 3 polkit agent | `pkexec true` from the session: GNOME's dialog, approved, exit 0 |
| 3 NetworkManager | `active`; `nmcli general status`: connected, full connectivity |
| 3 bus daemon | `dbus-broker-launch --scope system --audit`; user buses also dbus-broker; `GetConnectionCredentials` holds `"ProcessFD" h` (count 1) |
| 4 `sudo apt-get install ./custodio_0.1.0-1_amd64.deb` | exit 0; user and group `custodio` (983); ExecStart `/usr/libexec/custodio/custodiod` |
| 4 import | `rsa2048` and `p256` imported; `pkcs11-tool -L` lists both slots |
| 4 `rsa2048` sign, approve, twice | dialog "Authentication is required to sign with a key held by Custodio" each time; `SHA256-RSA-PKCS`, both `Verified OK` |
| 4 `rsa2048` sign, cancel | `C_SignFinal` `CKR_FUNCTION_FAILED`, exit 1, no output file |
| 4 `p256` sign, approve, twice | dialog each time; `ECDSA-SHA256`, both `Verified OK` |
| 4 `p256` sign, cancel | `C_SignFinal` `CKR_FUNCTION_FAILED`, exit 1, no output file |
| 5 what broke | nothing found |

Journal (base query of `docs/audit.md`): 6 entries for 6 actions, 4 `signature made`, 2 `signature denied`, uid 1000, in order; none extra,
none missing.

Acceptance 15: pass. Answer for the open question (the milestone approver decides): on this machine the switch broke nothing that the
checks look at, so the run gives no reason to refuse Ubuntu 24.04 with dbus-broker.

- What "broke nothing" rests on: after the reboot `systemctl --failed` lists no unit and dbus-broker logs no warning. The few session
  warnings (an AppArmor denial of `org.freedesktop.host.portal.Registry.Register` from a snap, jackdbus and UPower lookups, gdm's
  `GDM_IS_REMOTE_DISPLAY` assertions) also occur in the boots on dbus-daemon of the same image. Not checked: Bluetooth, printing,
  suspend, a non-autologin login at gdm, snaps beyond the desktop integration one, and a later `apt upgrade`.
- polkit 124 takes the caller's pidfd from `ProcessFD` (section 3a, read in the same `124-2ubuntu1.24.04.4` package as this VM); with
  dbus-broker the bus now returns it, so the subject is pinned. This run does not observe the pinning, only the dialog and the cancel.
- `custodiod` is bus-activated: `systemctl is-active custodio` is `inactive` right after the install, until the first call.
- Client: `pkcs11-tool` with `/usr/lib/custodio/libcustodio_pkcs11.so`, started in the session with `labvm-gui`, input of 2000 bytes.
  `custodio import` reads the password from the terminal; piping it under `script` fails (`no input`), a Python `pty` works.
- The dialogs were answered from the hypervisor (`virsh send-key` for the lab account's password or Escape), after a screenshot
  showed each dialog. No person clicked them.

## F62: the SELinux domain by hand on fedora44 and bazzite after the move (2026-11-01)

Tree at `528e6d9`. Packages from `just e2e all` on that tree: the old-path fixture `custodio-0.1.0-1.x86_64.rpm` (`target/packages-oldpath`,
daemon at `/usr/lib/custodio/custodiod`, sha256 `3fa4cbc4d1fe3ae3b3bad43aac56264804d00325b2fc103cf01811b90829b678`) and
`custodio-0.1.1-1.x86_64.rpm` (`target/packages-next`, sha256 `f4733b31acea943871d24ff3fd617ce9f5048eb21627b430c4a4317783ecb437`).
Followed `docs/manual-acceptance.md` "F61 fedora44" and "F61 bazzite". Client: `pkcs11-tool --module /usr/lib/custodio/libcustodio_pkcs11.so`
in the desktop session (`labvm-gui`), 2000 bytes of input, `SHA256-RSA-PKCS` and `ECDSA-SHA256`; signatures checked with `openssl dgst -verify`.

**Host.** Ubuntu 26.04.1, podman 5.7.0: `just e2e all` exit 0, "e2e: passed: alma10 arch debian13 fedora44 ubuntu2404 ubuntu2604"; the only
skipped cases are the six `upgrade-oldpath-*` of arch (no old path there). `cargo` comes from `~/.cargo/bin` and `nfpm` from mise:
`PATH=$HOME/.cargo/bin:$PATH mise exec -- just e2e all`.

**fedora44** (labvm, Fedora Linux 44 Workstation, kernel 6.19.10-300.fc44.x86_64, dbus-broker 37, polkit 127, `Enforcing`; window from `11/01/26 10:11:01`):

| Step | Result |
|---|---|
| 1 `dnf install` old path, import `rsa2048` and `p256` | `custodiod` in `system_u:system_r:init_t:s0`; the four key files `init_var_lib_t`, the directory `var_lib_t` |
| 2 `dnf upgrade ./custodio-0.1.1-1.x86_64.rpm` | `/usr/libexec/custodio/custodiod` (`bin_t`) present, `/usr/lib/custodio/custodiod` gone; active, main PID 3603 (new); `unconfined_service_t`; key files already `var_lib_t` |
| 3 `stat` before and after, `systemd-tmpfiles --create`, `matchpathcon` | mode `600`, owner `65534:65534`, sizes 138, 411, 1217, 617: unchanged; `var_lib_t`, as `matchpathcon` gives |
| 4 signatures, no new import | dialog each time (screenshots); approved `rsa2048` and `p256` `Verified OK`; cancelled `rsa2048` fails (`C_SignFinal` `CKR_FUNCTION_FAILED`) |
| reboot | `unconfined_service_t`, `var_lib_t`; approved `rsa2048` `Verified OK`, cancelled `p256` fails |
| SELinux | no AVC, USER_AVC or SELINUX_ERR names custodio, polkit or the module; 1 AVC in the window, `systemd_resolved_t` on `systemd_machined_var_run_t` at boot; `USER_AUTH` 29 |
| journal (`docs/audit.md` base query) | 6 entries for 6 actions: 4 `signed`, 2 `denied`, uid 1000, in order |

**bazzite** (labvm, Bazzite GNOME 44.20261006.1, kernel 7.2.8-ogc5.1.fc44.x86_64, dbus-broker 37, polkit 127, `Enforcing`; window from `11/01/26 10:15:53`; on the host, no toolbox):

| Step | Result |
|---|---|
| 1 `rpm-ostree install` old path, reboot, import | `LocalPackages: custodio-0.1.0-1.x86_64`; daemon `lib_t`, `custodiod` in `init_t`; key files `init_var_lib_t`; one approved `rsa2048` signature `Verified OK` |
| 2 `rpm-ostree uninstall custodio --install ./custodio-0.1.1-1.x86_64.rpm`, reboot | `Upgraded: custodio 0.1.0-1 -> 0.1.1-1`; before the reboot the key files are still `init_var_lib_t`; after it `/usr/libexec/custodio/custodiod` (`bin_t`), old path gone, `unconfined_service_t`, key files `var_lib_t`; `stat` identical to the one before step 2 |
| 3 signatures, no new import | dialog each time (screenshots); approved `rsa2048` and `p256` `Verified OK`; cancelled `rsa2048` fails (`CKR_FUNCTION_FAILED`) |
| SELinux | no AVC names custodio, polkit or the module; 30 in the window, all at boot: `chcon` `mac_admin` (from `unconfined_service_t` and `tuned_t`), `lsblk` `getattr` on `proc_t` (`bootupd_t`), as in F55; `USER_AUTH` 23 |
| journal | 4 entries for 4 actions: 3 `signed`, 1 `denied`, in order |

F62: pass on both machines.

- **With dnf the label comes back during the upgrade, not at the next boot.** systemd's `transfiletriggerin` on `/usr/lib/tmpfiles.d/`
  (`rpm -q --filetriggers systemd`) runs `systemd-tmpfiles --create` at the end of every transaction that installs a file there, so the
  key files were `var_lib_t` right after `dnf upgrade`. The boot path was seen on bazzite, where no trigger runs at deploy time.
- The directory itself is `var_lib_t` before the move too: only files the old service created are `init_var_lib_t`.
- As in F55, the dialogs were answered from the hypervisor (`virsh send-key`: the lab account's password, or Escape) after a screenshot
  showed each one. No person clicked them. `pkcs11-tool` writes ECDSA as raw `r||s`; `--signature-format openssl` gives the DER that `openssl dgst -verify` reads.

## F67

How `custodiod` can read the caller's flatpak app-id (SPEC open question "How `custodiod` can read the app-id"), settled by trying each
candidate under the real `custodio.service` on a supported target. Date 2026-11-01.

**Decision: (c)** is at the end. Everything below was run; where something was only read or is inferred, it says so.

### Setup

- Target `debian13` (`e2e/targets/debian13/Containerfile`, built as `custodio-e2e-debian13`), rootless podman 5.4.2, started like
  `e2e/run.sh` does (`--privileged --cgroupns=host`, tmpfs on `/run`, `/tmp`), `systemctl is-system-running --wait` → booted.
  The packaged `target/packages/custodio_0.1.0-1_amd64.deb` was installed, so the unit is the one a user gets.
  Versions: kernel `7.0.0-42-generic` (the container shares the host kernel), systemd 257.13-1~deb13u1, `dbus-daemon` 1.16.2, polkitd as in the image.
- The unit under test: `sha256sum` of `/usr/lib/systemd/system/custodio.service` in the container is `e12c2ed0…`, of `data/custodio.service`
  `2ad1fbd0…`. They differ in one line, made by packaging (`diff` output): `ExecStart=/usr/libexec/custodio/custodiod` (package) against
  `ExecStart=/usr/lib/custodio/custodiod` (`data/`). Every hardening line is identical.
- To run probes *as the service* without changing the unit file, a drop-in `/etc/systemd/system/custodio.service.d/probe.conf` replaces only
  `Type=oneshot` and `ExecStart=` (a script that runs the probe file; `runprobe` copies a script to `/run`, restarts the unit and prints its
  journal). The unit is not edited. `systemctl show custodio.service` in that state:
  `User=custodio DynamicUser=yes PrivateUsers=yes ProtectProc=invisible ProcSubset=pid CapabilityBoundingSet= AmbientCapabilities= ProtectControlGroups=yes`.
  Inside the probe: `id: uid=993(custodio)`, `CapEff/CapBnd/CapAmb: 0000000000000000`, `ls /proc | grep -c '^[0-9]'` → 4 (its own tree only).
- The callers: user `alice` (uid 1001, `useradd`, `loginctl enable-linger alice` → `user@1001.service` active, so there is a real user manager).
  Processes were started in alice's own manager with `systemd-run --user --scope --unit=… python3 holder.py` (it connects to the system bus and stays):
  - positive: `app-flatpak-org.example.My_App\x2dName-5151.scope`, with `/proc/<pid>/cgroup` (seen as root)
    `…/user.slice/user-1001.slice/user@1001.service/app.slice/app-flatpak-org.example.My_App\x2dName-5151.scope`. The app-id has `.`, `_` and `-`.
  - negative 1: `app-gnome-gedit-99b.scope` in the same `app.slice`.
  - negative 2: a process outside alice's user manager (`/init.scope`).
  Real flatpak is **absent** from the container, so the scope is forged by the user manager exactly as flatpak requests it (below). A person can forge it the same way.
  The container nests all cgroups under `/sys/fs/cgroup/<container id>/…`; on a host the same tree starts at `/sys/fs/cgroup/user.slice/…`.
- Where flatpak places the scope (**verified** by reading `common/flatpak-run.c` at tags 1.16.1 and 1.18.4): `flatpak_run_in_transient_unit()` escapes the app id
  with `systemd_unit_name_escape()` (keeps `[A-Za-z0-9:_.]`, every other byte becomes `\xNN`, so `-` is `\x2d`), builds
  `g_strdup_printf ("app-flatpak-%s-%s.scope", app_id_escaped, instance_id_escaped)` and calls `StartTransientUnit` with the property `PIDs=[getpid()]` on the
  *user* manager's private socket `/run/user/<uid>/systemd/private`. No `Slice` is set, so systemd puts it in the user manager's `app.slice`:
  `user@<uid>.service/app.slice/app-flatpak-<escaped id>-<n>.scope` (the placement was **observed** with `systemd-run --user --scope` above).
  The instance id `<n>` is `g_strdup_printf ("%u", g_random_int ())` (`common/flatpak-instance.c`, `flatpak_instance_allocate_id`): a decimal u32, not a pid.
  If there is no `/run/user/<uid>/systemd/private`, flatpak only logs `g_info ("Failed to run in transient scope: …")` and runs without a scope.
- The process the bus names (`xdg-dbus-proxy`) is in the scope: in `flatpak_run_app` the comment says "Must run this before spawning the dbus proxy, to ensure it
  ends up in the app cgroup" and `flatpak_run_in_transient_unit` is called before `flatpak_run_maybe_start_dbus_proxy` (same tags; line 513/526 in 1.16.1, 634/647 in 1.18.4).
  `flatpak run` moves *itself* into the scope, then spawns the proxy, which inherits the cgroup. That is reading plus the cgroup inheritance rule; it was **not observed**
  with a real flatpak. `xdg-dbus-proxy` runs as the person's uid (it is a child of `flatpak run`). The `xdg-dbus-proxy` source was not read for this: the claim relies on flatpak's code above and on cgroup inheritance, not on that source.
- `xdg-desktop-portal` does not use the scope for flatpaks (it opens `/proc/<pid>/root/.flatpak-info`, `xdp_app_info_flatpak_new`). For non-flatpak apps it parses the unit name
  with `^app-(?:[[:alnum:]]+\-)?(.+?)(?:\-[[:alnum:]]*)(?:\.scope|\.slice)$` and `cunescape` (**read**, `xdp-app-info-host.c`, main). We do not copy that regex (below).
- Flatpak app-id syntax (`flatpak_is_valid_name`, `common/flatpak-ref-utils.c`, 1.16.1, **read**): not empty, at most 255 characters, at least three elements,
  elements `[A-Za-z0-9_-]`, not starting with a digit, `-` only in the last element, `_` anywhere, no leading `.`.

### Baseline: the premise holds, and it is the unit that causes it

As `custodio` under the unit (pids 250 = the forged scope, 253 = outside any app scope, 264/267 other scopes, all uid 1001):

```
-- alice pid 250
ls: cannot access '/proc/250/root': No such file or directory
cat: /proc/250/cgroup: No such file or directory
cat: /proc/250/status: No such file or directory
```
(the same for every alice pid: `ProtectProc=invisible` hides them, so the error is ENOENT, not EACCES.) Controls, all in the same container:
```
custodio's own process, under the unit:  /proc/self/root -> /     /proc/self/cgroup: …/system.slice/custodio.service
custodio uid, plain shell (no sandbox):  ls: cannot read symbolic link '/proc/250/root': Permission denied
                                         cat /proc/250/cgroup → …/app.slice/app-flatpak-org.example.My_App\x2dName-4242.scope   (works; `-4242` is from an earlier run of the same forged holder, `-5151` is the one used in the other runs; only the readability matters here)
alice reading her own pid 250:           /proc/250/root -> /      (works)
root, no sandbox:                        /proc/250/root -> /      (works)
```
So `/proc/<pid>/cgroup` of another uid is readable without the sandbox and invisible with it (`ProtectProc=invisible`), and the `root` link fails for another uid
even without the sandbox (the `PTRACE_MODE_READ` check), as the SPEC says.

### (a) Loosen the unit — rejected

Each step is a drop-in on top of the probe drop-in, same caller pid 250, same `runprobe`:

| Step | Setting changed | `/proc/250/root` as `custodio` |
|---|---|---|
| a1 | `ProtectProc=default`, `ProcSubset=all` (18 pids visible) | `Permission denied` (`PrivateUsers=yes` still maps other uids to nobody) |
| a2 | a1 + `PrivateUsers=no` | `Permission denied`, `CapEff=0` |
| a3 | a2 + `CapabilityBoundingSet=CAP_SYS_PTRACE`, `AmbientCapabilities=CAP_SYS_PTRACE` (`CapEff: 0000000000080000`) | **`/proc/250/root -> /` readable** |
| a4 | a2 + `CAP_DAC_READ_SEARCH` instead (`CapEff: 0000000000000004`) | `Permission denied` |

Pid 250 is a plain `tail`, not a real flatpak sandbox, so there is no `/.flatpak-info` under its root (`No such file or directory` in a3); the point of a3 is that the root link is
readable. The smallest loosening is therefore four settings together (`ProtectProc=default`, `ProcSubset=all`, `PrivateUsers=no`, `CAP_SYS_PTRACE`).
The exposure gate, run on `data/custodio.service` with exactly those four sed-edited lines:

```
$ systemd-analyze security --offline=yes --no-pager --threshold=10 data/custodio.service | tail -1      (exit 0)
→ Overall exposure level for custodio.service: 0.6 SAFE 😀
$ systemd-analyze security --offline=yes --no-pager --threshold=10 <loosened copy> | tail -1             (exit 1)
→ Overall exposure level for custodio.service: 1.3 OK 🙂
$ scripts/check-unit-hardening.sh <loosened copy>                                                         (exit 1)
unit-hardening: … must have 'ProtectProc=invisible' exactly once and no other ProtectProc= line   (and the same for ProcSubset=pid, PrivateUsers=yes)
```
**Rejected**: it fails `just security-score` (1.3 above the threshold 10 = 1.0) and `just unit-hardening`, and a3 shows what it buys the key holder: a process
with `CAP_SYS_PTRACE` that sees all 18 pids. SPEC: "Never (a)".

### (b) A separate privileged reader — not built in M3

What it would need, from a3/a4: a process with `CAP_SYS_PTRACE` in the bounding and ambient sets, `PrivateUsers=no`, `ProtectProc=default` (it has to see the caller's pid),
plus an interface to `custodiod`: a unix socket or an fd handed over with the caller's pidfd, from which it resolves the pid (`/proc/self/fdinfo/<pidfd>`, `Pid:`), reads
`/proc/<pid>/root/.flatpak-info` hostilely (no symlinks, bounded size and time) and returns the id. a3 proves that the capability set is enough; nothing more was built.
**Not built in M3**: it adds a second unit with `CAP_SYS_PTRACE` and an IPC channel, a new privileged attack surface and a package, install and uninstall path (SELinux
domain on fedora/alma, polkit/bus policy for the socket), all for a field that is only a record and that (c) delivers without any privilege.

### (c) Sources that need no `/proc` access of another uid — works

All run as `custodio` under the unchanged unit, with the three callers above. The bus is `dbus-daemon` 1.16.2, so `GetConnectionCredentials` has `ProcessFD`.
The probe (`/run/probe_c.py`, Python/Gio) asked `org.freedesktop.DBus.GetConnectionCredentials(<unique name>)` and used the returned fd. Output (trimmed):

```
=== caller pos: bus name :1.11
GetConnectionCredentials keys: ['LinuxSecurityLabel', 'ProcessFD', 'ProcessID', 'UnixGroupIDs', 'UnixUserID'] UnixUserID 1001 ProcessID 921 ProcessFD fd 7
fdinfo: pos: 0 | flags: 02000002 | mnt_id: 5 | ino: 6502949 | Pid: 921 | NSpid: 921 |
PIDFD_GET_INFO ok: mask=0x7 cgroupid=131639 pid=921 tgid=921
resolve by walking /sys/fs/cgroup comparing st_ino: ['/sys/fs/cgroup/<cid>/user.slice/user-1001.slice/user@1001.service/app.slice/app-flatpak-org.example.My_App\x2dName-5151.scope'] (0.001s)
targeted lookup in user@<uid>.service/app.slice: ['app-flatpak-org.example.My_App\x2dName-5151.scope'] 0.0006s
GetUnitByPID   -> ('/org/freedesktop/systemd1/unit/user_401001_2eservice',)
GetUnitByPIDFD -> ('/org/freedesktop/systemd1/unit/user_401001_2eservice', 'user@1001.service', [212, 201, …])
sandbox view of the caller: /proc/921/cgroup -> [Errno 2] No such file or directory
=== caller gedit:  … cgroupid=131683 … targeted lookup: ['app-gnome-gedit-99b.scope']  GetUnitByPID → user@1001.service
=== caller loose:  … cgroupid=129296 … resolve: [' …/init.scope'] ; targeted lookup in user@<uid>.service/app.slice: []  GetUnitByPID → /org/freedesktop/systemd1/unit/init_2escope
```

| Source (as `custodio`, under the unit) | Positive caller | Negative callers | Verdict |
|---|---|---|---|
| (c1) pidfd `fdinfo` | `Pid: 921` only: no cgroup | same | gives the pid, not the scope |
| (c2) `ioctl(pidfd, PIDFD_GET_INFO)` with `PIDFD_INFO_CGROUPID` (`_IOWR(0xFF, 11, struct pidfd_info)`, size 64, mask 7) | `cgroupid=131639` | 131683 (gedit), 129296 (init.scope) | works; id is the cgroupfs directory's inode number |
| (c2b) resolve the cgroup id to a name: list `app.slice` of `user@<uid>.service` and compare `st_ino` | `app-flatpak-org.example.My_App\x2dName-5151.scope`, 0.0006 s | `app-gnome-gedit-99b.scope`; for the process outside the user manager: not found | works under `ProtectControlGroups=yes` (a read-only mount) |
| (c2c) `open_by_handle_at` with the cgroup id as a handle | – | – | **fails: the unit's seccomp filter kills the service** (`code=killed, status=31/SYS`, `Failed with result 'signal'`), and the call needs `CAP_DAC_READ_SEARCH` anyway. Do not use it. |
| (c3) fdinfo `Pid:` + read `cgroup.procs` of each scope in `user@<uid>.service/app.slice` (mode 0644) | pid 921 found in `app-flatpak-org.example.My_App\x2dName-5151.scope`; 6 scopes scanned in 0.0009 s | gedit: `app-gnome-gedit-99b.scope`; outside: not found (`None`) | works, needs no new kernel feature |
| (c4) systemd `GetUnitByPID` / `GetUnitByPIDFD` over the system bus | `user@1001.service` | `user@1001.service`; `init.scope` | **does not work**: the system manager only knows `user@<uid>.service`, the scope belongs to the user manager, whose bus (`/run/user/<uid>/bus`, `/run/user/1001/systemd/private`) `custodio` cannot reach. |

Notes on (c4): the bus policy (`data/com.rfirma.Custodio1.conf`, the default `org.freedesktop.systemd1.conf`) let the call through, and no polkit authentication was asked (no agent
was running and the call returned at once). If polkit were asked it would be systemd's own check on `org.freedesktop.systemd1.*`, not Custodio's per-signature authorization;
it must not be mistaken for it or cached as one. The result is useless anyway.
Kernel dependency: `PIDFD_GET_INFO` and `PIDFD_INFO_CGROUPID` appear in `include/uapi/linux/pidfd.h` at `v6.13` and not at `v6.12` (**read** on both tags; `fs/pidfs.c` at `v6.12`
has no `PIDFD_GET_INFO`). Debian 13's stock kernel is 6.12 (stated from memory of the distribution, not run here: the e2e containers always use the host's kernel, 7.0). So (c2) cannot be
the only source; (c3) uses only `fdinfo` and a plain file read and has no such floor. Only the 7.0 kernel was run; the `cgroup.procs` read is a stable interface, not tested on 6.12.
`/proc/<pid>/cgroup` stays invisible in the sandbox (last line of the output), as does `sd_pid_get_user_unit()` which reads it.

### (d) The deviation — not chosen

Every (c) source above was tried first and two of them (c2b, c3) work, so the condition for (d) ("only if every (c) source failed") does not hold. No entry was added to
`SPEC_DEVIATIONS.md` and acceptances 9 and 15 stand as written, with the source of (c) in place of `/.flatpak-info`.

### What a reader (the F-parser and F-reader features) needs

- **Source** (the contract for the reader): take the `ProcessFD` and `UnixUserID` that `GetConnectionCredentials` returned for the sender (the same pinned process the bus names, which is
  `xdg-dbus-proxy` for a flatpak). Primary: (c3). `pid` from `/proc/self/fdinfo/<fd>` (`Pid:`; `0` means another pid namespace and `-1` a terminated process: both undetermined, per `pidfd_open(2)`).
  Directory `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/app.slice/` (the standard layout when custodiod runs on the host; the e2e container's nested root is why the
  experiment walked the tree to find the same directory, and the direct path was **not** tried here, so the first reader feature must test it, or find the cgroup2 mount from `/proc/self/mountinfo`
  or `/proc/self/cgroup`). For every direct child directory (never follow a symlink; `is_dir(follow_symlinks=False)`), read `cgroup.procs`, and the child that lists the pid names the scope.
  Optional shortcut on kernels ≥ 6.13: `PIDFD_GET_INFO` cgroup id compared with each child's `st_ino` (c2b). It must give the same answer as (c3) and is not required.
  `<uid>` must be the one from the credentials, so a uid cannot name another uid's scope (only its own user manager can create units under its own `user@<uid>.service`; nothing was run to
  attempt the opposite, this is systemd's permission model).
- **Format of the name**: `app-flatpak-<E>-<N>.scope`. `<E>` is the app id with every byte outside `[A-Za-z0-9:_.]` replaced by `\xNN` (lower-case hex, so `-` is `\x2d`; this was seen in
  the forged name `org.example.My_App\x2dName`, which systemd kept). `<N>` is the decimal instance id (flatpak: `%u` of a u32). Because `<E>` contains no `-` and `<N>` neither, the string
  after `app-flatpak-` and before `.scope` has exactly one `-`: **split at the last `-`** (reject a name with more or fewer than one, or an `<N>` that is not 1 to 10 digits). Unescape `<E>` accepting
  only `\x2d` (anything else, such as `\x2f`, is invalid). Then validate the result as a flatpak app id (rules above, at most 255 characters, `-` only in the last element). A value that fails is never copied.
  Do not use the portal's regex: it accepts a launcher word and an empty id.
- **Bounds**: the scope name is at most 255 bytes including `.scope`. Checked: systemd accepted a 255-byte name and answered `Failed to mangle scope name: Invalid argument` for 256, so
  the escaped id plus `app-flatpak-`, `-<N>` and `.scope` is at most 255 (the unescaped id is below that; a flatpak with an id so long that systemd refuses the scope simply runs without one, which the reader reports as "no flatpak scope"). Read at most a fixed number of
  children of `app.slice` (suggested 4096) and each `cgroup.procs` bounded in size (suggested 1 MiB) and in time (the whole lookup shares one deadline, suggested 1 s; the measured cost is 1 ms for 6 scopes).
  A pid list is parsed as decimal numbers only.
- **Same process afterwards**: re-read the pinned fd's `Pid:` after the scan; it must be equal and not `-1`. For (c2) read `PIDFD_GET_INFO` a second time, same `cgroupid`.
  The pidfd refers to the process, not to a pid number, so a reused pid cannot be confused. (Not run here: the re-read after exit.)
- **The three cases**: *read*: the pinned process is listed in a scope whose name parses and validates as above; *none*: the scan of the caller's `app.slice` finished without finding the pid in any
  `app-flatpak-…` scope (a different scope such as `app-gnome-gedit-99b.scope`, or not under `user@<uid>.service` at all: both seen above); *undetermined*: no `ProcessFD`, `Pid:` 0 or -1, a read error,
  a limit hit, a name that does not parse or validate, or a pid mismatch after the scan. Known limit: a flatpak started without a user manager (no scope created, see `g_info` above) is *none*.
- The app-id is a record, not an authorization: any process of a person can create an `app-flatpak-*.scope` in its own user manager (done above with `systemd-run --user --scope`), as the SPEC says.

Decision: (c)

### F81 follow-up: where the cgroup tree starts

The F67 setup observed the e2e container (`--cgroupns=host`) nesting the tree as `/sys/fs/cgroup/<container id>/user.slice/…`, a host as
`/sys/fs/cgroup/user.slice/…`. The service's own `/proc/self/cgroup` is `0::/<prefix>/system.slice/custodio.service` in both, so the reader
(`app_id_source/scan.rs` `tree_root`) takes everything in front of the first `system.slice` component as the prefix, once, at start. An unexpected
shape (no `0::` line, no `system.slice`, `.`, `..`, empty or NUL component) gives the bare mount, which finds no scope (`None`), never a wrong id.
Tested on fixture trees only (`tests/tree_root.rs`); the real container run is F95. Not re-run in a container here.


## F68

Service detection through `xdg-dbus-proxy` (SPEC open question "Detection through the flatpak proxy"). Date 2026-11-01. Markers: `read` = from source only,
`run` = measured here. Nothing here edits the SPEC; the conflicts with it are at the end.

### Sources and setup

- **Proxy source**: `flatpak/xdg-dbus-proxy` tag **0.1.6**, file `flatpak-proxy.c`. The binary that was run is Debian trixie's `xdg-dbus-proxy 0.1.6-1+deb13u3`
  (`xdg-dbus-proxy --version` → `0.1.6`); the Debian patches were not diffed against the tag. Function and rule table: `get_dbus_method_handler()` (bus-driver
  calls, lines ~1985–2090) decides the handler of each call; `flatpak_proxy_client_get_max_policy_and_matched()` gives the policy of the destination; the switch
  in the client-to-bus path (lines ~2490–2600) applies the handler; the rule table is the comment at lines ~60–186.
- **How flatpak starts the proxy** (`read`, flatpak tag **1.16.1**): `--system-talk-name=NAME` is a flatpak option, not a proxy option
  (`common/flatpak-context.c` `option_system_talk_name_cb` → `flatpak_context_set_system_bus_policy(…, FLATPAK_POLICY_TALK)`). `flatpak_context_add_bus_filters()`
  (same file, ~2665) writes `--filter` and then `--talk=NAME` for each entry (`flatpak_policy_to_string()` → `talk`), and `common/flatpak-run-dbus.c` (~347–362) calls
  it with `app_id = NULL` for the system bus, so there is no `--own`. The proxy command line is therefore
  `xdg-dbus-proxy unix:path=/run/dbus/system_bus_socket <socket> --filter --talk=com.rfirma.Custodio1`; the client sees `<socket>` as its system bus.
  Without `--filter` the proxy forwards everything and would show every call passing, so it is always given.
- **Run on** (`run`): the e2e image `custodio-e2e-debian13` booted with systemd as PID 1 in rootless podman (`podman run -d --privileged --cgroupns=host --tmpfs /run
  --tmpfs /run/lock --tmpfs /tmp`, as `e2e/run.sh`), kernel 7.0.0-42, systemd 257.13. Two system buses, both started by systemd:
  **dbus-broker 37-2** (`dbus-broker-launch --scope system --audit`; `apt-get install dbus-broker`, container restarted) and **dbus-daemon 1.16.2**
  (`--system --systemd-activation`, the image's own). The real `data/com.rfirma.Custodio1.service` (`Exec=/bin/false`, `User=custodio`,
  `SystemdService=custodio.service`) and `data/com.rfirma.Custodio1.conf` are installed; user `custodio` from `data/sysusers.d`.
  Proxies: `systemd-run --unit=f68-proxy-talk xdg-dbus-proxy unix:path=/run/dbus/system_bus_socket /run/f68-talk.sock --filter --talk=com.rfirma.Custodio1`
  and `… /run/f68-none.sock --filter` (the "name not allowed by the sandbox" case: `--filter` with no `--talk` for the name).
  Client: `dbus-send --bus=ADDRESS --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.<Call> …`; `call-unowned` is
  `dbus-send --dest=com.rfirma.Custodio1 /com/rfirma/Custodio1 org.freedesktop.DBus.Peer.Ping` (auto-start allowed, the default).
- **The situations** (`run`, by `setup.sh <situation>` in the container; the script and the stub are inlined below, `/root/activation.service` and `/root/com.rfirma.Custodio1.conf`
  are copies of `data/com.rfirma.Custodio1.service` and `data/com.rfirma.Custodio1.conf`):
  ```sh
  #!/bin/bash
  # usage: setup.sh running|masked|missing|failing|notinstalled
  S=/usr/share/dbus-1/system-services/com.rfirma.Custodio1.service
  U=/etc/systemd/system/custodio.service
  systemctl stop custodio.service 2>/dev/null; systemctl unmask custodio.service 2>/dev/null; systemctl reset-failed custodio.service 2>/dev/null
  rm -f $U $S /etc/dbus-1/system.d/com.rfirma.Custodio1.conf
  case $1 in
   notinstalled) ;;
   *) cp /root/activation.service $S; cp /root/com.rfirma.Custodio1.conf /etc/dbus-1/system.d/ ;;
  esac
  case $1 in
   running) cp /root/custodio-run.service $U ;;
   masked) systemctl mask custodio.service >/dev/null 2>&1 ;;
   failing) sed 's#ExecStart=.*#ExecStart=/bin/false#' /root/custodio-run.service > $U ;;
  esac   # missing: nothing more (no custodio.service)
  systemctl daemon-reload; systemctl reload dbus-broker   # on the dbus-daemon run: systemctl reload dbus
  [ "$1" = running ] && systemctl start custodio.service
  ```
  `/root/custodio-run.service`:
  ```ini
  [Unit]
  Description=F68 stub for custodio.service
  [Service]
  Type=dbus
  BusName=com.rfirma.Custodio1
  User=custodio
  ExecStart=/usr/bin/python3 /usr/local/bin/f68-stub.py
  ```
  `/usr/local/bin/f68-stub.py` (owns the name through Gio):
  ```python
  import gi
  gi.require_version("Gio", "2.0")
  from gi.repository import Gio, GLib
  Gio.bus_own_name(Gio.BusType.SYSTEM, "com.rfirma.Custodio1", Gio.BusNameOwnerFlags.NONE, None, None, None)
  GLib.MainLoop().run()
  ```
  The situations:
  - *running*: `/etc/systemd/system/custodio.service` is a stub (`Type=dbus`, `BusName=com.rfirma.Custodio1`, `User=custodio`, `ExecStart=python3` owning the name through
    Gio), started; the activation file and policy installed.
  - *not activatable*, three setups, because they give different errors: **masked** (`systemctl mask custodio.service`), **missing** (activation file installed, no
    `custodio.service`), **failing** (`custodio.service` with `ExecStart=/bin/false`, `Type=dbus`). In all of them the activation file is the real one, `Exec=/bin/false`.
    The Debian package ships neither a stub nor a masked unit, so the one that matches "installed, not started" best on a real host is **failing** or **missing**.
  - *not installed*: activation file, policy and unit removed.
  - *name not allowed*: the `--filter` proxy without `--talk`.
- Also run, **labelled extra**: a private `dbus-daemon` (`--config-file` with `<servicedir>`, no systemd, no policy) with the real activation file and its proxy with
  `--talk`. It is a third stand-in for hosts where dbus-daemon execs `Exec=` itself, never for the host baseline; it gives `Spawn.ChildExited` (below).

### What the proxy does with each call (`--filter --talk=com.rfirma.Custodio1`) — `read`, each confirmed by `run`

| Call | Rule in `flatpak-proxy.c` 0.1.6 | With `--talk` | Without `--talk` (name has policy NONE) |
|---|---|---|---|
| NameHasOwner | `HANDLE_FILTER_HAS_OWNER_REPLY`: passed only if arg0 has policy ≥ SEE (`validate_arg0_name`), otherwise **rewritten** to a synthetic reply `false` | **pass** | **rewritten**: `false` |
| GetNameOwner | `HANDLE_FILTER_GET_OWNER_REPLY`, same test, else synthetic error | **pass** | **rewritten**: `org.freedesktop.DBus.Error.NameHasNoOwner` |
| ListActivatableNames | `HANDLE_FILTER_NAME_LIST_REPLY`: always sent, the reply is **filtered** to names with policy ≥ SEE (`EXPECTED_REPLY_LIST_NAMES`) | **filtered**: our name stays (run: 9 names → 2 on broker, `org.freedesktop.DBus` and ours) | **filtered**: ours removed (1 name left, `org.freedesktop.DBus`) |
| StartServiceByName | `HANDLE_VALIDATE_TALK`: passed if arg0 has policy ≥ TALK; with policy NONE the call is hidden (`handle_hide`) | **pass** | **rewritten**: `org.freedesktop.DBus.Error.ServiceUnknown` (no message text) |
| call-unowned (any method to the name) | policy of the destination: `< SEE` → `HANDLE_HIDE`, `SEE` only → `HANDLE_DENY` (`AccessDenied`), `TALK` → forwarded if `any_filter_matches()` accepts the call, which `--talk` satisfies (measured: `Ping` passes, the bus activates) | **pass** (the bus activates and answers) | **rewritten**: `ServiceUnknown` (or `NameHasNoOwner` if the call has `NO_AUTO_START` or the destination is a unique name) |

Not seen: `AccessDenied` for a hidden name (it needs `--see`, which flatpak never gives a system-bus name from `--system-talk-name`). `ListNames` is filtered the same
way as `ListActivatableNames` (not run). `UpdateActivationEnvironment` and `BecomeMonitor` are denied.

### What a client sees (`run`)

Columns: **host** = plain bus; **talk** = through the proxy with `--talk`; **none** = through `--filter` without `--talk`. On every cell of every bus **talk is identical to host**
(compared line by line, apart from the `ListActivatableNames` total); only the `none` column differs, so it is given once per bus. "msg" is the message text, which is not API.
Unique names (`:1.N`) vary. `NoReply` = `dbus-send`'s 25 s reply timeout.

**dbus-broker 37 (the baseline target), host = talk:**

| Situation | NameHasOwner | ListActivatableNames | StartServiceByName | GetNameOwner | call-unowned |
|---|---|---|---|---|---|
| running | `true` | lists the name | `uint32 2` (already running) | `":1.40"` | `Ping` returns |
| not activatable, **masked** | `false` | lists the name | `ServiceUnknown`, msg `…activation request failed: unit is masked` | `NameHasNoOwner` | `NameHasNoOwner`, msg `…unit is masked` |
| not activatable, **missing** unit | `false` | lists the name | `ServiceUnknown`, msg `…unknown unit` | `NameHasNoOwner` | `NameHasNoOwner`, msg `…unknown unit` |
| not activatable, **failing** unit | `false` | lists the name | `ServiceUnknown`, msg `…startup job failed` | `NameHasNoOwner` | `NameHasNoOwner`, msg `…startup job failed` |
| not installed | `false` | **absent** | `ServiceUnknown`, msg `The name is not activatable` | `NameHasNoOwner` | `ServiceUnknown`, msg `The name is not activatable` |
| **none** (not allowed), any of the above four | `false` (rewritten) | **absent** (filtered) | `ServiceUnknown`, msg = the error name (rewritten) | `NameHasNoOwner`, msg = the error name (rewritten) | `ServiceUnknown`, msg = the error name (rewritten) |

**dbus-daemon 1.16.2 (`--systemd-activation`, the Debian/Ubuntu default), host = talk:**

| Situation | NameHasOwner | ListActivatableNames | StartServiceByName | GetNameOwner | call-unowned |
|---|---|---|---|---|---|
| running | `true` | lists the name | `uint32 2` | `":1.2"` | `Ping` returns |
| not activatable, **masked** | `false` | lists the name | `org.freedesktop.systemd1.UnitMasked` | `NameHasNoOwner` | `org.freedesktop.systemd1.UnitMasked` |
| not activatable, **missing** unit | `false` | lists the name | `org.freedesktop.systemd1.NoSuchUnit` | `NameHasNoOwner` | `org.freedesktop.systemd1.NoSuchUnit` |
| not activatable, **failing** unit | `false` | lists the name | `NoReply` after 25 s (no reply at all) | `NameHasNoOwner` | `NoReply` after 25 s |
| not installed | `false` | **absent** | `ServiceUnknown`, msg `The name com.rfirma.Custodio1 was not provided by any .service files` | `NameHasNoOwner` | same `ServiceUnknown` |
| **none** (not allowed), any | `false` (rewritten) | **absent** (filtered) | `ServiceUnknown` (rewritten) | `NameHasNoOwner` (rewritten) | `ServiceUnknown` (rewritten) |

**Extra, private `dbus-daemon` without systemd (labelled; the real file `Exec=/bin/false` is executed):** not activatable → `StartServiceByName` and `call-unowned` both
`org.freedesktop.DBus.Error.Spawn.ChildExited` (msg `Process com.rfirma.Custodio1 exited with status 1`), `ListActivatableNames` lists the name; not installed →
`ServiceUnknown` (msg `…was not provided by any .service files`), name absent; through `--talk` identical in every cell.

Findings that the documentation must not get wrong:

1. **`Spawn.*` is not what the supported hosts return** for "installed but not activatable". Under systemd activation the name is `ServiceUnknown` (dbus-broker, on
   `StartServiceByName`), `NameHasNoOwner` (dbus-broker, on a plain call), `org.freedesktop.systemd1.UnitMasked` / `NoSuchUnit` (dbus-daemon), or no reply (dbus-daemon, failing
   unit). `Spawn.ChildExited` appears only on a bus without systemd that executes `Exec=/bin/false`. The documentation must not name one error for this case.
2. What is **stable** across both buses and all three setups: `ListActivatableNames` lists the name exactly when the activation file is installed (broker 9 vs 8 names, daemon
   likewise); `NameHasOwner` is `true` only when the service runs; `GetNameOwner` fails with `NameHasNoOwner` whenever it does not run.
3. Through the proxy, **`--talk` makes every one of these results identical to the host** (including the error names and messages), so the same steps work.
4. Without `--talk`, **three situations collapse** into one: not installed, not activatable and running all look like *not installed* (`NameHasOwner false`, name absent from
   `ListActivatableNames`, `ServiceUnknown`). "Name not allowed by the sandbox" is therefore **indistinguishable from "not installed"** to the client; the proxy never answers
   `AccessDenied` for it. Only the documentation (the missing `--system-talk-name`) can separate them.

### Detection steps for the client documentation

Each step names the rows it separates.

1. Connect to the system bus (`DBUS_SYSTEM_BUS_ADDRESS`, or `/run/dbus/system_bus_socket`; inside flatpak it is the proxy socket). If it cannot connect: no system bus (not Custodio's problem).
2. `NameHasOwner("com.rfirma.Custodio1")` = `true` → **installed and running**; go on to call. Separates *running* from every other row.
3. `false` → `ListActivatableNames`, and look for the name. Present → **installed but not running**: go to step 4. Absent → **not installed, or not allowed by the sandbox**
   (the two cannot be told apart through the proxy, see finding 4): tell the person to install Custodio and, inside flatpak, to check that the app has
   `--system-talk-name=com.rfirma.Custodio1`. Separates *installed* from *not installed / not allowed*.
4. Installed, not running: `StartServiceByName("com.rfirma.Custodio1", 0)` (or just make the call; the bus activates it). Result `1` or `2` → started, go on. Any error (`ServiceUnknown`,
   `NameHasNoOwner`, `UnitMasked`, `NoSuchUnit`, `Spawn.*`, no reply) → **installed but not activatable**: report the error name and message to the person. Do not branch on
   which name, only on that it failed (finding 1).
5. After a successful start, use the interface; any error from it is a Custodio error (`docs/api.md`), not a detection result.

Distinguished: running / not activatable / not installed-or-not-allowed. Not distinguished: not installed vs not allowed by the sandbox (proxy rewrites every probe to the
same answers).

### Conflicts with the SPEC

- SPEC "Detection": "what a client sees when the service is absent, not activatable, or blocked by the sandbox" cannot be three different results: absent and blocked
  look the same through the proxy (finding 4). The documentation should say so and give the permission as the cause to check.
- Not a conflict with the SPEC, but a correction to the contract's example: it names `org.freedesktop.DBus.Error.Spawn.*` for "not activatable" (to be measured), and that name does not occur on dbus-broker or on dbus-daemon under systemd (finding 1). The SPEC names no error; it is not edited.
- Acceptance 15 ("detects the service by the documented steps") holds with steps 1–5: with `--talk`, every call the steps make passes. Real flatpak was not run here; the
  proxy was started with the command line flatpak 1.16.1 builds (`read`).

Detection: connect to the system bus; `NameHasOwner` true → running; else `ListActivatableNames` has the name → installed, try `StartServiceByName` and treat any error as not activatable (do not rely on one error name); the name absent → not installed or not allowed (`--system-talk-name` missing), indistinguishable through the proxy.

## F89: which agent answers, and how the agent dies with the CLI (2026-11-02)

Sources: polkit master (GitHub mirror `polkit-org/polkit`, `src/programs/pkttyagent.c`,
`src/polkitbackend/polkitbackendinteractiveauthority.c`; the installed `polkitd` is 126-2 and its
`pkttyagent --help` matches), systemd main (`src/shared/polkit-agent.c`, `src/shared/exec-util.c`).
Line numbers are approximate; no tag was pinned. Commands were run in the dev container.

**Deciding "no agent answers" (Outcome B).**
- verified: polkitd keeps agents in a table keyed by the subject exactly as registered; registering
  a subject that is already there fails ("An authentication agent already exists for the given
  subject"). A `unix-process` subject is accepted without a session check, so registering for a
  pid never collides with the session's agent.
- verified (`get_authentication_agent_for_subject`): for the subject being authorized, polkitd looks
  up the agent registered for that exact process; if it has `fallback=true` it is only remembered,
  then the session's agent is looked up, and the remembered fallback is used only if there is none.
  So `--fallback` never replaces or outranks an agent of the session. An agent registered for the
  process *without* `--fallback` would outrank the session's agent.
- verified: the Authority interface has no call or property that tells whether an agent exists
  (methods: EnumerateActions, CheckAuthorization, CancelCheckAuthorization, (Un)Register
  AuthenticationAgent(+WithOptions), AuthenticationAgentResponse(2), Enumerate/RevokeTemporary...;
  properties BackendName, BackendVersion, BackendFeatures). `pkcheck` has no such option. The only
  probe left, registering an agent for the session, is itself the forbidden act, and a
  `CheckAuthorization` with interaction starts an authentication. inferred: nothing side-effect-free
  exists. systemd does not probe either: `polkit_agent_open` forks `pkttyagent --notify-fd N
  --fallback` whenever the process has a controlling terminal and is not root.
- Result: no reliable check. The narrowest replacement that polkit itself enforces is
  `pkttyagent --fallback --process=PID,START_TIME`: it runs, but only for the CLI's process, and an
  agent of the session keeps answering. Recorded in `SPEC_DEVIATIONS.md`.
- command run: `pkttyagent --fallback --process=$$,1` exits 127 here ("Authorization not
  available"): no `polkitd` in the dev container, so a real registration cannot be shown here.

**`pkttyagent` and its parent (kill mechanism).**
- verified: `pkttyagent` never watches its parent or stdin (it sits in `g_main_loop_run`, handles
  only SIGTERM/SIGINT/SIGTSTP); `objdump -T /usr/bin/pkttyagent` imports `getppid` and no `prctl`.
  Option (1) is out. systemd uses `FORK_DEATHSIG_SIGTERM` (parent-death signal) itself.
- Option (2) probed in the container (`setpriv from util-linux 2.41.5`): a process started as
  `setpriv --pdeathsig=KILL -- sleep 300` from a shell was gone one second after `kill -9` of the
  shell; the same `sleep` started without `setpriv` was still alive. `setpriv` execs, so `ps` and
  `/proc/<pid>/cmdline` show `sleep 300`: the agent keeps its pid and its own argv.
- The signal fires when the parent *thread* exits, so the agent is spawned from the main thread.
- `setpriv` is not pinned by the packages: packaging must list `util-linux` (it is part of the
  base system of Debian, Fedora and Arch) as a runtime dependency. It is not optional: if it is
  missing, no agent is started (the same as a missing `pkttyagent`).
- Signals: the CLI forbids `unsafe`, so handlers come from the `ctrlc` crate (feature
  `termination`: SIGINT, SIGTERM, SIGHUP, MIT/Apache-2.0, depends on `nix`); `cargo deny check bans` passes with it.

## F90: packages that provide `setpriv` and `pkttyagent`

Probes run in the target containers (2026-11-02): `dnf provides /usr/bin/setpriv /usr/bin/pkttyagent` on almalinux:10 and fedora:44 gives
`util-linux` (setpriv) and `polkit` (pkttyagent) on both, so the rpm needs `util-linux` and already has `polkit`. `pacman -F` on
archlinux: `core/util-linux` has `usr/bin/setpriv`, `extra/polkit` has `usr/bin/pkttyagent`. Debian 13: `dpkg -S /usr/bin/setpriv` is
`util-linux`, which is Essential (`dpkg-query -W -f='${Essential}' util-linux` = yes), so the deb adds nothing; `pkttyagent` comes with
`polkitd`. The proof that the names resolve is `just e2e`, which installs the packages with each target's package manager.

## F91: `busctl call` does not report the error name (2026-11-02)

Run in the dev container (systemd 257) against a private `dbus-daemon`: `busctl --user call org.freedesktop.DBus /org/freedesktop/DBus
org.freedesktop.DBus GetNameOwner s com.nobody.x` prints only `Call failed: Could not get owner of name 'com.nobody.x': no such name`, with
and without `--verbose`; the error name (`org.freedesktop.DBus.Error.NameHasNoOwner`) is lost. So the per-call error name that F91 compares
cannot be read from busctl. The guest has GLib's D-Bus through python3-gi (the test agent already needs it, `e2e/agent.py`); a
`Gio.DBusProxy`-free `Gio.DBusConnection.call_sync` raises a `GLib.Error` whose `Gio.DBusError.get_remote_error` is the name.

## F97: pkttyagent with PAM checking the password (2026-11-02)

Probed in the debian13 guest (polkit 126, `just e2e-cases debian13 'cli-*'`), as the contract's step asked, before relying on it:
- verified: with the image's `polkit-1` PAM file (`pam_permit`) polkit's agent helper has no conversation, so a typed password proves nothing (control: the same run
  with `pam_permit` set for the step gives no `Password:` prompt, `import-right` fails to find the pkttyagent banner, and the wrong-password import succeeds).
- verified: with `auth required pam_unix.so` / `account required pam_unix.so` in `/etc/pam.d/polkit-1`, a `chpasswd`-set password for a fresh account (`carol`), and
  `/usr/lib/polkit-1/polkit-agent-helper-1` setuid root, `custodio import` and `custodio delete` on a pseudo-terminal with no agent in the session print
  `==== AUTHENTICATING FOR com.rfirma.custodio.<action> ====`, `Authenticating as: carol`, `Password: `; the right password ends `==== AUTHENTICATION COMPLETE ====`
  and the call succeeds; a wrong one ends `==== AUTHENTICATION FAILED ====`, `custodio: not authorized`, exit non-zero (no second prompt). So `pam_permit` is not needed
  as a fallback and the wrong-password case stays.
- verified: a D-Bus `ImportP12` from the same session with no terminal is refused with `PolkitDenied` (no agent registered), the precondition of those cases.
- verified: the service leaves an empty directory `<uid>` in its state directory for an account that had keys and deleted them; the step removes carol's (`rmdir`)
  with the account.

## F101: M3 acceptance 14 by hand on ubuntu2604, the client API with busctl (2026-11-02)

Machine: labvm `ubuntu2604` (libvirt), Ubuntu 26.04.1 LTS, kernel 7.0.0-38-generic, GNOME on Wayland (autologin, GNOME Shell's polkit agent),
dbus-daemon 1.16.2 (no dbus-broker), polkit 127 (`polkitd 127-2ubuntu1.1`), systemd 259.5, busctl from systemd 259, OpenSSL 3.5.5. Package
`custodio_0.1.0-1_amd64.deb` from `just package` at `e5a57af` (sha256 `ec52eebad0e1d16ac9d98cfa29bcddf806f749c1550cb57471d44b07ec43306a`),
installed with `apt-get install ./…`. Followed `docs/manual-acceptance.md` §16 and `docs/api.md` only; files from the six `openssl` commands
of "Examples". Every command ran in the desktop session (`labvm-gui`), as uid 1000.

| # | Dialog seen | Error or result seen | Result |
|---|---|---|---|
| 1 | none | service not yet started (bus activation): `NameHasOwner` `b false`, listed in `ListActivatableNames`, `StartServiceByName` `u 1`, then `b true`, and `u 2` | pass |
| 2 | none | `a(ssay) 0` | pass |
| 3 | "Authentication is required to import a certificate and key into Custodio", cancelled | `Call failed: not authorized` | pass |
| 4 | the import dialog, approved | `Call failed: wrong password or unreadable .p12 file` | pass |
| 5 | none | `Call failed: invalid arguments` | pass |
| 6 | the import dialog, approved | `s "ecdsa-p256"` | pass |
| 7 | none | `Call failed: a key with this id already exists` | pass |
| 8 | none | `a(ssay) 1 "demo" "ecdsa-p256" 375 …` | pass |
| 9 | "Authentication is required to replace a certificate held by Custodio", approved | `Call failed: certificate does not match the key` | pass |
| 10 | the replace dialog, approved | no output; the listed certificate (382 bytes) equals `renewed.der` byte for byte | pass |
| 11 | "Authentication is required to sign with a key held by Custodio", approved, twice | `ay 64 …` both times; a dialog each time | pass |
| 12 | none | `Call failed: no such key` | pass |
| 13 | "Authentication is required to delete a certificate held by Custodio", cancelled | `Call failed: not authorized`; `demo` still listed | pass |
| 14 | the delete dialog, approved | no output; `a(ssay) 0` | pass |

Journal (`journalctl -u custodio`): 9 entries for the 9 calls that reached polkit, in order: import denied, import failed (wrong password),
key imported, certificate replacement refused, certificate replaced, 2 signature made (`ecdsa`), delete denied, key deleted; all uid 1000,
`CUSTODIO_APP_ID_STATE=none`. Steps 5, 7 and 12 left no entry. None extra, none missing.

Acceptance 14: pass. Nothing needed beyond `docs/api.md`.

- Step 1 of §16 expects `b true` "with the service running". On a fresh install the service is bus-activated and not yet running, so
  the first answer was `b false`; the page's "do the other steps of Detection" covered it, and those steps matched `docs/api.md`.
- The two signatures of step 11 are identical: ECDSA here is deterministic (RFC 6979, M0 F-sign), not a cached reply; the dialog showed both times.
- The dialogs were answered from the hypervisor (`virsh send-key`: the lab account's password and Enter, or Escape), after a screenshot
  showed each dialog. Step 15 (`AuthorizationUnavailable`) was not run, as the page says.
- A person then repeated steps 0 to 14 and the journal check by hand on the same VM, restored to its clean snapshot with the same
  package, typing the commands in a desktop terminal and answering each dialog: every dialog, result and journal entry matched the
  table above.

## F102: M3 acceptance 15 by hand on fedora44, a test flatpak (2026-11-02)

Machine: labvm `fedora44` (libvirt), Fedora 44, GNOME on Wayland (autologin, GNOME Shell's polkit agent), dbus-broker 37, polkit 127,
systemd 259.5, flatpak 1.17.6, flatpak-builder 1.4.12. Package `custodio-0.1.0-1.x86_64.rpm` from `just package` at `e5a57af` (sha256
`72953e950230ee984832295fb82b534f91090d4f5bb10d5c977a426e5a961b73`; no code change since), installed with `dnf install`. Followed
`docs/manual-acceptance.md` §17. Key `p256` made as in §1 and imported with `custodio import` (the import dialog shown and approved).
Runtimes `org.freedesktop.Platform//24.08` and `org.freedesktop.Sdk//24.08` from flathub, as user installs. Commands ran in the desktop
session (`labvm-gui`), as uid 1000; dialogs answered from the hypervisor (`virsh send-key`) after a screenshot showed each one.

| # | Step | Expected | Seen | Result |
|---|---|---|---|---|
| 1 | Detection inside the flatpak | `b true`, name listed | `busctl: orden no encontrada` (twice), `not listed` | fail |
| 2-6 | Sign, journal | | not run: §17 says to stop when the runtime lacks `busctl` | not run |

Acceptance 15: **fail**. `org.freedesktop.Platform` 24.08 ships no `busctl`; it ships `gdbus`, `dbus-send` and `python3`. The manifest
`packaging/flatpak/com.rfirma.CustodioTest.json` (F99) and §17 step 2 call `busctl`.

- `flatpak-builder --user --install --force-clean build-dir …` as written failed: `fusermount3: failed to access mountpoint
  …/.flatpak-builder/rofiles/rofiles-…: Permission denied`, `Failure spawning rofiles-fuse`, over SSH and in the desktop session alike
  (no AVC logged). `--disable-rofiles-fuse` built and installed it; `flatpak info --show-permissions` shows only
  `[System Bus Policy] com.rfirma.Custodio1=talk`. The build also warns that the 24.08 runtime is end-of-life.
- Diagnosis outside the documented steps, with `gdbus` from the same sandbox (`flatpak run --command=gdbus com.rfirma.CustodioTest`):
  `NameHasOwner` → `(true,)`; `ListActivatableNames` lists `com.rfirma.Custodio1`; `Sign p256 4161 0 0 <32 zero bytes>` showed
  "Authentication is required to sign with a key held by Custodio", approved, and returned 64 bytes, twice, a dialog each time. Each
  signature's journal entry (base query of `docs/audit.md`) has `CUSTODIO_APP_ID=com.rfirma.CustodioTest`,
  `CUSTODIO_APP_ID_STATE=read`, `CUSTODIO_UID=1000` (= `id -u`), `CUSTODIO_OPERATION=sign`, `CUSTODIO_OUTCOME=signed`; on the second,
  `CUSTODIO_PID=5090` was the `xdg-dbus-proxy` seen running during the call (the application's `gdbus` was pid 5094). So the service
  meets acceptance 15; the test application and its page do not.

### F102 repeat after `fa76c48` (gdbus): pass

Same VM restored to `limpia`, same `.rpm`, §17 as changed by `fa76c48` (manifest and steps with `gdbus`, runtimes 25.08 from
flathub as user installs). `custodio import --id p256` again (import dialog, approved).

| # | Step | Expected | Seen | Result |
|---|---|---|---|---|
| 1 | Detection inside the flatpak | `(true,)`, name listed | `(true,)`, `'com.rfirma.Custodio1'` | pass |
| 2 | Sign: dialog action | `com.rfirma.custodio.sign` | "Authentication is required to sign with a key held by Custodio", approved | pass |
| 3 | Sign: result | 64 bytes | `([byte 0x5b, …],)`, 64 bytes | pass |
| 4 | Journal: app-id | `com.rfirma.CustodioTest`, state `read` | `CUSTODIO_APP_ID=com.rfirma.CustodioTest`, `CUSTODIO_APP_ID_STATE=read`; also found by the app-id query | pass |
| 5 | Journal: uid | `id -u` of the person | `CUSTODIO_UID=1000`, `id -u` 1000 | pass |
| 6 | Journal: pid | the proxy's, not the application's | `CUSTODIO_PID=4121` = `xdg-dbus-proxy`; `gdbus` was 4129 | pass |

Acceptance 15: pass. One entry since the step started (`signature made: uid 1000 pid 4121 key p256`), none extra.

- The documented build failed again on `rofiles-fuse`; the page's fallback (`--disable-rofiles-fuse`) built it. Permissions:
  only `com.rfirma.Custodio1=talk`.
- The two lines of step 2 were copied from the page into a file and run with `flatpak run --command=sh --filesystem=/tmp:ro
  com.rfirma.CustodioTest /tmp/step2.sh`, not typed into an interactive shell; the extra read-only `/tmp` is a file permission
  and does not touch the bus policy or the app-id.
- A person then repeated §17 by hand on the same VM, restored to its clean snapshot with the same package, following the steps in
  a desktop terminal (import of `p256`, build, detection, sign from `flatpak run --command=sh`, journal) and answering each dialog:
  every dialog, result and journal entry matched the table above.

## F103: M3 acceptance 16 by hand on fedora44, Firefox, LibreOffice and a second account (2026-11-02)

Machine: labvm `fedora44` (libvirt), Fedora 44, GNOME on Wayland (autologin, GNOME Shell's polkit agent), SELinux enforcing, dbus-broker
37, polkit 127, systemd 259.5, Firefox 150.0-1.fc44 (Fedora package, `/usr/bin/firefox`), LibreOffice 26.2.1.2-2.fc44, nss 3.131.0,
p11-kit 0.26.2. Package `custodio-0.1.0-1.x86_64.rpm` from `just package` at `e5a57af` (sha256
`72953e950230ee984832295fb82b534f91090d4f5bb10d5c977a426e5a961b73`; only the test flatpak manifest changed since), installed with
`dnf install`. Followed `docs/manual-acceptance.md` §18. Keys `rsa2048` and `p256` made as in §1 and imported with `custodio import` in
the desktop session (an import dialog each, approved). As in F54, the lab image's `softhsm2.module` was moved out of
`/usr/share/p11-kit/modules/`. Dialogs answered from the hypervisor after a screenshot showed each one.

| # | Step | Expected | Seen | Result |
|---|---|---|---|---|
| 1 | Firefox signs, dialog seen | signature made | No manual registration (through p11-kit-proxy, as F54). `openssl s_server -Verify 1 -www -no_ticket -no_cache` with a server certificate from the test CA. `p256`: selector, a dialog "Authentication is required to sign with a key held by Custodio" per signature, two approved (page and a second connection), page loads (`Peer signature type: ecdsa_secp256r1_sha256`). After a Firefox restart, `rsa2048`: approved, page loads (`rsa_pss_rsae_sha256`); reload and cancel the dialog: `SSL_ERROR_HANDSHAKE_FAILED` | pass |
| 2 | LibreOffice signs, dialog seen | valid signature | File > Digital Signatures > Digital Signatures > Sign Document offers both certificates. `rsa2048`: dialog, approved, XAdES `rsa-sha256`; signing again and cancelling the dialog added no signature. `p256`: cancel first (no signature added), then approved, XAdES `ecdsa-sha256`. Each document reopened after LibreOffice was closed: "Este documento está firmado digitalmente y la firma es válida" | pass |
| 3 | Journal comparison | none extra, none missing | 8 entries for 8 dialogs: Firefox 3 `signed` + 1 `denied` (pids 4526 and 5577, the Firefox process before and after the restart), LibreOffice 2 `signed` + 2 `denied` (pids 7061 and 8135, `soffice.bin` for each document); `CUSTODIO_UID=1000`, `CUSTODIO_APP_ID_STATE=none`, mechanisms `ecdsa`, `rsa_pkcs_pss_sha256` (Firefox) and `rsa_pkcs` (LibreOffice). Outside the base query only the two `key imported` entries | pass |
| 4 | Second account: token listing | no token | account `segunda` (uid 1001, no keys), its own logind session (`machinectl shell segunda@.host`): new NSS database, `modutil -list` shows `p11-kit-proxy` with no slots, `certutil -L -h all` empty, `pkcs11-tool -L` and `--list-objects` `No slots.` | pass |
| 5 | Second account: `ListKeys` | `a(ssay) 0` | `a(ssay) 0`; `custodio list` "You have no keys in the custodio service." | pass |

Acceptance 16: pass. No AVC from the start of the run (`ausearch -m AVC,USER_AVC --input-logs`: 0; `-m USER_AUTH`: 64);
`custodiod` runs as `unconfined_service_t`.

- §18 step 3 and step 5 say to register the module with `modutil -add` as in §6. On Fedora that fails: `ERROR: Failed to add module
  "custodio". Probable cause : "Unknown PKCS #11 error."`, for the person who signs and for the second account alike. Fedora's NSS
  loads `p11-kit-proxy` into every database, the proxy has already initialized the module in the same process, and the module's
  `C_Initialize` answers `CKR_CRYPTOKI_ALREADY_INITIALIZED` (`crates/custodio-pkcs11/src/module.rs`), which NSS reports as unknown.
  Nothing is lost: the tokens reach both clients through the proxy. Without `</dev/null` the command waits at its p11-kit warning
  prompt even with `-force`.
- LibreOffice used a dedicated NSS database (`certutil -N --empty-password`, CA trusted `C,C,C`) set as `CertDir` in the profile, as
  in F34; the selector named that directory. After signing it asks "¿Quiere recordar esta firma cada vez que guarde?": answered No.
- The second account was checked from the command line in its own session, not from a graphical login: its Firefox and LibreOffice
  were not opened. Both load Custodio through the same p11-kit-proxy whose listing in that account is empty.
- A person then repeated §18 by hand on the same VM, with the same package (keys deleted and imported again, Firefox, LibreOffice
  with two new documents, journal and AVC check, and the second account in a graphical login: its Firefox and LibreOffice offered no
  Custodio certificate) and answering each dialog: every dialog, result and journal entry matched the table above.

## F106

Which parent key in the owner hierarchy wraps the imported keys (the SPEC "Which parent" open
question). Everything below ran on `swtpm` (libtpms, IBM manufacturer id `0x49424d00`, TPM 2.0 in the
dev container) through `just with-swtpm bash -c '...'`, with `tpm2-tools` and the probe
`cargo run -p custodio-it --example tpm-probe -- parent [--tcti <tcti>]`. The restart and clear
experiments also use `just with-swtpm`: it exposes the control socket at `<TCTI path>.ctrl`, so
`swtpm_ioctl --unix <sock>.ctrl -i` (re-initialise, state kept) followed by `tpm2_startup -c` inside one
`bash -c` is a TPM restart on the same state. Nothing here was run on a hardware TPM: that is F111, with the
same probe. Each claim is **verified** (a command run here, or a source read) or **inferred**.

### The two candidates

- **A. Persistent SRK** at `0x81000001`, the handle the TCG provisioning guidance reserves for the SRK
  (what `systemd-cryptenroll` and `systemd-creds` use), created once from the TCG SRK template and made
  persistent with `TPM2_EvictControl`.
- **B. Primary recreated from a fixed template** on each use: `TPM2_CreatePrimary` in the owner hierarchy
  from a template the code carries. A primary is a function of the hierarchy seed and the template, so the
  same template gives the same key every time (the probe creates each template twice and compares). The
  object is transient and flushed after use.

The template compared is the TCG SRK template: restricted decryption key, `fixedTPM|fixedParent|
sensitiveDataOrigin|userWithAuth|noDA|restricted|decrypt`, name algorithm SHA-256, AES-128-CFB, null scheme,
empty unique field, in two variants: RSA 2048 and ECC P-256 (the probe's `srk_template`).

### The probe

`tpm-probe parent` prints one `key: value` line each. It never calls `EvictControl`, never sets an auth value
and never clears; it creates transient primaries and flushes them. Exit status: 0 when the TPM answered and
the owner hierarchy accepts an empty auth; 1 when the TPM cannot be reached or the owner hierarchy is
unusable (the facts that can still be read are printed first, the persistent key among them); 2 on a usage
error. The exit is therefore non-zero with an owner password even when candidate A would still work: the probe
reports "can the service provision or recreate", not "can it use an existing key", and prints the second fact
too (`persistent_0x81000001*`).

Read-only check: persistent handles, NV indexes and the persistent/NV counters before and after a probe, in
one `with-swtpm` call (each call starts a new TPM, so separate calls would prove nothing). It was run on the
fresh TPM and again with an SRK persisted (second diff below):

```
### A. read-only check on a fresh TPM
probe exit=0
listings identical
$ tpm2_getcap handles-persistent
$ tpm2_getcap handles-nv-index
$ tpm2_getcap properties-variable | grep -E 'HR_PERSISTENT|HR_NV|NV_COUNTERS'
TPM2_PT_HR_NV_INDEX: 0x0
TPM2_PT_HR_PERSISTENT: 0x0
TPM2_PT_HR_PERSISTENT_AVAIL: 0x41
TPM2_PT_NV_COUNTERS: 0x0
TPM2_PT_NV_COUNTERS_AVAIL: 0x19
```

Output on a fresh `swtpm` (`just with-swtpm cargo run -q --locked -p custodio-it --example tpm-probe -- parent`):

```
manufacturer: 0x49424d00 (IBM)
persistent_handles: none
nv_indexes: 0
persistent_0x81000001: empty
owner_hierarchy: accepts empty auth
rsa2048_name: 000b5579a95be4992ffc65f1af40ad99464974076145fdb1f68d09964f8ab5bad361
rsa2048_public_sha256: 5579a95be4992ffc65f1af40ad99464974076145fdb1f68d09964f8ab5bad361
rsa2048_deterministic: yes
rsa2048_mean_ms: 32.8 (N=5, each call includes ReadPublic and FlushContext)
ecc_p256_name: 000baf5f61e7b762f4b3e72f0dabdceb88977702a0fd434a40843a8480eb1d1618bf
ecc_p256_public_sha256: af5f61e7b762f4b3e72f0dabdceb88977702a0fd434a40843a8480eb1d1618bf
ecc_p256_deterministic: yes
ecc_p256_mean_ms: 4.4 (N=5, each call includes ReadPublic and FlushContext)
persistent_0x81000001_matches_srk: empty
```

Negative controls (the probe can fail). The environment TCTI is unset here; the messages differ by cause, so a
person on F111 can tell them apart:

```
$ tpm-probe parent --tcti swtpm:path=/nonexistent     (parsed fine, connect fails)   exit=1
tpm-probe: cannot connect to the TPM: TSS Layer: TCTI, Code: 0x000A000A, Message: IO failure.
$ tpm-probe parent --tcti bogus:x                     (fails while parsing)          exit=1
tpm-probe: malformed --tcti "bogus:x": The provided parameter is invalid for that type.
$ tpm-probe parent                                    (no TCTI at all)               exit=1
tpm-probe: no TCTI: pass --tcti or set TPM2TOOLS_TCTI/TCTI/TEST_TCTI: Some of the required parameters were not provided.
$ tpm-probe frob                                      (usage)                        exit=2
```

### Cost per call (candidate B)

Means over N=5 timed calls (after two untimed ones), each including `CreatePrimary`, `ReadPublic` and
`FlushContext`, on `swtpm`: **ECC P-256 about 4.3 to 4.4 ms, RSA 2048 about 23 to 33 ms** (two runs above:
32.8 and 23.1 ms). `swtpm` is software: a hardware TPM is slower for RSA by a large factor (RSA 2048 key
generation takes seconds on some parts), and ECC P-256 primaries are normally far cheaper there too. N is kept
small for that reason and printed next to each mean so F111 numbers can be compared. **Inferred** for hardware.
Mitigation either way: the service creates the primary once per import or load of a key, not per signature,
and may hold the loaded transient parent only while it loads a child.

### Candidate A: persistent SRK at `0x81000001`

NV write: **yes**. `TPM2_EvictControl` stores the object in the TPM's NV storage and consumes a persistent
slot. It does not create an NV index, so `handles-nv-index` stays empty; the persistent counters show it:

```
### B. persist an ECC P-256 SRK at 0x81000001
name-alg:
attributes:
persistent-handle: 0x81000001
action: persisted
$ tpm2_getcap handles-persistent
- 0x81000001
$ tpm2_getcap handles-nv-index
$ tpm2_getcap properties-variable | grep -E 'HR_PERSISTENT|HR_NV|NV_COUNTERS'
TPM2_PT_HR_NV_INDEX: 0x0
TPM2_PT_HR_PERSISTENT: 0x1
TPM2_PT_HR_PERSISTENT_AVAIL: 0x40
TPM2_PT_NV_COUNTERS: 0x0
TPM2_PT_NV_COUNTERS_AVAIL: 0x19
### probe with persisted SRK
manufacturer: 0x49424d00 (IBM)
persistent_handles: 0x81000001
nv_indexes: 0
persistent_0x81000001: occupied
persistent_0x81000001_template: ecc NistP256 fixedtpm=true fixedparent=true sensitivedataorigin=true userwithauth=true noda=true restricted=true decrypt=true sign=false
persistent_0x81000001_name: 000b59644dbdbedad559d8520067a3b2ce1c54dbcad446e6155dbe368eafb1f4c7cf
owner_hierarchy: accepts empty auth
rsa2048_name: 000b589ff68f2c2c3807ef8d4db72516ccbced13b1791648ca7c0c4ed5b7b938bc50
rsa2048_public_sha256: 589ff68f2c2c3807ef8d4db72516ccbced13b1791648ca7c0c4ed5b7b938bc50
rsa2048_deterministic: yes
rsa2048_mean_ms: 23.1 (N=5, each call includes ReadPublic and FlushContext)
ecc_p256_name: 000b59644dbdbedad559d8520067a3b2ce1c54dbcad446e6155dbe368eafb1f4c7cf
ecc_p256_public_sha256: 59644dbdbedad559d8520067a3b2ce1c54dbcad446e6155dbe368eafb1f4c7cf
ecc_p256_deterministic: yes
ecc_p256_mean_ms: 4.3 (N=5, each call includes ReadPublic and FlushContext)
persistent_0x81000001_matches_srk: yes (ecc_p256)
exit=0
### read-only check, persisted SRK present
listings identical
```

Secret in the service: **none**. The key is generated by the TPM from its seed and has an empty auth value (the
TCG template, `userWithAuth` with an empty auth, `noDA`). Provisioning needs the owner hierarchy authorisation,
which the service would have to hold when the owner has a password (see below).

Reboot: **survives** (verified). A restart of the TPM on the same state keeps the handle, the name and the
template (restart: `swtpm_ioctl -i` then `tpm2_startup -c`):

```
### C. restart swtpm on the same state (swtpm_ioctl -i on the control socket, then tpm2_startup -c)
startup rc=0
$ tpm2_getcap handles-persistent
- 0x81000001
$ tpm2_getcap handles-nv-index
$ tpm2_getcap properties-variable | grep -E 'HR_PERSISTENT|HR_NV|NV_COUNTERS'
TPM2_PT_HR_NV_INDEX: 0x0
TPM2_PT_HR_PERSISTENT: 0x1
TPM2_PT_HR_PERSISTENT_AVAIL: 0x40
TPM2_PT_NV_COUNTERS: 0x0
TPM2_PT_NV_COUNTERS_AVAIL: 0x19
persistent_0x81000001: occupied
persistent_0x81000001_template: ecc NistP256 fixedtpm=true fixedparent=true sensitivedataorigin=true userwithauth=true noda=true restricted=true decrypt=true sign=false
persistent_0x81000001_name: 000b59644dbdbedad559d8520067a3b2ce1c54dbcad446e6155dbe368eafb1f4c7cf
rsa2048_name: 000b589ff68f2c2c3807ef8d4db72516ccbced13b1791648ca7c0c4ed5b7b938bc50
ecc_p256_name: 000b59644dbdbedad559d8520067a3b2ce1c54dbcad446e6155dbe368eafb1f4c7cf
persistent_0x81000001_matches_srk: yes (ecc_p256)
```

`TPM2_Clear` (verified): the owner seed changes and the persistent object is removed with it. The next probe
shows the handle empty and new template names for both candidates:

```
### D. tpm2_clear (lockout auth empty)
rc=0
$ tpm2_getcap handles-persistent
$ tpm2_getcap handles-nv-index
$ tpm2_getcap properties-variable | grep -E 'HR_PERSISTENT|HR_NV|NV_COUNTERS'
TPM2_PT_HR_NV_INDEX: 0x0
TPM2_PT_HR_PERSISTENT: 0x0
TPM2_PT_HR_PERSISTENT_AVAIL: 0x41
TPM2_PT_NV_COUNTERS: 0x0
TPM2_PT_NV_COUNTERS_AVAIL: 0x19
persistent_handles: none
persistent_0x81000001: empty
rsa2048_name: 000b69d5385230987b95e648d5ab6787396c50142101930b0c4a322671aa22118b4f
ecc_p256_name: 000be85b77e10a0c9f28dc3e6ce6a4705b4a6ce42639a267f5e5dd4d4002ac698185
persistent_0x81000001_matches_srk: empty
```

Package upgrade: **inferred**. The TPM state is not part of the package, so an upgrade does not touch it. A
new package version could carry a different template, which would leave the old SRK at the handle with a name
that no longer matches (see "another template" below). Both candidates need the template to be frozen across
versions.

### Candidate B: primary recreated on each use

NV write: **no**. `CreatePrimary` allocates only a transient object, flushed after use; the probe does it twice
plus N timed calls and the listings are identical before and after (run A above). Secret in the service:
**none**. The primary has an empty auth value and no `sensitive.data` input; it derives from the owner seed and
the template only (the probe's `*_deterministic: yes` lines).

Reboot: **survives** (verified). The primary is a function of the seed: the names after the restart equal the
names before it (`rsa2048_name` `000b589f...` and `ecc_p256_name` `000b5964...` in the "probe with persisted SRK" run
and again after the restart, section C above). `TPM2_Clear`: **changes** (verified, section D: the names become
`000b69d5...` and `000be85b...`), so every key wrapped under the old primary is lost either way. Package
upgrade: **inferred**: the only thing the package carries is the template, so as long as the template bytes do
not change, the primary is the same; a changed template gives a different name, which the stored-parent-name
check (below) turns into an error instead of a failed load.

### Owner hierarchy with a password

`tpm2_changeauth -c o secret`, then creation without the password (verified):

```
### E. owner password, nothing persisted (candidate B, and first provisioning of A)
changeauth rc=0
ERROR: Esys_CreatePrimary(0x9A2) - tpm:session(1):authorization failure without DA implications
ERROR: Unable to run tpm2_createprimary
createprimary (no password) rc=1
$ probe
manufacturer: 0x49424d00 (IBM)
persistent_handles: none
nv_indexes: 0
persistent_0x81000001: empty
owner_hierarchy: unusable (TSS Layer: TPM, Code: 0x000009A2, Message: Authorization failure without DA implications (associated with session number 1).)
persistent_0x81000001_matches_srk: empty
probe exit=1
$ bad password
ERROR: Esys_CreatePrimary(0x9A2) - tpm:session(1):authorization failure without DA implications
ERROR: Unable to run tpm2_createprimary
rc=1
$ right password, candidate B works
rc=0
persistent-handle: 0x81000001
action: persisted
```

The exact response is `0x9A2`: `TPM_RC_AUTH_FAIL` as seen through a session ("authorization failure without DA
implications"; the owner hierarchy is not subject to the dictionary-attack lockout). The probe exits 1 and
quotes the code, and still prints the occupant of `0x81000001`.

- **B** needs the owner authorisation on every use, so with a password it fails with `0x9A2` on every import
  *and* on every later load: the service would have to keep the owner password. That is a secret in the
  service, which the SPEC default rules out. It fails; it does not fall back.
- **A** needs the owner authorisation only to provision, not to use. With an SRK already persisted, creating a
  child under it and loading it works without the owner password, while changing the persistent set (evict)
  still fails with `0x9A2`:

```
### F. owner password set AFTER the SRK was persisted: the persisted key still loads as a parent
$ probe
persistent_0x81000001: occupied
persistent_0x81000001_template: ecc NistP256 fixedtpm=true fixedparent=true sensitivedataorigin=true userwithauth=true noda=true restricted=true decrypt=true sign=false
persistent_0x81000001_name: 000b04dcc9f0f0b3c06b7033af2d521ac56d0adf7d32303d3b3becff3455160843e3
owner_hierarchy: unusable (TSS Layer: TPM, Code: 0x000009A2, Message: Authorization failure without DA implications (associated with session number 1).)
persistent_0x81000001_matches_srk: unknown (owner hierarchy unusable, no template name to compare)
probe exit=1
create under persisted SRK without owner password rc=0
name: 000b1f19e7a19cedc43a74b8f8cb6f5f8608aab60bf70d9cd7da59f73904f96d4bfa
load under persisted SRK without owner password rc=0
$ evict without password
ERROR: Esys_EvictControl(0x9A2) - tpm:session(1):authorization failure without DA implications
ERROR: Unable to run tpm2_evictcontrol
rc=1
password removed rc=0
```

If the owner has a password and the handle is empty, A cannot be provisioned either (`0x9A2`).

Service behaviour (both): an owner hierarchy it cannot use makes the import fail with a named error carrying the
TPM response code (`TPM_RC_AUTH_FAIL`, `0x9A2`); no fallback to the software key store, no retry with another
parent, and the service never asks for or stores the owner password.

### Another key at `0x81000001`

The occupant can be anything. A naive "use whatever is at the handle" would wrap keys under a key the
service did not create: a signing key cannot be a parent at all, and a storage key with another template or
a known auth value could be one the service cannot recreate or that another program controls. Negative controls
on `swtpm` (verified; G1 a signing key, G2 the SRK template with `noDA` cleared, G3 the service trying to write
over it):

```
### G. foreign occupants of 0x81000001
--- G1: a signing key (different type of use)
persistent_0x81000001: occupied
persistent_0x81000001_template: ecc NistP256 fixedtpm=true fixedparent=true sensitivedataorigin=true userwithauth=true noda=false restricted=false decrypt=false sign=true
persistent_0x81000001_name: 000bdac6def86a62661909e6a1d150b1706bad0d9bfa710f2428ccdb97ab1f86268f
ecc_p256_name: 000b04dcc9f0f0b3c06b7033af2d521ac56d0adf7d32303d3b3becff3455160843e3
persistent_0x81000001_matches_srk: no
--- G2: same type, one attribute differs (noda cleared)
persistent_0x81000001: occupied
persistent_0x81000001_template: ecc NistP256 fixedtpm=true fixedparent=true sensitivedataorigin=true userwithauth=true noda=false restricted=true decrypt=true sign=false
persistent_0x81000001_name: 000bbcdb0ba2d4cd920323778505ccd5cd1fea621f1655d589b5d8eab4875b8fb115
ecc_p256_name: 000b04dcc9f0f0b3c06b7033af2d521ac56d0adf7d32303d3b3becff3455160843e3
persistent_0x81000001_matches_srk: no
probe exit=0
--- G3: evictcontrol onto an occupied handle (what a service must never do)
ERROR: Esys_EvictControl(0x14C) - tpm:error(2.0): NV Index or persistent object already defined
ERROR: Unable to run tpm2_evictcontrol
persist onto occupied rc=1
```

The probe tells them apart in two ways: the `persistent_0x81000001_template` line (restricted, decrypt, sign,
noda), and the name, which is the SHA-256 of the whole public area, so any difference gives
`persistent_0x81000001_matches_srk: no`, while the expected SRK gives `yes (ecc_p256)` or `yes (rsa2048)`. The
service must treat `no` as unusable: error, no overwrite, no eviction (it does not own the handle; and
`EvictControl` onto an occupied handle fails with `0x14C` anyway). Candidate B has no such case: it never reads
the handle.

### Where a stored blob records the parent name

A key created under a parent is stored as `TPM2B_PUBLIC` plus `TPM2B_PRIVATE`. Neither carries the parent name
in clear (verified below: the digest of the parent's name does not occur in either file). What the TPM enforces is cryptographic: the
private part is an inner-wrapped sensitive area plus an integrity HMAC whose key is derived from the parent's
seed and which covers the child's name. `TPM2_Load` under any other parent, or under the same template after a
`TPM2_Clear`, fails:

```
### H. parent name in the stored blob
A name: 000bd220817b6187c743d7ae66c7c2e120fa00f5ac76be002724aab1ee89ca4e134b
create rc=0
34 c.cdata
128 c.priv
90 c.pub
parent name digest inside c.pub: 0
parent name digest inside c.priv: 0
parent name digest inside c.cdata: 0
$ load under A (same parent)
name: 000be63b67ed957b7b8deaf56488e73309c64b4f8f1832632bbe2f657403742bf894
rc=0
$ load under B (RSA SRK template, same hierarchy)
ERROR: Esys_Load(0x1DF) - tpm:parameter(1):integrity check failed
ERROR: Unable to run tpm2_load
rc=1
$ load under A' (same template, after tpm2_clear)
A' name: 000bb3488b64ff9b06d5aa9bf527e412fb6a859608af624900def561e1843c5cb234
ERROR: Esys_Load(0x1DF) - tpm:parameter(1):integrity check failed
ERROR: Unable to run tpm2_load
rc=1
```

The error is `0x1DF`, `TPM_RC_INTEGRITY` on parameter 1 ("integrity check failed"). It does not say which
parent was expected, and the same code appears for a damaged blob. So the **service stores the parent name
itself, next to the blob** (a `parent_name` field: the 34 bytes `000b || sha256` of the parent's public area),
and before `Load` it computes the name of the parent it is about to use (B: `CreatePrimary` then
`ReadPublic`; A: `ReadPublic` of `0x81000001`) and compares: a mismatch is the named error "stored under a
different parent" (clear, other template, other TPM, other template version) without ever sending the blob to
the TPM. The TPM check is the backstop; its `0x1DF` is the error the service reports if the check was skipped
or the stored name was edited.

### Package removal

For the chosen parent (B): **nothing in the TPM**. No persistent object, no NV index and no auth value was
created, so removal has nothing to evict. Only the service's own state (the stored wrapped keys and their
`parent_name`) is removed or kept, as the removal policy for the key store dictates. For A, removal must not
evict `0x81000001`: the handle is shared with `systemd-cryptenroll`, `systemd-creds` and other tools, whose
credentials depend on it, so a package that removes it can destroy data it did not create. Even the rule "evict
only if the name matches our template" would remove keys of other tools that use the same TCG template.

### Sources read

- **TCG TPM v2.0 Provisioning Guidance**, Version 1.0 Revision 1.0 (15 March 2017), Table 2: the SRK is
  `0x81000001` (EK `0x81010001`). **verified** (PDF read). Section 7.5.1 derives the shared SRK template from
  the EK Credential Profile 2.0 with four changes (set `userWithAuth`, clear `adminWithPolicy`, set `noDA`,
  empty `authPolicy`), and a shared SRK uses an all-zero well-known auth value. **verified**. The remaining fields
  of the probe's template (AES-128-CFB, null scheme, SHA-256 name, RSA 2048 / exponent 0 / 256 zero bytes of
  unique, ECC P-256 / 32+32 zero bytes) come from the EK profile and were **inferred** from memory, not read.
  The "Persistent Handle Assignments" reference was not read.
- **systemd v257** (`src/shared/tpm2-util.c`, `tpm2-util.h`, `src/tpm2-setup/tpm2-setup.c`; about 200 of the 330 KB
  of `tpm2-util.c` were read): `TPM2_SRK_HANDLE` is `0x81000001`; the template is ECC P-256 (preferred) or
  RSA 2048, SHA-256 name, AES-128-CFB, null scheme, empty authPolicy, `noDA`, `userWithAuth`, unique zeroed.
  **verified**. With the handle empty, `tpm2_get_or_create_srk` runs `CreatePrimary` in the owner hierarchy and
  `Esys_EvictControl` with the owner as authoriser, so it relies on an empty owner auth. **verified**. With the
  handle occupied it compares nothing: it uses whatever is there (on `TPM2_RC_NV_DEFINED` it re-reads the
  handle and uses that). **verified**. `systemd-tpm2-setup` pins the SRK public key in
  `/run/systemd/tpm2-srk-public-key.pem` and under `/var/lib/systemd/`; a mismatch with the `/run` copy is
  fatal. **verified**. No evict, clear or flush of the SRK was found in the files read; the last 130 KB of
  `tpm2-util.c`, the package scripts, and the `cryptenroll` and `creds` sources were not read, so "never
  evicts on removal" is **inferred**. This matches the finding above: systemd's "use whatever is there" is
  exactly the behaviour Custodio must not copy.
- `tpm2_createprimary` (tpm2-tools 5.7): name hash SHA-256, RSA 2048 and ECC P-256 are the defaults, a
  restricted parent gets `aes128cfb`. **verified**. Its default attributes do not include `noDA` (**inferred**;
  the experiments above pass the attributes explicitly).

### Decision

Applying the SPEC default (no NV write, no secret in the service, an unusable owner hierarchy fails the import
and never falls back): candidate B. A is rejected because it needs an NV write, a provisioning step that needs
the owner password when one is set, a shared handle with a foreign-key case, and an eviction rule on removal.
B costs 4 ms per creation on ECC P-256 (RSA 2048 about 25 ms on `swtpm`, far more on hardware), fails
with `0x9A2` when the owner has a password, and loses every wrapped key at `TPM2_Clear`, as A does too.
The template is the ECC P-256 TCG SRK template above, frozen in code with its name checked in a test;
F111 runs the probe on a hardware TPM and confirms the cost and that ECC P-256 is available there before
the choice is recorded in `docs/decisions.md`. The service never writes persistent state to the TPM.

Decision: a primary recreated on each use from the fixed TCG SRK template, ECC P-256 (no persistent SRK at 0x81000001)

## F107

Mechanism parity on the TPM, and the capabilities each key type needs: the SPEC open questions "Mechanism
parity on the TPM" and "A TPM that lacks a capability only for some mechanisms", for a person to approve in
F111. Everything below ran on `swtpm` 0.7.1-1.5 with libtpms 0.9.2-3.2 (TPM 2.0 revision 1.64, firmware
version raw `0x20191023`, manufacturer IBM), inside `just with-swtpm`, with the probe
`cargo run -q --locked -p custodio-it --example tpm-probe -- mechanisms [--tcti <tcti>]` and with the tests
`cargo test -p custodio-it --test tpm_filter -- --nocapture`. Nothing ran on a hardware TPM: that is F111, with the
same probe command. Each claim is **verified** (a command run here) or **inferred**.

Scope: RSA 2048 and ECC P-256 only, the two kinds M4 ships. RSA 3072/4096 and P-384 are not probed. Import
(`TPM2_Import`), the real capability query in the service and the parent key (F106) are other features: the probe
uses transient primaries in the owner hierarchy, because the mechanism behaviour does not depend on the parent.

### Method

- **The two ways.** (a) `TPM2_Sign` only: the probe parses a `DigestInfo` for `CKM_RSA_PKCS`, serves
  `CKM_RSA_PKCS_PSS` only when the requested salt length is the one the TPM produces, and everything else is
  `lacks`. (b) The padding is built in the probe (PKCS#1 v1.5 block type 1, EMSA-PSS with MGF1 and a random salt
  of the requested length) and the TPM does only the raw RSA private operation, `TPM2_RSA_Decrypt` with the null
  scheme on a key with the `decrypt` attribute. (b) is RSA only: `CKM_ECDSA` has no raw private operation to
  replace `TPM2_Sign`, so the probe prints `way=b ... outcome=n/a` for it; it is not an unrun case.
- **The verifier is not the probe.** Every signature is checked by the `openssl` command line (3.5.7), on files in a
  temporary directory: `pkeyutl -verifyrecover` for `CKM_RSA_PKCS` (the signature must open to exactly the payload;
  `-verify` refuses inputs over 64 bytes, a SHA-512 `DigestInfo` is 83), `pkeyutl -verify` with `rsa_padding_mode:pss`,
  `rsa_pss_saltlen:<n>` and `rsa_mgf1_md` for PSS, `pkeyutl -verify` for ECDSA. The probe's padding code is never
  run backwards. The first run of the probe printed `verified=no` for the SHA-384/512 `DigestInfo` and for the
  largest salt in (b); both were probe bugs (the 64-byte limit above, and `TPM2_GetRandom` returning at most 64 bytes
  for a 222-byte salt), found because the verifier was independent, and fixed. The probe exits 1 when a served
  signature does not verify (it did, for those runs), so a broken probe cannot pass the `verify`.
- **Table rule for (a).** For `CKM_RSA_PKCS_PSS`, "served" means the requested salt length equals the salt the TPM
  produces. Every other length is `lacks` by that policy (the cell says `policy:`), not a TPM error: the TPM was
  asked for the same signature and gave the same one.
- **Negative controls, all in the output:** the verifier rejects a right signature over a wrong payload
  (`control: verifier ... wrong_payload=no`); a wrong expected salt (found + 1) does not verify
  (`wrong_salt_verifies=no`); the rightmost 32 bytes of a SHA-384/512 digest do not verify an ECDSA signature made
  over the leftmost 32 (`verified_over_rightmost_32=no`); a sign-only key refuses the raw operation (`0x182`).

### The probe output

Pasted from one run (`exit 0`; the lines of the capability section are the list further down).

```
manufacturer: 0x49424d00 (IBM)
persistent_handles: none
nv_indexes: 0
verifier: OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)
table_rule_a: CKM_RSA_PKCS_PSS is served under (a) only when salt_requested equals the salt the TPM produces; any other length is lacks by that policy, not a TPM error
key: rsa2048 sign-only fixedtpm=true fixedparent=true sensitivedataorigin=true restricted=false sign=true decrypt=false
key: rsa2048 sign|decrypt fixedtpm=true fixedparent=true sensitivedataorigin=true restricted=false sign=true decrypt=true
key: ecc_p256 sign-only fixedtpm=true fixedparent=true sensitivedataorigin=true restricted=false sign=true decrypt=false
control: verifier right_payload=yes wrong_payload=no
case: way=a mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-1 outcome=served rc=- verified=yes
case: way=a mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-256 outcome=served rc=- verified=yes
case: way=a mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-384 outcome=served rc=- verified=yes
case: way=a mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-512 outcome=served rc=- verified=yes
case: way=a mechanism=CKM_RSA_PKCS payload="36-byte MD5+SHA-1 stand-in (TLS 1.0/1.1)" outcome=lacks rc=service parser: not a known DigestInfo tpm_if_passed_as_digest=Code: 0x000001D5, Message: Structure is the wrong size (associated with parameter number 1). 
case: way=a mechanism=CKM_RSA_PKCS payload="DigestInfo with an unknown hash OID" outcome=lacks rc=service parser: not a known DigestInfo tpm_if_passed_as_digest=Code: 0x000001D5, Message: Structure is the wrong size (associated with parameter number 
salt_found: hash=SHA-256 tpm_salt=32 hash_len=32 equals_hash_len=yes largest_possible=222 wrong_salt_verifies=no
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=32 outcome=served rc=- salt_found=32 verified=yes
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=222 outcome=lacks rc=policy: TPM salt is 32, not 222 salt_found=32 verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=0 outcome=lacks rc=policy: TPM salt is 32, not 0 salt_found=32 verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=20 outcome=lacks rc=policy: TPM salt is 32, not 20 salt_found=32 verified=n/a
salt_found: hash=SHA-384 tpm_salt=48 hash_len=48 equals_hash_len=yes largest_possible=206 wrong_salt_verifies=no
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=48 outcome=served rc=- salt_found=48 verified=yes
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=206 outcome=lacks rc=policy: TPM salt is 48, not 206 salt_found=48 verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=0 outcome=lacks rc=policy: TPM salt is 48, not 0 salt_found=48 verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=20 outcome=lacks rc=policy: TPM salt is 48, not 20 salt_found=48 verified=n/a
salt_found: hash=SHA-512 tpm_salt=64 hash_len=64 equals_hash_len=yes largest_possible=190 wrong_salt_verifies=no
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=64 outcome=served rc=- salt_found=64 verified=yes
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=190 outcome=lacks rc=policy: TPM salt is 64, not 190 salt_found=64 verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=0 outcome=lacks rc=policy: TPM salt is 64, not 0 salt_found=64 verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=20 outcome=lacks rc=policy: TPM salt is 64, not 20 salt_found=64 verified=n/a
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-256 handover=truncated32+SHA-256 outcome=served rc=- verified_over_leftmost_32=yes verified_over_full_digest=yes verified_over_rightmost_32=no
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-256 handover=full+own-hash outcome=served rc=- verified_over_leftmost_32=yes verified_over_full_digest=yes verified_over_rightmost_32=no
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-384 handover=truncated32+SHA-256 outcome=served rc=- verified_over_leftmost_32=yes verified_over_full_digest=yes verified_over_rightmost_32=no
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-384 handover=full+own-hash outcome=served rc=- verified_over_leftmost_32=yes verified_over_full_digest=yes verified_over_rightmost_32=no
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-512 handover=truncated32+SHA-256 outcome=served rc=- verified_over_leftmost_32=yes verified_over_full_digest=yes verified_over_rightmost_32=no
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-512 handover=full+own-hash outcome=served rc=- verified_over_leftmost_32=yes verified_over_full_digest=yes verified_over_rightmost_32=no
case: way=b mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-1 outcome=served rc=- verified=yes bytes_equal_way_a_same_key=yes
case: way=b mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-256 outcome=served rc=- verified=yes bytes_equal_way_a_same_key=yes
case: way=b mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-384 outcome=served rc=- verified=yes bytes_equal_way_a_same_key=yes
case: way=b mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-512 outcome=served rc=- verified=yes bytes_equal_way_a_same_key=yes
case: way=b mechanism=CKM_RSA_PKCS payload="36-byte MD5+SHA-1 stand-in (TLS 1.0/1.1)" outcome=served rc=- verified=yes bytes_equal_way_a_same_key=n/a (way a lacks)
case: way=b mechanism=CKM_RSA_PKCS payload="DigestInfo with an unknown hash OID" outcome=served rc=- verified=yes bytes_equal_way_a_same_key=n/a (way a lacks)
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=32 outcome=served rc=- salt_found=32 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=222 outcome=served rc=- salt_found=222 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=0 outcome=served rc=- salt_found=0 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=20 outcome=served rc=- salt_found=20 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=48 outcome=served rc=- salt_found=48 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=206 outcome=served rc=- salt_found=206 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=0 outcome=served rc=- salt_found=0 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=20 outcome=served rc=- salt_found=20 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=64 outcome=served rc=- salt_found=64 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=190 outcome=served rc=- salt_found=190 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=0 outcome=served rc=- salt_found=0 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=20 outcome=served rc=- salt_found=20 verified=yes
control: way=b key_without_decrypt rsa_decrypt=Code: 0x00000182, Message: Inconsistent attributes (associated with handle number 1).
case: way=b mechanism=CKM_ECDSA curve=P-256 digest=SHA-256 outcome=n/a rc=RSA only: ECDSA has no raw private operation the TPM offers in place of TPM2_Sign
case: way=b mechanism=CKM_ECDSA curve=P-256 digest=SHA-384 outcome=n/a rc=RSA only: ECDSA has no raw private operation the TPM offers in place of TPM2_Sign
case: way=b mechanism=CKM_ECDSA curve=P-256 digest=SHA-512 outcome=n/a rc=RSA only: ECDSA has no raw private operation the TPM offers in place of TPM2_Sign
capability: call=GetCapability(ALGS) item=algorithm RSA (0x0001) present
capability: call=GetCapability(ALGS) item=algorithm SHA-1 (0x0004) present
capability: call=GetCapability(ALGS) item=algorithm SHA-256 (0x000b) present
capability: call=GetCapability(ALGS) item=algorithm SHA-384 (0x000c) present
capability: call=GetCapability(ALGS) item=algorithm SHA-512 (0x000d) present
capability: call=GetCapability(ALGS) item=algorithm RSASSA (0x0014) present
capability: call=GetCapability(ALGS) item=algorithm RSAES (0x0015) present
capability: call=GetCapability(ALGS) item=algorithm RSAPSS (0x0016) present
capability: call=GetCapability(ALGS) item=algorithm ECDSA (0x0018) present
capability: call=GetCapability(ALGS) item=algorithm ECC (0x0023) present
capability: call=GetCapability(ALGS) item=algorithm MGF1 (0x0007) present
capability: call=GetCapability(ECC_CURVES) item=curve NIST P-256 (0x0003) present
capability: call=TestParms key=rsa2048 scheme=RSASSA hash=SHA-1 supported
capability: call=TestParms key=rsa2048 scheme=RSASSA hash=SHA-256 supported
capability: call=TestParms key=rsa2048 scheme=RSAPSS hash=SHA-256 supported
capability: call=TestParms key=ecc_p256 scheme=ECDSA hash=SHA-256 supported
capability: call=TestParms key=rsa2048 scheme=RSASSA hash=SHA-384 supported
capability: call=TestParms key=rsa2048 scheme=RSAPSS hash=SHA-384 supported
capability: call=TestParms key=ecc_p256 scheme=ECDSA hash=SHA-384 supported
capability: call=TestParms key=rsa2048 scheme=RSASSA hash=SHA-512 supported
capability: call=TestParms key=rsa2048 scheme=RSAPSS hash=SHA-512 supported
capability: call=TestParms key=ecc_p256 scheme=ECDSA hash=SHA-512 supported
capability: call=TestParms key=rsa2048 scheme=NULL (for way b, with the decrypt attribute) supported
decrypt_key: sign-only attributes: fixedtpm=true fixedparent=true sensitivedataorigin=true restricted=false sign=true decrypt=false
decrypt_key: sign|decrypt attributes: fixedtpm=true fixedparent=true sensitivedataorigin=true restricted=false sign=true decrypt=true
decrypt_other_caller: key=sign-only rsa_decrypt(RSAES, chosen ciphertext) refused Code: 0x00000182, Message: Inconsistent attributes (associated with handle number 1).
decrypt_other_caller: key=sign-only sign(RSASSA, SHA-256, chosen digest) served
decrypt_other_caller: key=sign-only duplicate(no new parent) Code: 0x00000124, Message: Authorization handle is not correct for command.
decrypt_other_caller: key=sign|decrypt rsa_decrypt(RSAES, chosen ciphertext) plaintext recovered: "secret message"
decrypt_other_caller: key=sign|decrypt sign(RSASSA, SHA-256, chosen digest) served
decrypt_other_caller: key=sign|decrypt duplicate(no new parent) Code: 0x00000124, Message: Authorization handle is not correct for command.
result: every case ran; every served signature verified
```

### Results per mechanism (verified)

Every "served" cell was verified by `openssl` (above). `lacks` cells give the cause.

| Mechanism | Way (a) `TPM2_Sign` only | Way (b) padding in the service, raw private operation in the TPM |
|---|---|---|
| `CKM_RSA_PKCS`, `DigestInfo` SHA-1, SHA-256, SHA-384, SHA-512 | served, verified (the probe parses the `DigestInfo` and passes the digest with `RSASSA` and the hash) | served, verified, and the bytes equal (a)'s on the same key (PKCS#1 v1.5 is deterministic) |
| `CKM_RSA_PKCS`, payload that is not a `DigestInfo`: a 36-byte stand-in for the MD5+SHA-1 of TLS 1.0/1.1 (right length, SHA-256 bytes), and a `DigestInfo` with a hash OID no table knows | `lacks`: the parser refuses; handed to the TPM as a digest it answers `0x1D5` (wrong size) | served, verified |
| `CKM_RSA_PKCS_PSS`, SHA-256/384/512, salt = hash length (32/48/64) | served, verified (this is what the TPM produces) | served, verified |
| `CKM_RSA_PKCS_PSS`, salt largest that fits (222/206/190) | `lacks` (policy: the TPM's salt is the hash length) | served, verified at that salt |
| `CKM_RSA_PKCS_PSS`, salt 0 and salt 20 | `lacks` (policy) | served, verified at that salt |
| `CKM_ECDSA`, P-256, SHA-256/384/512 digest, the service's truncation | served, verified (see "Hashes a P-256 key needs") | n/a: RSA only |

The composed mechanisms (`CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, `CKM_SHA512_RSA_PKCS`,
`CKM_SHA256_RSA_PKCS_PSS` and the other hashes, `CKM_ECDSA_SHA256/384/512`) hash in the module or the service and
then call the base case, so they reduce to the rows above and need nothing further from the TPM.

`CKM_RSA_PKCS` with a payload that is not a `DigestInfo` is the one row where the two ways differ in kind: (a) cannot
serve it at all (TLS 1.0/1.1 client authentication signs the 36-byte MD5+SHA-1 concatenation, and any PKCS#11
client may hand `CKM_RSA_PKCS` any payload that fits), (b) serves it and the result verifies. The SHA-1
`DigestInfo` is served by this `swtpm` under (a); a TPM or firmware policy that disables SHA-1 would turn it into
`lacks` (inferred; F111 repeats the probe).

### PSS salt length per hash (verified)

The salt is found by verifying with each length 0 to the largest that fits and taking the one that verifies; the
`salt_found` lines:

| Hash | Salt the TPM produces | Hash length | Equal? | Largest that fits in 2048 bits |
|---|---|---|---|---|
| SHA-256 | 32 | 32 | yes | 222 |
| SHA-384 | 48 | 48 | yes | 206 |
| SHA-512 | 64 | 64 | yes | 190 |

libtpms 0.9.2 uses the hash length, as SPEC section 4 says. So TLS 1.3 (salt = hash length) works under (a) on this
`swtpm`, and the other lengths do not. Whether a hardware TPM does the same is not known (inferred from SPEC's
remark that firmware differs; the TPM 2.0 structures text has said "the largest salt that fits"): F111 must read the
`salt_found` lines on the hardware. Under (b) the salt is whatever the service builds, so this does not matter.

### Hashes a P-256 key needs from the TPM (verified)

`CKM_ECDSA` takes a digest. The service truncates a SHA-384/512 digest to its leftmost 32 bytes
(`docs/decisions.md`, 2026-10-28). Two ways to hand it to `TPM2_Sign` were run:

- `truncated32+SHA-256`: the 32 bytes with the scheme `ECDSA` and hash SHA-256. Served for all three digests; the
  signature verifies over the leftmost 32 bytes and not over the rightmost 32.
- `full+own-hash`: the whole 48 or 64-byte digest with the scheme hash SHA-384 or SHA-512. Also served here, and it
  verifies over the leftmost 32 bytes, so this TPM truncates by itself. It needs SHA-384/SHA-512 from the TPM.

(OpenSSL's ECDSA verification also truncates a long digest, so `verified_over_full_digest=yes` is expected; the
rightmost-32 control is what shows the truncation is to the leftmost bytes.) A P-256 key therefore needs **SHA-256
only** from the TPM when the service hands over the 32 truncated bytes, which it already computes. That is the
recommended hand-over: it keeps the truncation in one place and does not make a TPM without SHA-384/512 lack
`CKM_ECDSA`.

### The `decrypt` attribute against the threat model

What was run (`decrypt_*` lines): a sign-only and a sign|decrypt RSA key were created under a primary, their blobs
kept, the first connection closed, and **a second connection** recreated the primary and loaded the blobs, as another
holder of the TPM and of the state directory could.

- The sign|decrypt key (`sign=true decrypt=true`; the TPM accepts both on an unrestricted key with the null scheme; the spec
  rejects them together only on restricted keys, which was not run) decrypted a PKCS#1 v1.5 ciphertext that `openssl` made to its public
  key: `plaintext recovered: "secret message"`. The sign-only key refused: `0x182`, attributes.
- Both keys signed a digest of the caller's choosing (`RSASSA`, SHA-256): so signing is possible for any holder with
  or without `decrypt`. That is the "Root can use a TPM key" row of the SPEC threat model, accepted by design.
- Neither key could be duplicated: `TPM2_Duplicate` answered `0x124` (an authorization of the wrong kind: the key's
  empty `authPolicy` needs a policy session that cannot be built). `decrypt` does not change that: the key stays
  `fixedTPM|fixedParent`, nothing leaves the TPM. The in-scope threat "take a key out of the TPM" is not affected.

What the attribute adds, then, is **decryption of chosen ciphertexts** (anything encrypted to the certificate's
public key: S/MIME or CMS messages, a recorded TLS-RSA key exchange) and **signing of arbitrary padding** (the raw
operation signs any block, so also formats the service does not offer). Both are *use* of the key by someone who
controls the running machine and can reach the TPM. SPEC "Out of scope" lists exactly that: "root *using* a key
while it controls the running machine". The in-scope items (root reading the state directory, a stolen disk,
`TPM2_Duplicate`) are unchanged. What does change is the content of "Root can use a TPM key": root could already
sign in the name of the certificate; with `decrypt` root could also read past mail encrypted to it. For the
encrypted kinds root can do both and also copy the key, so a TPM key with `decrypt` is still strictly stronger than
the fallback. The service itself never exposes decryption (no `C_Decrypt` path), and under (b) it never passes a
client-chosen block to the raw operation: it always builds the padding itself. SPEC "Attributes of the imported
key" asks for "no more usages than" the mechanisms need, and says whether that includes `decrypt` "is an open
question": under (b) it does.

### The TPM capabilities each key type needs (the list the service will query)

Written once. Calls: `GetCapability(ALGS)` (`TPM2_GetCapability` with `TPM_CAP_ALGS`), `GetCapability(ECC_CURVES)`
(`TPM_CAP_ECC_CURVES`), `GetCapability(COMMANDS)` (`TPM_CAP_COMMANDS`), `TestParms` (`TPM2_TestParms`, the
exact check for a combination of type, size, scheme and hash). On `swtpm` every item answered "present" or
"supported" (the `capability:` lines above; the commands: `tpm2_getcap commands` lists `TPM2_CC_Import`,
`TPM2_CC_Load`, `TPM2_CC_Sign`, `TPM2_CC_RSA_Decrypt`, `TPM2_CC_TestParms`, `TPM2_CC_GetCapability`).

**RSA 2048, way (b)** (the recommended one):

| Item | Answered by |
|---|---|
| algorithm RSA (`0x0001`) | `GetCapability(ALGS)` |
| key size 2048, exponent 65537, scheme null | `TestParms` rsa2048 null scheme |
| name algorithm SHA-256 (`0x000b`) | `GetCapability(ALGS)` |
| the `decrypt` attribute on a signing key: the command `TPM2_RSA_Decrypt` is implemented | `GetCapability(COMMANDS)`; the attribute itself is only proven by the import succeeding and `tpm2_readpublic` showing it (it cannot be queried) |
| no hash, no signature scheme: the service hashes and pads | nothing to query |

**RSA 2048, way (a)** (not recommended; listed so the choice is complete): the rows above except the `decrypt`
attribute, plus scheme `RSASSA` (`0x0014`) with each of SHA-1, SHA-256, SHA-384, SHA-512 (`TestParms` for each),
scheme `RSAPSS` (`0x0016`) with each of SHA-256, SHA-384, SHA-512 (`TestParms` for each), and the salt the TPM
produces (not queryable: found by signing, as the probe does).

**ECC P-256:**

| Item | Answered by |
|---|---|
| algorithm ECC (`0x0023`) | `GetCapability(ALGS)` |
| curve NIST P-256 (`0x0003`) | `GetCapability(ECC_CURVES)` |
| scheme ECDSA (`0x0018`) with hash SHA-256 | `TestParms` ecc P-256 ECDSA SHA-256 |
| name algorithm SHA-256 | `GetCapability(ALGS)` |
| SHA-384 and SHA-512: **not needed** with the truncated hand-over | nothing to query |

An item the TPM answers "absent" or "unsupported" is "lacks" (SPEC section 2); any other failure of a query is not,
and fails the import.

### Simulating a TPM that lacks one of them

- **A profile does not exist here (verified).** Neither `swtpm` 0.7.1 nor libtpms 0.9.2 has one:
  ```
  $ swtpm socket --tpm2 --print-capabilities
  { "type": "swtpm", "features": [ "tpm-1.2", "tpm-2.0", "tpm-send-command-header", "flags-opt-startup", "cmdarg-seccomp", "cmdarg-key-fd", "cmdarg-pwd-fd", "cmdarg-print-states", "nvram-backend-dir", "nvram-backend-file", "rsa-keysize-1024", "rsa-keysize-2048", "rsa-keysize-3072" ], "version": "0.7.1" }
  $ swtpm_setup --help | grep -i -E "profile|algorithms"      # no output
  $ swtpm socket --help | grep -i profile
                 : Choose the action of the seccomp profile when a      # the seccomp profile, not a TPM profile
  $ nm -D /usr/lib/x86_64-linux-gnu/libtpms.so.0 | grep -i profile      # no output; no TPMLIB_SetProfile
  ```
  So there is no `swtpm`/libtpms profile that disables an algorithm, and `swtpm` implements every scheme, hash and
  curve of the spec (its curve list is `0001 0002 0003 0004 0005 0010 0011 0020`). Nothing real can be removed.
- **The replacement (built): `custodio_it::tpm_filter::TpmFilter`** (`crates/custodio-it/src/tpm_filter.rs`, std only, no
  `unsafe`, unit tests in the file, integration tests in `tests/tpm_filter.rs`). It sits on a unix socket in front of
  the `swtpm` socket, speaks the bare TPM framing of the `swtpm` TCTI on both sides, passes `<path>.ctrl` through,
  and changes what the client sees: `GetCapability` for algorithms and curves loses the lacking entries;
  `TestParms` with a lacking type, symmetric, scheme, hash or curve, and `Sign` / `RSA_Decrypt` with a lacking scheme
  or hash, get the format-one response code of the spec (`TPM_RC_TYPE`, `TPM_RC_SCHEME`, `TPM_RC_HASH`,
  `TPM_RC_CURVE`, parameter 1, or 2 for `Sign`). F108 onward reuse it: `TpmFilter::start(upstream_socket,
  filter_socket, Lacks { algorithms, curves })` and `filter.tcti()`.
- **It fails one capability while plain `swtpm` passes (verified):**
  ```
plain swtpm:
  TestParms rsa2048 RSAPSS SHA-256: supported
  Sign RSAPSS SHA-256: served
through the filter (lacks RSAPSS 0x0016):
  GetCapability(ALGS): RSAPSS absent, RSASSA present
  TestParms rsa2048 RSAPSS SHA-256: TSS Layer: TPM, Code: 0x000001D2, Message: Unsupported or incompatible scheme (assoc. with parameter number 1).
  TestParms rsa2048 RSASSA SHA-256: supported
  Sign RSAPSS SHA-256: TSS Layer: TPM, Code: 0x000002D2, Message: Unsupported or incompatible scheme (assoc. with parameter number 2).
  Sign RSASSA SHA-256: served
  TestParms rsa2048 RSASSA SHA-384: supported
  TestParms ecc_p256 ECDSA SHA-256: supported
through the filter (lacks SHA-384 0x000c and curve P-256 0x0003):
  GetCapability(ALGS): SHA-384 absent, SHA-256 present; GetCapability(ECC_CURVES): P-256 absent
  TestParms rsa2048 RSASSA SHA-384: TSS Layer: TPM, Code: 0x000001C3, Message: Hash algorithm not supported or not appropriate (assoc. with parameter number 1).
  TestParms rsa2048 RSASSA SHA-256: supported
  TestParms ecc_p256 ECDSA SHA-256: TSS Layer: TPM, Code: 0x000001E6, Message: Curve not supported (assoc. with parameter number 1).
  GetCapability(ECC_CURVES): [0001, 0002, 0003, 0004, 0005, 0010, 0011, 0020]
  TestParms rsa2048 RSASSA SM3_256: TSS Layer: TPM, Code: 0x000001C3, Message: Hash algorithm not supported or not appropriate (assoc. with parameter number 1).
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.62s
  ```
  The first block is a partial lack: the TPM lacks `RSAPSS` and keeps `RSASSA`, so `CKM_RSA_PKCS_PSS` is lost under
  (a) and nothing else. The hash code `0x1C3` is also what the real `swtpm` answers for SM3_256, which it does not
  implement (last two lines), so at least that code is measured, not only specified.
- **What it cannot simulate.** It only rewrites the answers to the commands above. It does not make `Create`,
  `Load`, `Import` or `CreatePrimary` refuse (they reach the real TPM), so a TPM that accepts a query and then fails an
  import is not simulated (that is the "TPM error during import" case of SPEC section 2, which is not "lacks" and
  needs a different fault). The scheme and curve response codes come from the TPM 2.0 Part 2 table
  and are **inferred**: `swtpm` implements every scheme and curve, so there is no real answer to compare with (only the
  hash code is measured). A hardware TPM may answer a different code for the same lack, or lack by returning
  `TPM_RC_COMMAND_CODE`. It does not model hardware timing, the salt a hardware TPM produces, or `GetCapability`
  paging (`moreData` is passed through).

### Partial lack: recommendation

SPEC section 4: "If a mechanism cannot be served by the TPM for a key type on a given TPM, that key type on that TPM
falls under 'lacks a capability' and is stored encrypted, TPM-bound. A mechanism is never silently dropped or
changed for a TPM key." The open question asks whether a key whose TPM lacks one mechanism should go to the TPM and lose it.

**Recommendation: keep the SPEC answer. The key type goes encrypted, TPM-bound, and `custodio import` says why.**
Reasons: (1) a TPM key that silently refuses `CKM_RSA_PKCS_PSS` with salt 20 gives a different error than the
encrypted kind for the same call, which is "dropped or changed for a TPM key"; (2) the person importing cannot know
which client will need which mechanism, and a key that works in Firefox but fails in LibreOffice is the worst
outcome of the two; (3) with way (b) the question mostly disappears for RSA: the list of what an RSA key needs
from the TPM is one algorithm, one size, the null scheme, the name hash and one command, with no per-mechanism
item, so a TPM either has all of it or lacks the key type, and a missing `RSAPSS` or SHA-384 changes nothing (the
first block of the filter run shows `RSAPSS` lacking while the capabilities in the (b) table are untouched;
that the raw operation then still works on that TPM is **inferred**, the filter run did not do a null-scheme
decrypt). A person who prefers TPM-with-loss would need an explicit, visible per-kind opt-in, which is the
administrator override SPEC already defers to M5; no departure from SPEC is needed for M4.

### Departures and points for the person in F111

- Way (b) puts the `decrypt` attribute on every TPM RSA key: SPEC's "no more usages than those" resolves to "includes
  `decrypt`". The "Not guaranteed" list of the threat model should say that root can also decrypt with a TPM RSA key.
- Under (b) the service must verify each signature with the public key before returning it (cheap), because the
  TPM returns a bare private-key exponentiation and a fault would otherwise leave the service as a signature.
- Under (b) the salt is drawn by the service (`TPM2_GetRandom` returns 64 bytes at most per call, as the first probe
  run showed) or by its own RNG; and the service's `CKM_RSA_PKCS_PSS` bound checks (data length, salt length)
  stay as they are, which is what gives "the same bounds and the same errors".
- Run the same probe on the hardware TPM: the `salt_found` lines (relevant only to (a)), the `capability:` lines, and
  whether `decrypt` plus `sign` is accepted on an unrestricted RSA key.

### The probe is read-only, and its exit codes (verified)

```
$ just with-swtpm bash -c 'listings; tpm-probe mechanisms; listings'     # one TPM, listings before and after
probe exit=0
listings identical
$ tpm2_getcap handles-persistent
$ tpm2_getcap handles-nv-index
TPM2_PT_HR_NV_INDEX: 0x0
TPM2_PT_HR_PERSISTENT: 0x0
TPM2_PT_HR_PERSISTENT_AVAIL: 0x41
TPM2_PT_NV_COUNTERS: 0x0
TPM2_PT_NV_COUNTERS_AVAIL: 0x19
$ tpm-probe bogus                                      ->  usage, exit 2
$ tpm-probe mechanisms --tcti swtpm:path=/nonexistent  ->  "tpm-probe: cannot connect to the TPM: ... IO failure.", exit 1
$ tpm-probe mechanisms --tcti notatcti                 ->  "tpm-probe: malformed --tcti", exit 1
```

The probe creates transient keys and flushes them; it calls no `EvictControl`, sets no auth value and does not clear.

### Decision

Way (a) loses `CKM_RSA_PKCS` with a payload that is not a `DigestInfo` and every `CKM_RSA_PKCS_PSS` salt length but
the hash length, so every RSA key would "lack" by SPEC section 4 or be served with fewer mechanisms than the
encrypted kind. Way (b) serves every mechanism, with bytes equal to (a) where (a) serves, for the cost of the
`decrypt` attribute, which adds use of the key that SPEC already leaves out of scope for root. ECC keys use
`TPM2_Sign` with the truncated digest and need SHA-256 only. Recommended for approval:

Decision: (b)

## F108

Question (SPEC open question "How `swtpm` reaches the end-to-end containers"): how does a TPM reach the privileged systemd containers
of `just e2e`? Everything below was run on 2026-11-03 in the `debian13` target (`e2e/targets/debian13/Containerfile`, image built with the
dev container's rootless podman, vfs driver), started as `e2e/run.sh` starts it (`podman run -d --privileged --cgroupns=host --tmpfs /run
--tmpfs /run/lock --tmpfs /tmp`, plus `-v target/packages:/pkg:ro`). Verified unless marked *inferred*.

### The container
- `podman exec f108 systemctl is-system-running` → `degraded`. The failed units are only `sys-kernel-config.mount`, `sys-kernel-debug.mount`,
  `sys-kernel-tracing.mount` and `systemd-modules-load.service` (there is no `/lib/modules` in the container or the dev container). Nothing
  TPM-related fails.
- Packages added at run time, from Debian trixie: `swtpm` 0.7.1-1.5, `swtpm-tools` 0.7.1-1.5, `tpm2-tools` 5.7-1, plus the real
  `custodio_0.1.0-1_amd64.deb` from `target/packages` (`apt-get install /pkg/custodio_0.1.0-1_amd64.deb`: exit 0). F109 adds the three TPM
  packages to the Containerfile (not done here); `strace` was installed only to debug.

### Route 1: `swtpm` with the kernel's vTPM proxy (`/dev/vtpmx`, host module `tpm_vtpm_proxy`): does not work here, needs a host change
Dev container (uid 1000, kernel 7.0.0-42-generic) and container give the same result:
```
$ ls -l /dev/vtpmx /dev/tpm*                 -> No such file or directory (both)
$ grep -c vtpm /proc/modules /proc/misc      -> 0 and 0
$ ls /lib/modules                            -> No such file or directory
$ ls /sys/module | grep -i tpm               -> tpm  tpm_crb  tpm_tis  tpm_tis_core      (no tpm_vtpm_proxy)
$ modprobe tpm_vtpm_proxy                    -> modprobe: not found   (container); `sudo -n` gives no root (dev container)
$ swtpm chardev --vtpm-proxy --tpm2 --tpmstate dir=/tmp --ctrl type=unixio,path=/tmp/x.ctrl
swtpm: Could not open /dev/vtpmx: No such file or directory
```
So there is no `/dev/tpmrm0` in the container by this route. The smallest host change (*inferred*: it needs root on the host, so it was not
run) is to load `tpm_vtpm_proxy` on the host (`modprobe tpm_vtpm_proxy`, persistent through `/etc/modules-load.d/`) and pass `/dev/vtpmx` into
the dev container (`--device /dev/vtpmx`); the `/dev/tpm<N>` and `/dev/tpmrm<N>` nodes that `swtpm chardev --vtpm-proxy` makes appear in the
host's devtmpfs, and would need a `mknod` in the nested container. Whether the host kernel ships the module is also unknown. A person must do
it. Since route 2 works, no `BLOCKED.md` is written: nothing the project needs waits for it. What route 2 does not exercise is a real
`/dev/tpmrm0` (the `tss` group, `DeviceAllow`, `PrivateDevices`): that is the per-target device question of F109 and the hardware run of F111.

### Route 2: the service reaches `swtpm`'s unix socket through a test-only drop-in: works
**A fact that shapes it: a host AppArmor profile confines `swtpm` inside the container.** `cat /proc/$(pgrep -x swtpm)/attr/current` →
`swtpm (enforce)`, although the container has no `/etc/apparmor.d/usr.bin.swtpm`: profiles belong to the host kernel and attach by path.
Measured effects: `swtpm` can create its socket and state only under `/tmp` and `/var/tmp` (`bind(... "/run/s.sock") = -1 EACCES`;
`swtpm: Could not open UnixIO socket: Permission denied` for `/run`, `/run/lock`, `/dev/shm`, `/var/lib/...`; `Could not open lockfile:
Permission denied` for a state directory under `/var/lib`), and `kill -9 <swtpm pid>` as root in the container gives `Permission denied`
(stop it with `swtpm_ioctl --unix <sock>.ctrl -s`, as F104 and F105 do). `swtpm_setup` works with the state in `/var/tmp`. On a host without the
profile the paths are free (*inferred*); the recipe below works on both. The unit has `PrivateTmp=yes`, so the socket directory is
bind-mounted into the unit.

Setup (state in `/var/tmp/f108-state`, socket directory `/tmp/f108-tpm`, TCTI `swtpm:path=/tmp/f108-tpm/swtpm.sock`; the TCTI also opens
`<path>.ctrl`, which must sit next to it and be reachable by the unit's dynamic user, hence `mode=0666` on both sockets, test only):
```
swtpm_setup --tpm2 --tpmstate /var/tmp/f108-state --createek --not-overwrite
swtpm socket --tpm2 --tpmstate dir=/var/tmp/f108-state --server type=unixio,path=/tmp/f108-tpm/swtpm.sock,mode=0666 \
     --ctrl type=unixio,path=/tmp/f108-tpm/swtpm.sock.ctrl,mode=0666 --flags not-need-init,startup-clear --daemon
```
The drop-in, `/run/systemd/system/custodio.service.d/f108-test-tpm.conf` (tmpfs, owned by no package, gone at reboot), on the **real shipped
`custodio.service` of the installed package** (`/usr/lib/systemd/system/custodio.service`, with every sandbox line):
```
[Service]
Type=oneshot
ExecStart=
ExecStart=/bin/sh /tmp/f108-tpm/cmd.sh
Environment=TPM2TOOLS_TCTI=swtpm:path=/tmp/f108-tpm/swtpm.sock
BindReadOnlyPaths=/tmp/f108-tpm
```
(`ExecStart` is replaced by a stand-in command here only because the service has no TPM code yet; F109 onward leave `ExecStart` alone and set
`Environment=` and `BindReadOnlyPaths=` only, with whatever variable the service's TPM code reads for its TCTI. `tss-esapi` accepts
`swtpm:path=<socket>` since 8.0 alpha, F105.) A case writes the command to `cmd.sh`, runs `systemctl start custodio.service` and reads
`journalctl -u custodio.service --since @$t -o cat`. The unit running `id -un; ls /tmp; touch /etc/f108; tpm2_getcap algorithms | grep -c
'^[a-z0-9_-]*:$'` printed:
```
custodio                                   <- the DynamicUser
tmp: f108-tpm                              <- PrivateTmp: only the bound directory
touch: cannot touch '/etc/f108': Read-only file system     <- ProtectSystem=strict
33                                         <- algorithms, through the TCTI, from inside the sandbox
$ systemctl show -p PrivateTmp -p ProtectSystem -p PrivateDevices -p RestrictAddressFamilies -p DynamicUser custodio.service
DynamicUser=yes  PrivateTmp=yes  PrivateDevices=yes  ProtectSystem=strict  RestrictAddressFamilies=AF_UNIX
```
So the socket gets through the shipped sandbox (`PrivateTmp`, `ProtectSystem=strict`, `PrivateDevices`, `RestrictAddressFamilies=AF_UNIX`,
`PrivateUsers`, `SystemCallFilter`, `MemoryDenyWriteExecute`) in one step. A unix socket is the only way: `AF_UNIX` and `IPAddressDeny=any`
forbid TCP.

### Cases (route 2), each run in the container
- **A TPM**: `swtpm` started as above; `tpm2_getcap algorithms | grep -c '^[a-z0-9_-]*:$'` → `33` from the shell and from the unit.
- **No TPM**: the case does not start `swtpm` (or stops it with `swtpm_ioctl --unix $SOCK.ctrl -s`) and leaves the drop-in's TCTI in place:
  that is what the service sees on a machine whose TPM is gone, and it is the "a TPM" setup minus one step. In the shell and in the unit:
  ```
  WARNING:tcti:src/util-io/io.c:304:socket_connect_unix() Failed to connect to /tmp/f108-tpm/swtpm.sock
  ERROR:tcti:src/tss2-tcti/tcti-swtpm.c:617:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM socket
  ERROR:tcti:src/tss2-tcti/tctildr-dl.c:149:tcti_from_file() Could not initialize TCTI file: swtpm      (tool exit 1)
  ```
  The other form, TCTI unset (`env -u TPM2TOOLS_TCTI tpm2_getcap algorithms`), makes the tools try the devices: `Failed to open specified
  TCTI device file /dev/tpmrm0: No such file or directory`, then the same for `/dev/tpm0`. That is the message of a machine with no TPM and
  no drop-in; the e2e cases use the first form because it is what they set up.
- **A TPM lacking a capability**: `custodio_it::tpm_filter::TpmFilter` (F107) is a library with no command line and F108 changes no code, so
  the run used a scratch wrapper outside the repository (`/tmp/f108-filter`: a `main` calling `TpmFilter::start(upstream, listen,
  Lacks { algorithms, curves })` over a copy of `tpm_filter.rs`, built in the dev container and copied into the container, same glibc 2.41).
  F109 turns it into an example of `custodio-it` that the container mounts; its arguments are the upstream socket, the socket to listen
  on and the lacking identifiers. The case points the drop-in's TCTI at the filter's socket (also in `/tmp/f108-tpm`). With `RSAPSS`
  (0x0016) lacking:
  ```
  plain swtpm:    tpm2_testparms rsa2048:rsapss:null   -> exit 0
  through filter: tpm2_testparms rsa2048:rsapss:null   -> ERROR: Esys_TestParms(0x1D2) ... Specified signing scheme is unsupported (exit 5)
  through filter: tpm2_testparms rsa2048:rsassa:null   -> exit 0
  tpm2_getcap algorithms | grep -c '^rsapss:'          -> 0 through the filter, 1 on plain swtpm
  ```
  `0x1D2` is `TPM_RC_SCHEME` with parameter 1, the code the filter answers (F107).
- **`tpm2-tools` reach the same TPM**: `TPM2TOOLS_TCTI=swtpm:path=/tmp/f108-tpm/swtpm.sock`, the same string as the service's. `swtpm` serves
  one client at a time (F105) and there is no `tpm2-abrmd` here, so the tools and the service **take turns**: a case runs a tool, which exits
  and closes its connection, and then starts the service (or a second process in its unit), never both at once. Shown: `tpm2_pcrread
  sha256:16` (all zeros) → `tpm2_pcrextend 16:sha256=76646072...b802` (SHA-256 of `f108`) → shell readback
  `0x3660EFA29138AD913029D0F539BA21F3B38D9638F5F7CA17CD6B99900A5EA9A4`, equal to `SHA-256(32 zero bytes || digest)` computed in advance with
  `python3 hashlib` → the unit (a second process, over the same socket) reads `16: 0x3660EFA2...A9A4`, non-zero and identical.
- **Extend, restart, clear.** Expectation stated before the run: after `swtpm` is stopped and started again the PCR is **zero** (a start does
  `Startup(CLEAR)`, which resets the PCRs), so a PCR cannot show persistence; an object under the owner hierarchy can. So before the restart
  the case persists one: `tpm2_createprimary -C o -G ecc -g sha256 -c p.ctx; tpm2_evictcontrol -C o -c p.ctx 0x81000f08; tpm2_flushcontext -t`
  (`0x81010001` and `0x81010016` are made by `swtpm_setup`; use another handle). `tpm2_readpublic -c 0x81000f08` name:
  `000bee4114329a98ceb6bfaf880de335f67a2f06f23b9feba89dd741ad3992cc406b`. Restart = `swtpm_ioctl --unix $SOCK.ctrl -s`, wait until
  `pgrep -x swtpm` prints nothing, start the same `swtpm socket` command on the same `--tpmstate` (F106 did the same through `swtpm_ioctl -i`
  plus `tpm2_startup -c`; not repeated). After: PCR 16 is `0x00...00` (as expected), `tpm2_getcap handles-persistent` still lists
  `0x81000F08`, and the name is byte-identical (`cmp` ok): the state, hence the owner seed, survived. Clear: `tpm2_clear` (exit 0) →
  `handles-persistent` lists nothing, `tpm2_readpublic -c 0x81000f08` fails (`ErrorCode (0x0000018b)`), and a fresh `createprimary -C o` has a
  different name from before (the owner seed changed, as F105 measured). With `swtpm` stopped the unit gives the "No TPM" message above.

### The shipped unit carries no test drop-in
The drop-in lives in `/run/systemd/system/custodio.service.d/`, a directory no package owns (`dpkg -S` → `no path found matching pattern`),
and the run removes it (`rm -rf` of that directory, `systemctl daemon-reload`). With the real package (`Package: custodio Version: 0.1.0-1`)
installed:
```
with the drop-in (negative control):
  systemctl show -p DropInPaths --value custodio.service  -> /run/systemd/system/custodio.service.d/f108-test-tpm.conf
  systemctl cat custodio.service | grep -c '^# /run/systemd/system/custodio.service.d/f108-test-tpm.conf'  -> 1
removed (what a run checks before the real cases and after):
  systemctl show -p DropInPaths --value custodio.service  -> (empty)
  systemctl show -p Environment --value custodio.service  -> (empty)
  systemctl cat custodio.service | grep -c '^# /'          -> 1   (only /usr/lib/systemd/system/custodio.service)
  find / -xdev -name custodio.service.d | wc -l             -> 0
the package, not the unit:
  dpkg -L custodio | grep -c custodio.service.d            -> 0      (dpkg -L custodio | grep -c 'custodio.service$' -> 1)
```
The file-list half is closed for the deb on debian13, with the real package. F109 onward run the same checks on each target with the target's
listing (`rpm -ql custodio`, `pacman -Ql custodio`): `... | grep -c custodio.service.d` must print 0, and `DropInPaths` must be empty in every
case that is not a TPM case. A TPM case installs the drop-in in its setup and removes it in its cleanup (a trap).

### What may differ on the other targets (*inferred*, not run) and the F109 check each implies
- ubuntu2404 / ubuntu2604: same AppArmor mechanism as the host here. Check: `cat /proc/$(pgrep -x swtpm)/attr/current`, and that `swtpm socket`
  on `/tmp/f108-tpm` exits 0.
- fedora44 / alma10: SELinux may confine `swtpm` (type `swtpm_t`) to its own directories and deny `/tmp`, and the service's domain
  (F62) must be allowed to connect to the socket. Check: `getenforce`; the `swtpm socket` command exits 0 on `/tmp/f108-tpm`; `tpm2_getcap`
  in the unit succeeds under enforcing. If not, the target uses the path its policy allows and the bind mount follows.
- arch: no mandatory access control by default. Check that `swtpm`, `swtpm-tools`'s equivalent and `tpm2-tools` install under those names and
  that `swtpm_ioctl` exists (the stop command relies on it).
- Every target: the count of algorithms is `swtpm`'s, not the OS's: compare it to non-zero rather than to 33.

Decision: route 2. The end-to-end containers get a TPM from `swtpm` on a unix socket under `/tmp` (state under `/var/tmp`), reached by `tpm2-tools` and by the
service through a TCTI string (`swtpm:path=...`) set in a test-only drop-in in `/run/systemd/system/custodio.service.d/` with `BindReadOnlyPaths=` for the socket directory,
removed by the run and checked absent from the shipped unit and package; "no TPM" is the socket absent, "lacking" is the F107 `TpmFilter`'s socket. Route 1 (`/dev/vtpmx`, a real `/dev/tpmrm0`) needs the host to load `tpm_vtpm_proxy` and a person to pass the device in: not needed now.

## F109

Question (SPEC open question "How the service reaches the TPM under its unit"): with `PrivateDevices=yes`, `PrivateUsers=yes` and a static
`custodio` user, what lets the service open the kernel resource manager `/dev/tpmrm0`, and does the unit still meet the `just security-score`
threshold? Only `/dev/tpmrm0` is considered; the raw TPM node is never opened, granted or named in a candidate. Run on 2026-11-03 in the six
e2e containers, built from the unchanged `e2e/targets/<t>/Containerfile` and started as `e2e/run.sh` does (`podman run -d --privileged
--cgroupns=host --tmpfs /run --tmpfs /run/lock --tmpfs /tmp`, rootless podman, vfs) plus `--device /dev/null:/dev/tpmrm0` (stand-in a). Every
candidate is a real unit file started by the container's own systemd (PID 1, state `degraded` on all six as in F108): the shipped
`data/custodio.service` text, `Type=dbus`/`BusName=` removed, `ExecStart=` swapped for a probe script (`id`, `/proc/self/*_map`, `ls /dev`, `ls -ln`
and an open for read/write of the nodes), output to `StandardOutput=append:`. The scratch scripts (not committed) are the only thing the
experiment needed. Verified unless marked *inferred*.

### What the containers can and cannot show
```
$ ls /dev/tpm* /dev/vtpmx /dev/fuse /dev/net/tun /dev/kvm   -> No such file or directory (all five)
$ ls -A /sys/class/tpmrm | wc -l                            -> 0   (the class directory exists, it has no device)
$ podman run --rm --privileged debian:trixie sh -c 'mknod /dev/tpmrm0 c 252 0'   (252: a placeholder major)
mknod: /dev/tpmrm0: Operation not permitted            uid_map: 0 1000 1 / 1 1 999 / 1000 1001 64535
$ podman run --rm --device /dev/null:/dev/tpmrm0 debian:trixie sh -c 'ls -l /dev/tpmrm0; chgrp 1 /dev/tpmrm0; chmod 600 /dev/tpmrm0'
crw-rw-rw- 1 nobody nogroup 1, 3 /dev/tpmrm0 ; chgrp: Operation not permitted ; chmod: Operation not permitted
```
So no real TPM node exists here (F108 route 2 gives `swtpm` on a socket, no device node) and a character device owned `root:tss 0660` cannot be made.
The stand-in is split in two. (a) `/dev/null` passed in as `/dev/tpmrm0` (mode 0666, owner nobody): only for what `PrivateDevices`, `BindPaths=`
and `DevicePolicy=closed` do to a node. (b) a regular file `root:tss 0660` at `/run/f109-tpmrm0` (outside what `ProtectSystem=strict` hides),
only for the group check. That the kernel checks a device inode's owner, group and mode as it does a regular file's is *inferred*.
Dev container: `systemd-analyze` 257.13, `just security-score` threshold `"10"` (justfile line 190, unchanged), shipped unit: `Overall exposure level
for custodio.service: 0.6 SAFE`.

### The `tss` group and the owner of `/dev/tpmrm0`
`getent group tss` before and after installing the package that owns the rules (`apt-get install tpm-udev`, `dnf install tpm2-tss`, `pacman -S tpm2-tss`):

| target | systemd | `tss` before | `tss` after | package with the rules | rule for `tpmrm[0-9]*` (`60-tpm-udev.rules`) | resulting node |
|---|---|---|---|---|---|---|
| debian13 | 257 | absent | `tss:x:101` | `tpm-udev` (creates user and group) | `MODE="0660", OWNER="tss", GROUP="tss"` | `tss:tss 0660` |
| ubuntu2404 | 255 | absent | `tss:x:102` | `tpm-udev` | `MODE="0660", OWNER="tss", GROUP="tss"` | `tss:tss 0660` |
| ubuntu2604 | 259 | absent | `tss:x:993` | `tpm-udev` | `MODE="0660", OWNER="tss", GROUP="tss"` | `tss:tss 0660` |
| fedora44 | 259 | `tss:x:59` | same (`Nothing to do`) | `tpm2-tss` 4.1.3 | `MODE="0660", GROUP="tss"` | `root:tss 0660` |
| alma10 | 257 | `tss:x:59` | same | `tpm2-tss` 4.1.3 | `MODE="0660", GROUP="tss"` | `root:tss 0660` |
| arch | 262 | `tss:x:971` | same | `tpm2-tss` 4.2.0 | `MODE="0660", GROUP="tss"` | `root:tss 0660` |

The rules file also says `tpm devices can only be accessed by the tss user but the tss group members can access tpmrm devices`. On the
Debian family the group does not exist until `tpm-udev` is installed (ubuntu2604's postinst printed `udevadm: not found`, harmless in a
container); on the others it is already there (`tpm2-tss` is a dependency of systemd's TPM support). The group name is `tss` on all six; its gid
differs (59 on the RPM family, dynamic elsewhere), so a unit must name it, never a number. A unit that names a missing group does not start:
```
SupplementaryGroups=nogrp_f109 (and -nogrp_f109) on debian13 (systemd 257) and arch (262):
  Failed to determine supplementary groups: No such process / Failed at step GROUP -> status 216; the "-" prefix does not help
```
So the package must depend on what creates `tss` (`tpm-udev` on the Debian family, `tpm2-tss` on RPM and Arch) or create the group itself with
sysusers `g tss -` (*inferred*: not run; whether Debian's `tpm-udev` postinst tolerates an existing group is unknown).

### The candidates and what each does
The unit runs as the **static** `custodio` user (`systemd-sysusers data/sysusers.d/custodio.conf` creates it: uid 988/992/992/996/998/968 on
the six; `id` in the sandbox shows that uid, not a dynamic one: `DynamicUser=yes` reuses it). Candidates, each the shipped text plus:
- **A** nothing (shipped: `PrivateDevices=yes`).
- **B** `BindPaths=/dev/tpmrm0`.
- **C** `PrivateDevices=no`, `DevicePolicy=closed`, `DeviceAllow=/dev/tpmrm0 rw`. **C0** is C without the `DeviceAllow=` line (control).
- **D** `DeviceAllow=/dev/tpmrm0 rw` and `BindPaths=/dev/tpmrm0`, `PrivateDevices=yes` kept. **DE** is D with `BindPaths=-/dev/tpmrm0`.
- a `g` suffix adds `SupplementaryGroups=tss`. None names the raw TPM node; `NoNewPrivileges`, the empty `CapabilityBoundingSet=`,
  `ProtectSystem`, `RestrictAddressFamilies` and `SystemCallFilter` are untouched.

`systemctl show -p PrivateDevices,PrivateUsers,DevicePolicy,DeviceAllow,SupplementaryGroups,User,DynamicUser` (the same on all six):
```
A   DevicePolicy=closed DeviceAllow=char-rtc r                                User=custodio DynamicUser=yes SupplementaryGroups=    PrivateDevices=yes PrivateUsers=yes
Dg  DevicePolicy=closed DeviceAllow=char-rtc r DeviceAllow=/dev/tpmrm0 rw     User=custodio DynamicUser=yes SupplementaryGroups=tss PrivateDevices=yes PrivateUsers=yes
Cg  DevicePolicy=closed DeviceAllow=char-rtc r DeviceAllow=/dev/tpmrm0 rw     ... SupplementaryGroups=tss PrivateDevices=no PrivateUsers=yes
C0  DevicePolicy=closed DeviceAllow=char-rtc r                                ... SupplementaryGroups=    PrivateDevices=no PrivateUsers=yes   (the line is gone)
```
**`PrivateDevices=yes` hides the node.** Unit A, `ls /dev` → `char core fd full hugepages log mqueue null ptmx pts random shm stderr stdin stdout tty urandom
zero` (no `tpmrm0`), `open rw /dev/tpmrm0: ENOENT (not visible)`, on all six. Unit C (`PrivateDevices=no`), the same stand-in: listed, `open rw: ok`
(the negative control of the test), also on all six.
**`BindPaths=` brings it back under `PrivateDevices=yes`.** Unit B: `crw-rw-rw- 1 65534 65534 1, 3 /dev/tpmrm0` listed, open ok, on all six; D the same.
**`DeviceAllow=`: not verified, inferred.** `/dev/null` is on the `DevicePolicy=closed` default list, so C opening it shows only visibility. The control
C0 (no `DeviceAllow=/dev/tpmrm0`) **still opens** it on all six targets (`open rw /dev/tpmrm0: ok`), so the rootless nested container cannot tell
whether the device filter admits the node: the effect of `DeviceAllow=/dev/tpmrm0 rw` is *inferred* and goes to F147. Why it is needed anyway
(*inferred*, from systemd's documentation): `PrivateDevices=yes` implies `DevicePolicy=closed` with only the default list, and a bound real node
is not on it, so without `DeviceAllow=` the open of a real `tpmrm0` would get `EPERM`; B therefore probably works for the stand-in only.
**An absent node.** debian13 and fedora44, node removed (`rm /dev/tpmrm0` after `umount`), unit D (plain `BindPaths=`):
`Failed at step NAMESPACE spawning /bin/sh: No such file or directory`, status 226/NAMESPACE: on a machine without a TPM the service would not
start at all. Unit DEg (`BindPaths=-/dev/tpmrm0`): starts (`Result=success`), `/dev` has no `tpmrm0`, `open rw /dev/tpmrm0: ENOENT (not visible)`.
`DeviceAllow=/dev/tpmrm0` for a missing node is harmless (DEg starts). Both on the two targets only; the others share the same systemd 257/259
code paths (*inferred*; on the other four the node was still present in the same test and DEg opened it: ok on all six).
(`BindPaths=-` is `BindPaths=-/dev/tpmrm0:/dev/tpmrm0:rbind` in `systemctl show`.)

### Group access under `PrivateUsers=yes` with the static `custodio` user
Inside the sandbox of every candidate: `uid_map  0 0 1; <uid> <uid> 1;` and the same `gid_map`, i.e. only root and the service's own uid/gid are
mapped. Unit Dg on debian13, file (b) `root:tss 0660`:
```
id: uid=988(custodio) gid=988(custodio) groups=988(custodio),65534(nogroup)       Groups: 65534 988
ls -ln /run/f109-tpmrm0: -rw-rw---- 1 0 65534 0 /run/f109-tpmrm0                  (gid 101 shown as 65534: unmapped)
open rw /run/f109-tpmrm0: ok
```
Without `SupplementaryGroups=tss` (units A, B, C, D): `groups=988(custodio)` only and `open rw /run/f109-tpmrm0: Permission denied` (negative control).
With it (Ag, Bg, Cg, Dg, DEg): `ok`. Identical on all six targets (the unmapped group is `nogroup` on the Debian family, `nobody` elsewhere;
ubuntu2604, arch list the gids in another order). Units with `SupplementaryGroups=tss` under `PrivateUsers=yes` **start** on all six:
`Result=success`, `ExecMainStatus=0`; the kernel still honours the supplementary group although the user namespace cannot name it. No candidate needed
`PrivateUsers=no`.

### Exposure
`systemd-analyze security --offline=yes --no-pager --threshold=10 <unit>`, exit status 0 for every candidate on every target (each target's own
`systemd-analyze`: 255, 257, 257, 259, 259, 262) and on the dev container's 257.13 (what `just system-gates` uses):

| candidate | 0.x on every target and the dev container | lines that cost points |
|---|---|---|
| shipped / A | 0.6 | RootDirectory, RestrictAddressFamilies, PrivateNetwork (0.5), DeviceAllow `char-rtc` |
| B | 0.6 | as A |
| D, DE | 0.6 | as A, `DeviceAllow=` shows `/dev/tpmrm0:rw` in the same 0.1 |
| Ag, Bg, Dg, DEg | 0.7 | as above plus `SupplementaryGroups=` 0.1 |
| C, C0, Cg, C0g | 0.8 | above plus `PrivateDevices=` 0.2 |

All are SAFE and under the threshold of 10 (1.0); the margin of the chosen one is 0.3. The bare-unit check of `just security-score` is untouched.

### Left to the hardware acceptance (F147)
Not shown by containers, each a command F147 runs on the machine with a real TPM (`dmesg | grep -i tpm` first):
- the driver (`tpm_crb` or `tpm_tis`) creates the node and udev applies the rules: `cat /sys/class/tpmrm/tpmrm0/dev` (a tpmrm major, not misc
  10:224, which is the raw node), `ls -ln /dev/tpmrm0` equals `tss:tss` or `root:tss`, `0660`, `udevadm info /dev/tpmrm0`.
- the device filter admits `DeviceAllow=/dev/tpmrm0 rw` for the real node and refuses without it: the open in the sandbox of DEg succeeds, and in
  DEg minus the `DeviceAllow=` line fails `EPERM` (the control that rootless containers could not give).
- group access to the real node under `PrivateUsers=yes`: `systemd-run --wait --pipe -p User=custodio -p DynamicUser=yes -p PrivateUsers=yes
  -p PrivateDevices=yes -p DeviceAllow='/dev/tpmrm0 rw' -p BindPaths=-/dev/tpmrm0 -p SupplementaryGroups=tss tpm2_getcap algorithms`
  (the unit's final form) lists algorithms; without `SupplementaryGroups=tss` it fails `EACCES`.
- the shipped `custodio.service` with the Decision's lines starts and `tpm2_getcap` through it works; and with the node absent (TPM disabled in
  firmware) it still starts.
- SELinux (fedora44, alma10): the domain of F62 may open `tpmrm_device_t`; not checked here.

Decision: the unit keeps `PrivateDevices=yes` and `PrivateUsers=yes` and gets exactly these directives (unit DEg), next to the existing `PrivateDevices=yes`:
```
PrivateDevices=yes
DeviceAllow=/dev/tpmrm0 rw
BindPaths=-/dev/tpmrm0
SupplementaryGroups=tss
```
Why: `BindPaths=` brings the node back through `PrivateDevices=yes`; the `-` keeps the service startable without a TPM (plain `BindPaths=` fails 226/NAMESPACE);
`DeviceAllow=` is what the device filter needs for a real node (inferred, F147); `SupplementaryGroups=tss` is what gives the static `custodio` user
the group of `root:tss 0660` or `tss:tss 0660` under `PrivateUsers=yes` (verified on all six); score 0.7 against the threshold 1.0, no `PrivateDevices=no`
(0.8). The packages must depend on what creates `tss` (`tpm-udev`, `tpm2-tss`) or the sysusers file gains `g tss -`; no change to `sysusers.d`, `data/` or
the Containerfiles is made by this feature.

## F110

Question (SPEC open question "How the service uses `systemd-creds` without root"): from the service's uid, under its real unit, which scope and
which call of `systemd-creds` / the Varlink interface `io.systemd.Credentials` encrypt and decrypt, is a TPM binding available that way, does
"TPM-bound" mean the TPM alone or host plus TPM, how is the credential bound to no PCR whatever the version's default, how does the plaintext
reach the call without a temporary file, and which errors mean "credential service unavailable" and "cannot decrypt"? Run on 2026-11-03 in the six
e2e containers (images of F109, started as `e2e/run.sh` does: `podman run -d --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock --tmpfs /tmp`,
rootless podman, vfs; `strace`, `swtpm`, `swtpm-tools`, `tpm2-tools` added at run time), and in the dev container (systemd 257.13, uid 1000, no PID 1
systemd, no `strace`; `swtpm` 0.7.1, `tpm2-tools` 5.7, `ls /dev/tpm*` → none, `podman info` → rootless, `vfs`). The probe is a real unit started by the container's systemd: the shipped `data/custodio.service` text, `Type=dbus`/`BusName=`/`After=`/
`Requires=` removed, `Type=oneshot`, F109's `DeviceAllow=/dev/tpmrm0 rw`, `BindPaths=-/dev/tpmrm0`, `SupplementaryGroups=tss`, `ExecStart=` swapped for a shell
probe. It runs as the static `custodio` user (created with `systemd-sysusers`: uid 988/992/992/995/997/968 on debian13, ubuntu2404, ubuntu2604, fedora44,
alma10, arch; `uid_map` `0 0 1` / `<uid> <uid> 1`, `groups=<uid>,65534`): the whole sandbox is on (`PrivateUsers`, `PrivateTmp`, `ProtectSystem=strict`,
`RestrictAddressFamilies=AF_UNIX`, `SystemCallFilter`, empty capability set). The scratch scripts are outside the repository. Verified unless marked *inferred*.

### Versions and what exists
| target | `systemd-creds --version` | `--user`/`--uid=` | socket `/run/systemd/io.systemd.Credentials` (`systemd-creds.socket`, mode 0666) | `varlinkctl introspect` | `withKey` parameter |
|---|---|---|---|---|---|
| debian13 | 257.13 | yes | yes | `Encrypt`, `Decrypt`; errors `BadFormat NameMismatch TimeMismatch NoSuchUser BadScope` | no |
| ubuntu2404 | 255.4 | **no**: `systemd-creds: unrecognized option '--user'` | **no**: `Failed to open '/run/systemd/io.systemd.Credentials': No such file or directory`; no `systemd-creds.socket` unit | - | - |
| ubuntu2604 | 259.9 | yes | yes | as above plus `CantFindPCRSignature NullKeyNotAllowed KeyBelongsToOtherTPM TPMInDictionaryLockout UnexpectedPCRState NVIndexUnusable` | yes |
| fedora44 | 259.10 | yes | yes | as ubuntu2604 | yes |
| alma10 | 257-23 | yes | yes | as debian13 | no |
| arch | 262.1 | yes | yes | as ubuntu2604 | yes |
The SPEC's "v256 for both" holds: from the source (tags v255 to v259, read by a subagent; NEWS) v255 has neither, v256 adds `--user`, `--uid=`, the Varlink
interface and `systemd-creds.socket`, v259 adds `withKey` to `Encrypt` (NEWS v259). The "v257 or v258 for completeness" question: nothing in v257 or later is missing for
the `user` scope as used below; what v258 changes is the default PCR mask (below).

### Which scope and call work from the service's uid
All of this inside the probe unit, each target with `--user` (five of six). Output of debian13 (the other four: the same lines, byte counts differ):
```
[user encrypt --with-key=host]      rc=0   [user decrypt] rc=0 plaintext equal     header id 55b9ed1d38594d43a8319d2ebb332ac6 (host key, scoped)
[user encrypt --with-key=host+tpm2] rc=0   [user decrypt] rc=0 plaintext equal     same id (no TPM in reach: see "Key used")
[user encrypt --with-key=auto]      rc=0   [user decrypt] rc=0 plaintext equal     same id
[user encrypt --with-key=tpm2]      rc=1 Selected key not available in --uid= scoped mode, refusing.      (also --with-key=null)
[system encrypt] (no --user)        rc=1 Failed to encrypt: io.systemd.InteractiveAuthenticationRequired
[varlink Encrypt scope=user]        rc=0 {"blob":"VbntHThZ..."}      [varlink Decrypt scope=user] {"data":"<base64 of the marker>"}
[varlink Encrypt scope=system]      rc=1 io.systemd.InteractiveAuthenticationRequired
[varlink Encrypt scope=user uid=0]  rc=1 io.systemd.InteractiveAuthenticationRequired
```
- **`user` scope, own uid, works without polkit** by the CLI (`systemd-creds --user encrypt|decrypt --name=NAME - -`) and by a direct Varlink call
  (`Encrypt {"name","text"|"data","scope":"user"}` → `{"blob"}`; `Decrypt {"name","blob","scope":"user"}` → `{"data"}` base64). Both are the same daemon call.
  Same on debian13, ubuntu2604, fedora44, alma10, arch.
- **`system` scope, or another uid, needs polkit**: `io.systemd.InteractiveAuthenticationRequired` (actions `io.systemd.credentials.encrypt`/`.decrypt`, implicit
  `auth_admin_keep` for any/inactive/active, `pkaction -a ... -v` on debian13). The service must never use them (an authorization, even if a rule granted it, is not
  to be cached; and a polkit rule for the service uid is not a thing to add for this). The dev container, which has no bus, shows the same call as `io.systemd.System {"errno":2}` (the daemon's polkit connection fails).
- **The CLI as a non-root uid always goes through Varlink** (`systemd-creds [--user] encrypt` with no socket: `Failed to connect to io.systemd.Credentials: No such file or directory`,
  dev container, all five `--with-key` values). The unprivileged CLI never reads `/var/lib/systemd/credential.secret` itself.
- **Bound to uid (verified), user name and machine-id (the user name by the source: `NoSuchUser`; machine-id *inferred*: only the uid was changed).** A credential made by the service's uid
  decrypted by uid 65534 (`nobody`), CLI and Varlink, all five targets: `Bad credential format.` / `io.systemd.Credentials.BadFormat`. Asking for the other uid's scope
  (`scope=user, uid=<service uid>`, from uid 65534, or `uid=4242` from the service) goes to polkit: `InteractiveAuthenticationRequired`. The service can only encrypt/decrypt for its own uid.
- **The host secret is not readable by the service**: `cat /var/lib/systemd/credential.secret` → `Permission denied` (`-r-------- root root 4112`) in the sandbox, five targets;
  the root daemon (`systemd-creds@.service`, started by the socket) reads it. In `user` scope the secret is mixed in: replacing it (root, random 4096 bytes) makes decrypt fail, restoring it makes it work again:
  `decrypt as service uid after host secret replaced: rc=1 Failed to decrypt: io.systemd.System` / Varlink `io.systemd.System {"errno":2}` (257) or `No such file or directory {"origin":"linux","errno":2,"errnoName":"ENOENT"}` (259, 262), `after restore: rc=0 MARKER`.
- **ubuntu2404 (255) has neither `--user` nor Varlink.** A non-root uid: `--with-key=host` and `host+tpm2` → `Failed to determine local credential host secret: Permission denied`.
  `--with-key=tpm2 --tpm2-pcrs= --tpm2-device=swtpm:path=...` **works** as uid 992 against `swtpm` (see "Key used"), encrypt and decrypt rc=0 (run by `setpriv` as the service uid, not inside the unit's sandbox). So on 255 only a TPM-alone credential can be made without root, and none without a TPM.

### Key used: TPM alone or host plus TPM, and where the TPM is opened
The Varlink path has **no key choice before v259 and no TPM choice ever**: `vl_method_encrypt` passes `_CRED_AUTO_SCOPED` (user) or `_CRED_AUTO` to `encrypt_credential_and_warn`
(creds.c v257:1219; v258:1288; v259:1371 reads `withKey` if given). `auto` means host key plus TPM when the root daemon finds a usable TPM, else host key only; a scoped credential is never TPM-only
(creds-util.c v258:1010). The daemon opens the TPM itself (the process is root's `systemd-creds` started by `systemd-creds.socket`); the caller cannot point it at a device or a PCR mask: those are
command-line globals of the daemon (creds.c v259:62, :984). `SYSTEMD_TPM2_DEVICE` exists but only the daemon's own environment is read.
- **No TPM is reachable by that daemon in any test environment here, so a TPM-bound Varlink credential was not produced; it is *inferred* from the source above and goes to F147.**
  In a real unit, with `SYSTEMD_LOG_LEVEL=debug` on `systemd-creds@.service` (drop-in, removed afterwards), debian13, `--user --with-key=host+tpm2` from the service uid:
  ```
  Found container virtualization podman.   (journal of systemd-creds@...:  `System lacks TPM2 support or running in a container, not attempting to use TPM2.`)
  $ ls /sys/class/tpmrm | wc -l  -> 0       $ systemd-detect-virt -c -> podman
  ```
  `tpm2_support()` skips the TPM when `detect_container() > 0` and there is no `/sys/class/tpmrm` device (tpm2-util.c v255:7324, v258:7770); no option bypasses it. Neither the e2e containers nor the dev container (also podman) can ever
  show a TPM-bound Varlink credential; `swtpm` (F108 route 2) is a socket, not a kernel device.
- **`withKey` (v259+) is a trap in `user` scope.** ubuntu2604, service uid: `withKey=host, scope=user` → blob id `5a1c6a86df9d4096b1d5a65e0862f19a` (host key, **not scoped**), and the service itself cannot decrypt it:
  `Decrypt scope=user` → `io.systemd.Credentials.BadScope`, `scope=system` → `InteractiveAuthenticationRequired` (uid 65534 the same). Without `withKey` the id is `55b9ed1d...` (scoped) and decrypts.
  `withKey=null, scope=user` **succeeds** (id `058469daf6f54324800549da0f8ea2fb`, no encryption) and `host+tpm2` is not a value (`host_tpm2`, enum; in the container `ENOTRECOVERABLE`). The service must therefore not send `withKey`, and must refuse a blob whose header id is the null id.
- **What "TPM-bound" means, shown with the tool's own TPM path (root, explicit device).** The CLI as root opens the TPM in its own process; `--tpm2-device=swtpm:path=<sock>` (a TCTI string) points it at `swtpm`, started by `just with-swtpm` (dev container) or `scripts/with-swtpm.sh` (targets).
  Each cell's expected result written before the run; the first four lines of the encrypt log say `rc=0` for `tpm2`, `host+tpm2`, `host`:

  | credential made with | nothing changed (exp. ok) | host secret replaced (exp.) | observed | TPM state replaced, new `swtpm` (exp.) | observed |
  |---|---|---|---|---|---|
  | `--with-key=tpm2` | ok | **ok** (TPM only) | ok | **fail** | `rc=1 Esys_Load ... Received TPM Error` |
  | `--with-key=host+tpm2` | ok | **fail** (needs both) | `Decryption failed (incorrect key?)` | **fail** | `rc=1 Esys_Load ... Received TPM Error` |
  | `--with-key=host` | ok | fail | `Decryption failed (incorrect key?)` | ok (no TPM involved) | `MARKER` |

  Identical on all six (dev container 257.13 and the six targets; arch prints `Esys_Load.c:314`, the others `:324`). So `tpm2` is **TPM alone**, `host+tpm2` and `auto` with a TPM are **host plus TPM**: clearing the TPM or replacing the host secret each loses the key of the second.
  The `user` scope adds the uid (and user name, *inferred* for the name and machine-id) to the host key. The service's `auto_scoped` can only be host plus TPM, or host alone.
- **ubuntu2404 (255), service uid, TPM alone as non-root** (the only TPM binding there, no host key): `--with-key=tpm2 --tpm2-pcrs= --tpm2-device=swtpm:path=...` rc=0, decrypt rc=0 `MARKER`. Anyone who can open the TPM can decrypt it: no uid binding.

### No PCR, explicitly
`systemd-creds encrypt --with-key=tpm2` (root, explicit device, all six), stored policy read back from the credential header: the id (16 bytes), four `le32`, the IV (12 bytes) pad to 8, then `le64 pcr_mask` at **byte 48** (creds-util.c v258:645-672; for a
non-TPM id those bytes are IV, not a mask). `od` of `base64 -d`:

| target | `systemd-creds` | no `--tpm2-pcrs` (default) | `--tpm2-pcrs=` (empty) | `--tpm2-pcrs=7` |
|---|---|---|---|---|
| debian13, ubuntu2404, alma10 | 257, 255, 257 | mask `8000000000000000` (PCR 7; it also warns `none of the selected PCRs are valid` on swtpm) | `0000000000000000` | `8000000000000000` |
| ubuntu2604, fedora44, arch | 259, 259, 262 | `0000000000000000` | `0000000000000000` | `8000000000000000` |
So **`--tpm2-pcrs=` with an empty value is the explicit "no PCR" argument, accepted by all six** (tpm2-util.c: empty clears the mask), and the default is non-empty (PCR 7) on 255 and 257, empty on 259 and 262 (NEWS v258: the new default
is empty). The negative control is the default run on the 255/257 targets. `host+tpm2` has the same mask at the same offset (checked, same table). **But the service cannot pass that argument**: the Varlink daemon takes it from its own command line
(`ExecStart=-systemd-creds`, no argument), so on 255-257 a TPM present on the machine makes `auto` produce PCR 7 (`arg_tpm2_pcr_mask = TPM2_PCR_MASK_DEFAULT`, creds.c v257:1032-1033; *inferred from the source*, not run: no TPM
reachable, see above). On 258+ the default is empty (creds.c v258:1101-1102), *inferred* the same way. Decision for every target: the service reads the header back after each `Encrypt` (id and, for a TPM id, the mask at byte 48) and **refuses to store a credential whose mask is not 0, or whose id is the null id**; that holds whatever
a future default is. F147 runs it on real hardware.

### Plaintext without a temporary file
`strace -f -qq -s 300 -e trace=execve,openat,creat,connect,write,send,sendto,sendmsg` of `systemd-creds --user encrypt --name=k - -` and `decrypt ... - -`, as the service uid (`setpriv`, outside the sandbox: `strace` needs `ptrace`, which `@system-service` refuses; debian13 and the four other `--user` targets, same result; ubuntu2404 has no `--user` to trace):
```
argv: ["systemd-creds","--user","encrypt","--name=k","-","-"]  /  ["systemd-creds","--user","decrypt","--name=k","-","-"]     execve lines containing the marker or its base64: 0
files opened for write/create (openat/creat) by both calls: none            connect(): 2 x AF_UNIX /run/systemd/io.systemd.Credentials
plaintext reaches the call:  sendto(3, "{\"method\":\"io.systemd.Credentials.Encrypt\", ...")   (stdin -> Varlink JSON, `data` base64)
plaintext leaves the call:   write(1, "F110-STRACE-MARKER-1610", 23)                           (stdout)
marker (raw or base64) in /tmp /var/tmp /var/lib /run /root after both calls: none
```
The probe unit does the same search from inside its own sandbox at the end of its run on all six (`grep -rIl --binary-files=text MARKER /tmp /var/tmp /var/lib/custodio /run` → no `MATCH:`; ubuntu2404 too, where it did not encrypt). Plaintext never passes through argv (`--name=` is the only data in argv, and
`ProtectProc=invisible` hides other processes' `/proc`). Exposures that remain: the pipe to `systemd-creds` (stdin/stdout of the child) or the Varlink socket, and, in the root daemon, its memory (root can read it: the SPEC's threat model already says so). A direct Varlink call, with `data`, needs no child
and no pipe. The base64 `data` in the reply is the plaintext: zeroize it. `SYSTEMD_LOG_LEVEL=debug` prints `"data":"<sensitive data>"`, not the bytes.

### Errors
Forced cases, service uid, `--user`/Varlink; the same on debian13, ubuntu2604, fedora44, alma10, arch unless a second form is given (257 form / 259-262 form):
| case | CLI (always rc=1) | Varlink | class |
|---|---|---|---|
| socket missing (`systemd-creds.socket` stopped, socket removed) | `Failed to connect to io.systemd.Credentials: No such file or directory` | connect fails: `Failed to open '/run/systemd/io.systemd.Credentials': No such file or directory` | **unavailable** |
| `systemd-creds` cannot start / no socket on ubuntu2404 | `unrecognized option '--user'` | socket absent (as above) | **unavailable** |
| encrypt, no key (host secret on tmpfs, no TPM; dev container) | `Failed to encrypt: io.systemd.System` | `io.systemd.System {"errno":2}` | **unavailable** |
| encrypt/decrypt that needs polkit (system scope, other uid) | `...: io.systemd.InteractiveAuthenticationRequired` | the same | **unavailable** (never called) |
| TPM missing / unusable at encrypt (259: `withKey=tpm2` in the container) | - | `State not recoverable {"errno":131,"errnoName":"ENOTRECOVERABLE"}` | **unavailable** |
| corrupted blob, garbage, empty, another uid | `Bad credential format.` | `io.systemd.Credentials.BadFormat {}` | **cannot decrypt** |
| wrong `--name` | `Name in credential doesn't match expectations.` | `io.systemd.Credentials.NameMismatch` | **cannot decrypt** |
| blob not base64 | - | `org.varlink.service.InvalidParameter {"parameter":"blob"}` | caller bug |
| host secret changed | `Failed to decrypt: io.systemd.System` | `io.systemd.System {"errno":2}` / `No such file or directory {...ENOENT}` | **cannot decrypt** |
| TPM state replaced (root CLI, not via Varlink) | `Esys_Load ... Received TPM Error` | *not shown* (no TPM): 259+ names `KeyBelongsToOtherTPM`, `TPMInDictionaryLockout`, `UnexpectedPCRState`, `NVIndexUnusable` | **cannot decrypt** (*inferred*) |
| scope mismatch (`withKey=host` blob decrypted with `scope=user`) | - | `io.systemd.Credentials.BadScope` | **cannot decrypt** |
The CLI loses the error name (always rc=1, text only); the service should speak Varlink itself and read the reply's error name (`varlinkctl` is only the test tool). **Pairs that cannot be told apart**: on 257 `io.systemd.System {"errno":2}` is both "no key available" at `Encrypt` and "host secret changed"
at `Decrypt` (the call tells which); and at `Decrypt` "TPM unusable / cleared / locked out" cannot be separated from "key wrong" on 257 (all `io.systemd.System`). Conservative mapping: a failure to connect, or any `Encrypt` error other than a named caller bug, is **unavailable**; every reply of `Decrypt` (any error) is **cannot decrypt**, the
same as a TPM blob that does not load (SPEC section 3), and no signature is made either way.

### Dev container (no systemd as PID 1), uid 1000
`strace` is not installed there (the strace run is on the targets). What the real binary does, with no mock:
```
$ systemd-creds --user encrypt --name=k - -   (also host|tpm2|null|auto, with SYSTEMD_CREDENTIAL_SECRET=...)    -> Failed to connect to io.systemd.Credentials: No such file or directory   (the unprivileged CLI needs the daemon)
$ unshare -Urm bash -c 'mount -t tmpfs t /var/lib/systemd; systemd-creds encrypt --with-key=host ...'                                                -> works: root of a user namespace takes the direct path (it generates the secret itself)
```
- **`--user` and Varlink, real daemon, no root, no PID 1:** `unshare -m --map-root-user --map-users=auto --map-groups=auto` (rootless podman's `newuidmap` and `/etc/subuid` give uids 1-998), then inside: `mount -t tmpfs t /run/systemd`;
  `mount --bind <dir on a real filesystem> /var/lib/systemd` (a tmpfs there gives `no encryption key available`: the secret must not be on tmpfs); `systemd-socket-activate -a --fdname=varlink -l /run/systemd/io.systemd.Credentials systemd-creds &` (**`--fdname=varlink`**, else the child runs `list` and
  the client gets `Connection reset by peer`); `chmod 0666` the socket; clients as `setpriv --reuid=42 --regid=42 --clear-groups systemd-creds --user ...` (uid 42 is `_apt`, a uid that resolves: an unknown uid gives `No such user.`). Result as uid 42:
  `--user` `host`, `host+tpm2`, `auto` encrypt+decrypt rc=0 (`MARKER`, id `55b9ed1d...`, no TPM), `tpm2` and `null` refused, system scope `io.systemd.System {"errno":2}` (no polkit bus), uid 1 decrypting uid 42's blob `BadFormat`, wrong name `NameMismatch`, host secret replaced → `io.systemd.System {"errno":2}`,
  socket removed → `Failed to connect to io.systemd.Credentials: No such file or directory`, `varlinkctl` introspect lists `Encrypt`/`Decrypt`. This covers every error row above except the TPM ones.
- **TPM-bound, `swtpm`, explicit device:** `just with-swtpm unshare -m --map-root-user bash -c 'mount --bind <real dir> /var/lib/systemd; systemd-creds encrypt --with-key=tpm2|host+tpm2 --tpm2-device="$TPM2TOOLS_TCTI" ...'` (the TCTI string `swtpm:path=<sock>` is what `with-swtpm` exports): the table in "Key used" and the PCR table were produced there first (two `with-swtpm` calls: the second is the "new TPM"). The CLI process opens the TPM.
- **Not possible there, so these cases belong to `just e2e-cases`/F147 with a real kernel TPM:** a Varlink `Encrypt` that includes the TPM (the daemon refuses a TPM in a container and without `/sys/class/tpmrm`, no environment variable bypasses it), and the stored mask of such a credential. Everything else above can be a normal integration test with the real `systemd-creds`, `swtpm` for the explicit-device TPM cases, and no fake.

Decision: debian13: scope `user` (own uid, no polkit), call the Varlink interface directly (`Encrypt`/`Decrypt` with `name`, `data`, `scope":"user"`, no `withKey`; plain `systemd-creds --user ... - -` is the same call), key `auto` is the daemon's (host+uid, plus the TPM when it finds one); no per-call no-PCR argument exists (`--tpm2-pcrs=` is the daemon's), so the service reads the mask back at byte 48 and refuses a nonzero mask or the null id; Encrypt error or connect failure → credential service unavailable, any Decrypt error → cannot decrypt.
Decision: ubuntu2404: no `--user`, no Varlink; the service can only run `systemd-creds encrypt|decrypt --with-key=tpm2 --tpm2-pcrs= --tpm2-device=<device> - -` itself (TPM alone, non-root, `--tpm2-pcrs=` = no PCR, stdin/stdout); no host-bound form without root; CLI exit 1 text: `Failed to determine local credential host secret` and a missing TPM → credential service unavailable, `Esys_Load` / `Decryption failed` / `Bad credential format` → cannot decrypt.
Decision: ubuntu2604: scope `user`, Varlink `Encrypt`/`Decrypt` directly, never `withKey` (user scope + `withKey` gives an unscoped or null credential); the default mask is empty in 259 (verified with the root CLI, source for Varlink) and the service reads the mask back at byte 48 and refuses nonzero or the null id; Encrypt error or connect failure → credential service unavailable, any Decrypt error (`BadFormat`, `NameMismatch`, `BadScope`, `io.systemd.System`, the TPM names) → cannot decrypt.
Decision: fedora44: as ubuntu2604 (systemd 259.10): scope `user`, Varlink directly, no `withKey`, read-back refusing nonzero mask or null id; Encrypt error or connect failure → credential service unavailable, any Decrypt error → cannot decrypt.
Decision: alma10: as debian13 (systemd 257): scope `user`, Varlink directly, no `withKey` (not in 257); no per-call no-PCR argument, read-back of the mask at byte 48 refusing nonzero or the null id; Encrypt error or connect failure → credential service unavailable, any Decrypt error → cannot decrypt.
Decision: arch: as ubuntu2604 (systemd 262.1): scope `user`, Varlink directly, no `withKey`, default mask empty (source), read-back refusing nonzero mask or the null id (the header ids differ in 262: `d4062dfb...` TPM, `1414258818...` host+TPM, so the id test is a list per version, not a constant); Encrypt error or connect failure → credential service unavailable, any Decrypt error → cannot decrypt.
Deviation: debian13 (systemd 257, `auto` binds to PCR 7 on a machine with a usable TPM and the caller cannot change it; the encrypted fallback is unavailable there when a TPM is present, host+uid-bound otherwise)
Deviation: alma10 (systemd 257, the same)
Deviation: ubuntu2404 (systemd 255: no `--user`, no Varlink, no host-bound credential without root; only a TPM-alone credential, no uid binding, and nothing on a machine without a TPM)

## F111

The probes of F106 and F107 on a hardware TPM, run by a person on 2026-11-03: a Dell XPS 13 9305 with a discrete
STMicroelectronics TPM (`TPM2_PT_MANUFACTURER` `0x53544D20` "STM ", family "2.0", revision 1.38,
`TPM2_PT_FIRMWARE_VERSION_1` raw `0x00010102`, that is 1.258, `_2` `0x0`). Native build of `origin/milestone/m4`
at 9887fa0 (Rust 1.99.1, tss2-esys 4.1.3, OpenSSL 3.5.5), `TPM2TOOLS_TCTI=device:/dev/tpmrm0`, the user given
`rw` on `/dev/tpmrm0` by a temporary ACL. Both probes exited 0; `handles-persistent` and `handles-nv-index` were
identical before and after. Verified unless marked inferred.

### What differs from `swtpm`

- **SHA-512 is absent** (`GetCapability(ALGS)`; `TestParms` with SHA-512 answers `0x1C3` for RSASSA, RSAPSS and
  ECDSA). Every way-(a) case that needs it lacks (`0x1D5`): the SHA-512 `DigestInfo`, all SHA-512 PSS salts, and the
  `full+own-hash` hand-over of a SHA-512 digest to P-256. Way (b) serves all of them and they verify; the ECDSA
  `truncated32+SHA-256` hand-over serves all three digests. Neither list of F107 for (b) nor the P-256 list contains
  SHA-512, so this TPM is `ready` for both key types; under (a) RSA would lack.
- **Cost of the parent (candidate B)**: ECC P-256 `CreatePrimary` 493.8 ms, RSA 2048 3741.6 ms (N=5, with
  `ReadPublic` and `FlushContext`), against 4.4 and about 25-33 ms on `swtpm`. F114 loads the key per signature
  and flushes by the end of the call, so with B every signature pays about 0.5 s for the parent on this TPM.
- **`0x81000001` is occupied** by an RSA 2048 restricted decryption key put there by another program, whose name
  is not the TCG SRK template's (`persistent_0x81000001_matches_srk: no`). A second persistent key sits at
  `0x81010001`, and 7 NV indexes exist. Candidate A would meet the foreign-key case on this first real machine.

### What is the same

- PSS salt produced by `TPM2_Sign`: the hash length (32 for SHA-256, 48 for SHA-384), as libtpms.
- `sign|decrypt` is accepted on an unrestricted RSA key; `TestParms` rsa2048 null scheme is supported; a sign-only
  key refuses `TPM2_RSA_Decrypt` with `0x182`. Way (b) signatures equal way (a) where (a) serves.
- From a second connection, the `sign|decrypt` key decrypted a chosen ciphertext ("secret message"); neither key
  could be duplicated (`0x124`).
- Both templates are deterministic.

### Raw output

stdout and stderr interleaved; the esys `WARNING`/`ERROR` lines are libtss2's log of the expected TPM errors.

```
### getcap properties-fixed
TPM2_PT_FAMILY_INDICATOR:
  raw: 0x322E3000
  value: "2.0"
--
TPM2_PT_REVISION:
  raw: 0x8A
  value: 1.38
--
TPM2_PT_MANUFACTURER:
  raw: 0x53544D20
  value: "STM "
TPM2_PT_VENDOR_STRING_1:
  raw: 0x10102
  value: ""
TPM2_PT_VENDOR_STRING_2:
  raw: 0x20102
  value: ""
TPM2_PT_VENDOR_STRING_3:
  raw: 0x0
  value: ""
TPM2_PT_VENDOR_STRING_4:
  raw: 0x0
  value: ""
--
TPM2_PT_FIRMWARE_VERSION_1:
  raw: 0x10102
TPM2_PT_FIRMWARE_VERSION_2:
  raw: 0x0
### before: handles-persistent
- 0x81000001
- 0x81010001
### before: handles-nv-index
- 0x1C00002
- 0x1C0000A
- 0x1C00012
- 0x1C10102
- 0x1C10103
- 0x1C10104
- 0x1C101C0
### tpm-probe parent
manufacturer: 0x53544d20 (STM)
persistent_handles: 0x81000001 0x81010001
nv_indexes: 7
persistent_0x81000001: occupied
persistent_0x81000001_template: rsa2048 fixedtpm=true fixedparent=true sensitivedataorigin=true userwithauth=true noda=true restricted=true decrypt=true sign=false
persistent_0x81000001_name: 000b3be24b5d2c593e979c82989d8d7bb74b9701d7137d5084096995dd04cd0083bc
owner_hierarchy: accepts empty auth
rsa2048_name: 000bc29fee123fd4dfa2e1d182c9ad8912360d287b1c55f1fc2d078212248950cf55
rsa2048_public_sha256: c29fee123fd4dfa2e1d182c9ad8912360d287b1c55f1fc2d078212248950cf55
rsa2048_deterministic: yes
rsa2048_mean_ms: 3741.6 (N=5, each call includes ReadPublic and FlushContext)
ecc_p256_name: 000bb5290d95a607204ec64ec5baa489a486095b1cd4f8685b04f5f7f1b9a07c2df5
ecc_p256_public_sha256: b5290d95a607204ec64ec5baa489a486095b1cd4f8685b04f5f7f1b9a07c2df5
ecc_p256_deterministic: yes
ecc_p256_mean_ms: 493.8 (N=5, each call includes ReadPublic and FlushContext)
persistent_0x81000001_matches_srk: no
exit=0
### tpm-probe mechanisms
manufacturer: 0x53544d20 (STM)
persistent_handles: 0x81000001 0x81010001
nv_indexes: 7
verifier: OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)
table_rule_a: CKM_RSA_PKCS_PSS is served under (a) only when salt_requested equals the salt the TPM produces; any other length is lacks by that policy, not a TPM error
key: rsa2048 sign-only fixedtpm=true fixedparent=true sensitivedataorigin=true restricted=false sign=true decrypt=false
key: rsa2048 sign|decrypt fixedtpm=true fixedparent=true sensitivedataorigin=true restricted=false sign=true decrypt=true
key: ecc_p256 sign-only fixedtpm=true fixedparent=true sensitivedataorigin=true restricted=false sign=true decrypt=false
control: verifier right_payload=yes wrong_payload=no
case: way=a mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-1 outcome=served rc=- verified=yes
case: way=a mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-256 outcome=served rc=- verified=yes
case: way=a mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-384 outcome=served rc=- verified=yes
WARNING:esys:src/tss2-esys/api/Esys_Sign.c:311:Esys_Sign_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_Sign.c:105:Esys_Sign() Esys Finish ErrorCode (0x000001d5) 
case: way=a mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-512 outcome=lacks rc=Code: 0x000001D5, Message: Structure is the wrong size (associated with parameter number 1). verified=n/a
WARNING:esys:src/tss2-esys/api/Esys_Sign.c:311:Esys_Sign_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_Sign.c:105:Esys_Sign() Esys Finish ErrorCode (0x000001d5) 
case: way=a mechanism=CKM_RSA_PKCS payload="36-byte MD5+SHA-1 stand-in (TLS 1.0/1.1)" outcome=lacks rc=service parser: not a known DigestInfo tpm_if_passed_as_digest=Code: 0x000001D5, Message: Structure is the wrong size (associated with parameter number 1). verified=n/a
WARNING:esys:src/tss2-esys/api/Esys_Sign.c:311:Esys_Sign_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_Sign.c:105:Esys_Sign() Esys Finish ErrorCode (0x000001d5) 
case: way=a mechanism=CKM_RSA_PKCS payload="DigestInfo with an unknown hash OID" outcome=lacks rc=service parser: not a known DigestInfo tpm_if_passed_as_digest=Code: 0x000001D5, Message: Structure is the wrong size (associated with parameter number 1). verified=n/a
salt_found: hash=SHA-256 tpm_salt=32 hash_len=32 equals_hash_len=yes largest_possible=222 wrong_salt_verifies=no
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=32 outcome=served rc=- salt_found=32 verified=yes
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=222 outcome=lacks rc=policy: TPM salt is 32, not 222 salt_found=32 verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=0 outcome=lacks rc=policy: TPM salt is 32, not 0 salt_found=32 verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=20 outcome=lacks rc=policy: TPM salt is 32, not 20 salt_found=32 verified=n/a
salt_found: hash=SHA-384 tpm_salt=48 hash_len=48 equals_hash_len=yes largest_possible=206 wrong_salt_verifies=no
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=48 outcome=served rc=- salt_found=48 verified=yes
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=206 outcome=lacks rc=policy: TPM salt is 48, not 206 salt_found=48 verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=0 outcome=lacks rc=policy: TPM salt is 48, not 0 salt_found=48 verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=20 outcome=lacks rc=policy: TPM salt is 48, not 20 salt_found=48 verified=n/a
WARNING:esys:src/tss2-esys/api/Esys_Sign.c:311:Esys_Sign_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_Sign.c:105:Esys_Sign() Esys Finish ErrorCode (0x000001d5) 
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=64 outcome=lacks rc=Code: 0x000001D5, Message: Structure is the wrong size (associated with parameter number 1). salt_found=n/a verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=190 outcome=lacks rc=Code: 0x000001D5, Message: Structure is the wrong size (associated with parameter number 1). salt_found=n/a verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=0 outcome=lacks rc=Code: 0x000001D5, Message: Structure is the wrong size (associated with parameter number 1). salt_found=n/a verified=n/a
case: way=a mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=20 outcome=lacks rc=Code: 0x000001D5, Message: Structure is the wrong size (associated with parameter number 1). salt_found=n/a verified=n/a
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-256 handover=truncated32+SHA-256 outcome=served rc=- verified_over_leftmost_32=yes verified_over_full_digest=yes verified_over_rightmost_32=no
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-256 handover=full+own-hash outcome=served rc=- verified_over_leftmost_32=yes verified_over_full_digest=yes verified_over_rightmost_32=no
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-384 handover=truncated32+SHA-256 outcome=served rc=- verified_over_leftmost_32=yes verified_over_full_digest=yes verified_over_rightmost_32=no
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-384 handover=full+own-hash outcome=served rc=- verified_over_leftmost_32=yes verified_over_full_digest=yes verified_over_rightmost_32=no
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-512 handover=truncated32+SHA-256 outcome=served rc=- verified_over_leftmost_32=yes verified_over_full_digest=yes verified_over_rightmost_32=no
WARNING:esys:src/tss2-esys/api/Esys_Sign.c:311:Esys_Sign_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_Sign.c:105:Esys_Sign() Esys Finish ErrorCode (0x000001d5) 
case: way=a mechanism=CKM_ECDSA curve=P-256 digest=SHA-512 handover=full+own-hash outcome=lacks rc=Code: 0x000001D5, Message: Structure is the wrong size (associated with parameter number 1). verified_over_leftmost_32=n/a
case: way=b mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-1 outcome=served rc=- verified=yes bytes_equal_way_a_same_key=yes
case: way=b mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-256 outcome=served rc=- verified=yes bytes_equal_way_a_same_key=yes
case: way=b mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-384 outcome=served rc=- verified=yes bytes_equal_way_a_same_key=yes
WARNING:esys:src/tss2-esys/api/Esys_Sign.c:311:Esys_Sign_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_Sign.c:105:Esys_Sign() Esys Finish ErrorCode (0x000001d5) 
case: way=b mechanism=CKM_RSA_PKCS payload=DigestInfo/SHA-512 outcome=served rc=- verified=yes bytes_equal_way_a_same_key=n/a (way a lacks)
case: way=b mechanism=CKM_RSA_PKCS payload="36-byte MD5+SHA-1 stand-in (TLS 1.0/1.1)" outcome=served rc=- verified=yes bytes_equal_way_a_same_key=n/a (way a lacks)
case: way=b mechanism=CKM_RSA_PKCS payload="DigestInfo with an unknown hash OID" outcome=served rc=- verified=yes bytes_equal_way_a_same_key=n/a (way a lacks)
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=32 outcome=served rc=- salt_found=32 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=222 outcome=served rc=- salt_found=222 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=0 outcome=served rc=- salt_found=0 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-256 salt_requested=20 outcome=served rc=- salt_found=20 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=48 outcome=served rc=- salt_found=48 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=206 outcome=served rc=- salt_found=206 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=0 outcome=served rc=- salt_found=0 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-384 salt_requested=20 outcome=served rc=- salt_found=20 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=64 outcome=served rc=- salt_found=64 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=190 outcome=served rc=- salt_found=190 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=0 outcome=served rc=- salt_found=0 verified=yes
case: way=b mechanism=CKM_RSA_PKCS_PSS hash=SHA-512 salt_requested=20 outcome=served rc=- salt_found=20 verified=yes
WARNING:esys:src/tss2-esys/api/Esys_RSA_Decrypt.c:305:Esys_RSA_Decrypt_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_RSA_Decrypt.c:102:Esys_RSA_Decrypt() Esys Finish ErrorCode (0x00000182) 
control: way=b key_without_decrypt rsa_decrypt=Code: 0x00000182, Message: Inconsistent attributes (associated with handle number 1).
case: way=b mechanism=CKM_ECDSA curve=P-256 digest=SHA-256 outcome=n/a rc=RSA only: ECDSA has no raw private operation the TPM offers in place of TPM2_Sign
case: way=b mechanism=CKM_ECDSA curve=P-256 digest=SHA-384 outcome=n/a rc=RSA only: ECDSA has no raw private operation the TPM offers in place of TPM2_Sign
case: way=b mechanism=CKM_ECDSA curve=P-256 digest=SHA-512 outcome=n/a rc=RSA only: ECDSA has no raw private operation the TPM offers in place of TPM2_Sign
capability: call=GetCapability(ALGS) item=algorithm RSA (0x0001) present
capability: call=GetCapability(ALGS) item=algorithm SHA-1 (0x0004) present
capability: call=GetCapability(ALGS) item=algorithm SHA-256 (0x000b) present
capability: call=GetCapability(ALGS) item=algorithm SHA-384 (0x000c) present
capability: call=GetCapability(ALGS) item=algorithm SHA-512 (0x000d) absent
capability: call=GetCapability(ALGS) item=algorithm RSASSA (0x0014) present
capability: call=GetCapability(ALGS) item=algorithm RSAES (0x0015) present
capability: call=GetCapability(ALGS) item=algorithm RSAPSS (0x0016) present
capability: call=GetCapability(ALGS) item=algorithm ECDSA (0x0018) present
capability: call=GetCapability(ALGS) item=algorithm ECC (0x0023) present
capability: call=GetCapability(ALGS) item=algorithm MGF1 (0x0007) present
capability: call=GetCapability(ECC_CURVES) item=curve NIST P-256 (0x0003) present
capability: call=TestParms key=rsa2048 scheme=RSASSA hash=SHA-1 supported
capability: call=TestParms key=rsa2048 scheme=RSASSA hash=SHA-256 supported
capability: call=TestParms key=rsa2048 scheme=RSAPSS hash=SHA-256 supported
capability: call=TestParms key=ecc_p256 scheme=ECDSA hash=SHA-256 supported
capability: call=TestParms key=rsa2048 scheme=RSASSA hash=SHA-384 supported
capability: call=TestParms key=rsa2048 scheme=RSAPSS hash=SHA-384 supported
capability: call=TestParms key=ecc_p256 scheme=ECDSA hash=SHA-384 supported
capability: call=TestParms key=rsa2048 scheme=RSASSA hash=SHA-512 lacks Code: 0x000001C3, Message: Hash algorithm not supported or not appropriate (associated with parameter number 1).
capability: call=TestParms key=rsa2048 scheme=RSAPSS hash=SHA-512 lacks Code: 0x000001C3, Message: Hash algorithm not supported or not appropriate (associated with parameter number 1).
capability: call=TestParms key=ecc_p256 scheme=ECDSA hash=SHA-512 lacks Code: 0x000001C3, Message: Hash algorithm not supported or not appropriate (associated with parameter number 1).
capability: call=TestParms key=rsa2048 scheme=NULL (for way b, with the decrypt attribute) supported
decrypt_key: sign-only attributes: fixedtpm=true fixedparent=true sensitivedataorigin=true restricted=false sign=true decrypt=false
decrypt_key: sign|decrypt attributes: fixedtpm=true fixedparent=true sensitivedataorigin=true restricted=false sign=true decrypt=true
WARNING:esys:src/tss2-esys/api/Esys_RSA_Decrypt.c:305:Esys_RSA_Decrypt_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_RSA_Decrypt.c:102:Esys_RSA_Decrypt() Esys Finish ErrorCode (0x00000182) 
decrypt_other_caller: key=sign-only rsa_decrypt(RSAES, chosen ciphertext) refused Code: 0x00000182, Message: Inconsistent attributes (associated with handle number 1).
decrypt_other_caller: key=sign-only sign(RSASSA, SHA-256, chosen digest) served
WARNING:esys:src/tss2-esys/api/Esys_Duplicate.c:354:Esys_Duplicate_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_Duplicate.c:116:Esys_Duplicate() Esys Finish ErrorCode (0x00000124) 
decrypt_other_caller: key=sign-only duplicate(no new parent) Code: 0x00000124, Message: Authorization handle is not correct for command.
decrypt_other_caller: key=sign|decrypt rsa_decrypt(RSAES, chosen ciphertext) plaintext recovered: "secret message"
decrypt_other_caller: key=sign|decrypt sign(RSASSA, SHA-256, chosen digest) served
WARNING:esys:src/tss2-esys/api/Esys_Duplicate.c:354:Esys_Duplicate_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_Duplicate.c:116:Esys_Duplicate() Esys Finish ErrorCode (0x00000124) 
decrypt_other_caller: key=sign|decrypt duplicate(no new parent) Code: 0x00000124, Message: Authorization handle is not correct for command.
result: every case ran; every served signature verified
exit=0
### after: handles-persistent
- 0x81000001
- 0x81010001
### after: handles-nv-index
- 0x1C00002
- 0x1C0000A
- 0x1C00012
- 0x1C10102
- 0x1C10103
- 0x1C10104
- 0x1C101C0
```
