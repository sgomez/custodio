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
`ProcessFD` key into a pidfd (polkit `main`, read 2026-10-27, verified). Which polkit release
first did this is not pinned down; 124 is taken from its NEWS. So polkit 124+ on a bus that
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
| Arch | 128 | 1.16.2 / 37 | Yes |

"Default bus" is inferred; package versions were checked, not each distribution's default.
Open risk: the end-to-end run covers only Debian 13; no other row was run.
RHEL 10 was checked through CentOS Stream 10 and the AlmaLinux 10 repository.

Consequence: supported targets are Debian 13, Ubuntu 25.10 and later, Fedora 41 and later,
RHEL/Alma 10 and Arch. Ubuntu 24.04 works only with `dbus-broker`. Debian 12, Ubuntu 22.04,
RHEL 9 and Leap are out. The only package built is the Debian 13 `.deb`; the end-to-end suite
runs on trixie (polkit 126, dbus-daemon 1.16.2).

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
| Arch | dbus-daemon | 1.16.2 | rolling (7.x) | present | present | probably absent (no default LSM, inferred) | present | absent | versions verified, rest inferred |

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
