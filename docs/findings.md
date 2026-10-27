# Findings on the open questions in SPEC.md

Evidence comes from reading source at the stated versions. No live spy or experiment was run;
each claim is marked **verified** (read in source or release notes) or **inferred**. Versions
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
  2 two seconds later. No thread is created and none lingers. The built `.so` does contain
  zbus's `zruntime` unblock pool (string "failed to spawn a thread for blocking work"); it
  spawns threads only for work handed to it, and our call path does not hand it any (the count
  above). A future zbus or a new code path could change that, so the test guards it.
- NSS treats `CKR_CRYPTOKI_ALREADY_INITIALIZED` as success (verified). Modules are called from
  several threads (verified: NSS task queue, main thread, Firefox's background protected-auth
  task); the module is thread-safe (cryptoki integration test `threads`).
- NSS registers no `pthread_atfork` handler for external modules (verified). After a fork,
  `NSS_ContextInit` calls `SECMOD_RestartModules`, which re-initializes a module only if
  `C_GetSlotList` fails (verified). So the module must be correct in a child by itself:
  `ffi.rs` registers `pthread_atfork` and holds the state lock across `fork`; the module keeps
  no connection or thread between calls (experiment above). The `forks` cryptoki test forks
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
  holding no connection or thread across calls is what makes this safe (the no-thread part
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
