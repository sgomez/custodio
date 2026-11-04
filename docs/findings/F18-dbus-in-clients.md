## 2. D-Bus client inside third-party processes

Versions read: as in `F18-always-authenticate.md`.

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

