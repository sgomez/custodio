## 1. `CKA_ALWAYS_AUTHENTICATE` and `C_Login(CKU_CONTEXT_SPECIFIC)`

Evidence is source reading at the stated versions plus one experiment: the cryptoki test
`signing_leaves_no_helper_threads` (thread counts around `C_Sign`, `F18-dbus-in-clients.md`). Each claim is marked **verified** (read in source or release notes) or **inferred**. Versions
read: NSS `NSS_3_110_RTM` (same as Debian trixie), Firefox `main`/`esr128`/`esr140`,
LibreOffice `main`, zbus 6.1.0 (our `Cargo.lock`), pkcs11-provider and libp11 default branches
(Oct 2026, not the exact distro versions). Distribution data: Repology API, dated 2026-10-27.

| Client | Behaviour | Status |
|---|---|---|
| NSS | `PK11_SignWithMechanism` (`lib/pk11wrap/pk11obj.c`): if the key has `CKA_ALWAYS_AUTHENTICATE`, it calls `PK11_DoPassword(..., contextSpecific=TRUE)` between `C_SignInit` and `C_Sign`; the result is ignored. `PK11_DoPassword` asks the application's password callback first; only with a password (or a protected authentication path) does `pk11_CheckPassword` call `C_Login(CKU_CONTEXT_SPECIFIC)`. | verified |
| NSS tools without a password callback (`certutil`) | No callback means no `C_Login`; NSS calls `C_Sign` anyway. | verified |
| Firefox | With `CKF_PROTECTED_AUTHENTICATION_PATH` it shows its own dialog and runs `PK11_CheckUserPassword(slot, NULL)` on a background task: `C_Logout` then `C_Login(CKU_USER, NULL, 0)` on the slot's default session. It is not `CKU_CONTEXT_SPECIFIC` on the signing session. | verified |
| LibreOffice | `GetPasswordFunction` always shows a password dialog; the typed value is ignored on a protected-path token. Cancel skips the login. | verified; the follow-on `C_Login(CKU_CONTEXT_SPECIFIC)` after a password is inferred |
| OpenSSL pkcs11-provider | `p11prov_sig_init` reads `CKA_ALWAYS_AUTHENTICATE` after `C_SignInit` and calls `C_Login(CKU_CONTEXT_SPECIFIC)`, with no PIN when the token has `CKF_PROTECTED_AUTHENTICATION_PATH`. | verified |
| OpenSSL libp11 engine | `p11_pkey.c`: after `C_SignInit`, `pkcs11_authenticate` when the attribute is set; `C_Login(CKU_CONTEXT_SPECIFIC, NULL, 0)` on a protected path, a PIN prompt otherwise. | verified |

Superseded by F34 for the LibreOffice row: no password dialog when `CKF_LOGIN_REQUIRED` is unset.

Conclusion: all three honour the attribute, but NSS only when the application cooperates, and
Firefox does it with `CKU_USER` rather than a context login. A pause cannot be assumed
per signature at the login step.

Decision for Custodio: keep `CKA_ALWAYS_AUTHENTICATE = false` (as `token.rs` does) and make
`C_Sign` itself call polkit on every signature. That is correct with every client above, needs no
PIN or login, and is what the spec requires ("every signature calls polkit"). Clients must
tolerate `C_Sign` blocking for as long as the person takes to answer.

