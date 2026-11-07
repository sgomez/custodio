## 4. Manual acceptance run (M01)

Run on 2026-10-27 in an Ubuntu 26.04 GNOME VM (polkit 127, dbus-daemon 1.16.2) with the F16
`.deb`, one imported RSA 2048 key and a test CA. All verified by hand unless marked.

- **rFirma (acceptance 2): passes** with a development build of rFirma that needed two fixes on
  its side: a fallback from `CKM_SHA256_RSA_PKCS` to `CKM_RSA_PKCS` over a `DigestInfo` (the
  module then offered only raw mechanisms), and no `C_Login` when the token lacks
  `CKF_LOGIN_REQUIRED` (`C_Login` then returned `CKR_FUNCTION_NOT_SUPPORTED`). Each signature
  showed the polkit dialog, a second one asked again, cancelling made the signature fail.
  Both causes are gone: the module offers composed mechanisms (`crates/custodio-pkcs11/src/composed.rs`;
  F33 signs RSA with unpatched rFirma 0.17.0) and `C_Login` returns `CKR_OK` for `CKU_USER` and
  `CKU_CONTEXT_SPECIFIC` (`crates/custodio-pkcs11/src/ffi/login.rs`).
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
- `custodiod` logged nothing per signature; the only trace was polkit's agent helper starting.
  Superseded by F35: one journal audit entry per action (`crates/custodiod/src/audit.rs`).

