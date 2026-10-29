# Milestones

## M0 — Prototype (done)

Proves the idea: a system service holds the key, a PKCS#11 module forwards to it over D-Bus, and
every signature asks polkit. Scope and acceptance in `docs/milestones/SPEC.md`; results in `docs/findings.md`.

## M1 — PKCS#11 compatibility and audit

Make Custodio work with clients as they are, instead of clients adapting to it.

- Composed mechanisms in the module: `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`,
  `CKM_SHA512_RSA_PKCS`, `CKM_ECDSA_SHA256` and peers. The module hashes and builds the
  `DigestInfo`; the service still receives only the hash.
- `C_Login` accepted as a no-op instead of `CKR_FUNCTION_NOT_SUPPORTED`.
- rFirma signs without the two workarounds recorded in `docs/findings.md`.
- LibreOffice signs a document through the module.
- One journal entry per signature: caller uid and pid, key, approved or denied. No key material and
  no hash contents.
- Manual acceptance with a P-256 key, not only RSA 2048.

## M2 — Packaging and distributions

- `.rpm` for Fedora and RHEL/Alma 10.
- End-to-end suite on every supported target in `docs/findings.md`, not only Debian 13.
- Ubuntu 24.04: decide between requiring `dbus-broker`, refusing to install, or documenting it.
- Firefox on Fedora: confirm that the system NSS sees the module through p11-kit without manual
  registration.
- Package repositories next to rFirma's channel on `rfirma.com`.

## M3 — rFirma integration

- rFirma detects Custodio on the system bus and offers to import a `.p12` into it instead of the
  rFirma store.
- After import, rFirma tells the person to delete the original `.p12` and offers to do it.
- Flatpak: the module ships inside rFirma's flatpak and reaches the service with
  `--system-talk-name=com.rfirma.Custodio1`. Without Custodio installed, rFirma keeps working as
  today.
- User documentation: what Custodio protects against and what it does not.

## M4 — TPM

- Import keys with `TPM2_Import` (`tss-esapi`); the service keeps the wrapped blob and the
  certificate in its state directory.
- Fall back to a file encrypted with `systemd-creds` when there is no TPM or it lacks the
  algorithm: bound to the TPM when there is one, to the host key otherwise. Weaker than
  `TPM2_Import`, because the key is decrypted in the service's memory to sign and root can take it.
- Migration of existing file keys into the TPM.
- Imported keys cannot leave the TPM: empty `authPolicy`, so `TPM2_Duplicate` fails. Grades and
  checks in `docs/reports/polkit-custodian-linux.md` section 8.

## M5 — Public release

- Written threat model and security policy (`SECURITY.md`, how to report a vulnerability).
- External review of the authorization path and the FFI layer.
- Repository made public, user README, release notes.

## Unassigned

- **Firefox snap:** the confined Firefox cannot load the module. Needs its own investigation
  (snap interfaces, a module inside the snap's reach) or a documented limitation.
- **Firefox without p11-kit:** Mozilla's builds bundle their own NSS and ignore `.module` files.
  Shipping an enterprise policy overrides the administrator's; another registration path is needed.
- **Several dialogs per page in TLS client authentication:** correct by design, but tiring on real
  sites. A short grace window would conflict with "never cache an authorization".
- **Document details in the dialog:** what polkit can show safely, and whether it is worth it when
  the hash cannot be proven.
- **Older distributions without `ProcessFD`** (Debian 12, Ubuntu 22.04, RHEL 9, openSUSE Leap):
  support them with a PID-based subject and its reuse risk, or leave them out.
- **Snap and immutable distributions** (systemd-sysext, rpm-ostree layering).
- **More key types:** RSA 3072/4096, P-384.
- **Fingerprint acceptance:** M0's SPEC acceptance 6 on a machine with a reader.
- **RSA-PSS:** `CKM_RSA_PKCS_PSS` and the composed variants, once a target client needs it.
- **Key lifecycle:** listing and deleting keys, replacing a renewed certificate, and what happens to
  the keys when the disk dies (no export by design).
- **Keys born in the TPM:** `C_GenerateKeyPair` and a CSR, so the key never exists outside the TPM
  (`fixedTPM`, `fixedParent`), as in Windows Hello. Depends on whether the CA's enrolment tool (the
  FNMT Configurador) can generate the key in a system PKCS#11 token.
- **Presence without polkit:** the service talking to `fprintd` or a FIDO key directly, so the
  barrier does not depend on the system PAM stack.
