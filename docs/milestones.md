# Milestones

## M0 — Prototype (done)

Proves the idea: a system service holds the key, a PKCS#11 module forwards to it over D-Bus, and
every signature asks polkit. Scope and acceptance in `docs/milestones/SPEC.md`; results in `docs/findings.md`.

## M1 — PKCS#11 compatibility and audit (done)

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

Build and test the packages; publishing them waits for M5.

- Supported: the versions whose bus has `ProcessFD` and that their distribution still maintains.
  Debian 13, Ubuntu 26.04, Fedora 44, RHEL/Alma 10 and Arch. Out: Debian 12, Ubuntu 22.04, RHEL 9
  and openSUSE Leap (no `ProcessFD`), Ubuntu 25.10 and Fedora 43 and earlier.
- `.rpm` for Fedora 44 and RHEL/Alma 10. Check that SELinux lets the service run without a policy of
  its own.
- Packages built with nfpm from one file list, replacing the M1 .deb-only tooling: the `.deb`, the `.rpm` and an
  Arch `.pkg.tar.zst`, all from `just package` on the host.
- Arch package installed with `pacman -U`. Acceptance on Omarchy 4, whose polkit agent is the
  Quickshell one inside `omarchy-shell`, not polkit-gnome.
- rpm-ostree layering of the `.rpm` on an atomic Fedora (Bazzite).
- End-to-end suite on every supported target, not only Debian 13; Alma 10 only there.
- Upgrade and removal: keys survive a package upgrade and the service restarts with them. Decide
  what removal and purge do with the state directory: keys cannot be exported, so deleting it
  destroys them.
- Ubuntu 24.04: require `dbus-broker`, tried on the `ubuntu2404` VM; refuse to install if switching
  the system bus breaks something. Never install on `dbus-daemon`.
- Firefox on Fedora and Arch: confirm that the system NSS sees the module through p11-kit without
  manual registration.

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
- Packages published in repositories next to rFirma's channel on `rfirma.com`.

## Unassigned

- **Firefox snap:** the confined Firefox cannot load the module. Needs its own investigation
  (snap interfaces, a module inside the snap's reach) or a documented limitation.
- **Firefox Flatpak:** the sandboxed Firefox does not see the host's module (seen on Fedora in F54);
  on atomic systems such as Bazzite every browser is a Flatpak. Needs its own investigation (the
  module inside the sandbox's reach, `--system-talk-name=com.rfirma.Custodio1` through
  `flatpak override`) or a documented limitation.
- **Firefox without p11-kit:** Mozilla's builds bundle their own NSS, and Arch's and Debian's NSS
  load no p11-kit proxy (`docs/findings.md`, F56), so Firefox ignores `.module` files there. M2
  documents registration by hand (`docs/install.md`, "Firefox"). An enterprise policy is one file and
  would override the administrator's. Candidate: a `custodio` command that registers the module in
  the user's NSS profiles, for Firefox and its derivatives (each with its own profile root).
- **Several dialogs per page in TLS client authentication:** correct by design, but tiring on real
  sites. A short grace window would conflict with "never cache an authorization".
- **Document details in the dialog:** what polkit can show safely, and whether it is worth it when
  the hash cannot be proven.
- **Snap and systemd-sysext** packages.
- **More key types:** RSA 3072/4096, P-384.
- **Fingerprint acceptance:** M0's SPEC acceptance 6 on a machine with a reader.
- **RSA-PSS:** `CKM_RSA_PKCS_PSS` and the composed variants, once a target client needs it.
- **Key lifecycle:** listing and deleting keys, replacing a renewed certificate, and what happens to
  the keys when the disk dies (no export by design).
- **Keys born in the TPM:** `C_GenerateKeyPair` and a CSR, so the key never exists outside the TPM
  (`fixedTPM`, `fixedParent`), as in Windows Hello. The FNMT Configurador cannot generate the key
  in a generic PKCS#11 token; the remaining routes are in `docs/reports/fnmt-configurador.md`.
- **Presence without polkit:** the service talking to `fprintd` or a FIDO key directly, so the
  barrier does not depend on the system PAM stack.
