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
- rFirma signs without the two workarounds recorded in `docs/findings/M01-acceptance.md`.
- LibreOffice signs a document through the module.
- One journal entry per signature: caller uid and pid, key, approved or denied. No key material and
  no hash contents.
- Manual acceptance with a P-256 key, not only RSA 2048.

## M2 — Packaging and distributions (done)

Build and test the packages; publishing them waits for M6.

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

## M3 — Client API (done)

What any client needs from the service, rFirma included. The rFirma side waits for M6.

- Import asks polkit, as signing does. Today any process of any uid can import.
- Each key belongs to the uid that imported it; listing and signing only see the caller's keys.
- Delete a key, and replace the certificate of a renewed one keeping the key.
- The journal entry names the flatpak app-id when the caller is a flatpak (read from the
  `xdg-dbus-proxy` process's `/.flatpak-info`); a record, not an authorization.
- `custodio list` and `custodio delete`, so the CLI uses the API as a client would.
- The D-Bus API documented for clients: detecting the service, import, list, delete, sign and their
  errors.

## M4 — TPM (done)

- Import keys with `TPM2_Import` (`tss-esapi`); the service keeps the wrapped blob and the
  certificate in its state directory.
- Fall back to a file encrypted with `systemd-creds` when there is no TPM or it lacks the
  algorithm: bound to the TPM when there is one, to the host key otherwise. Weaker than
  `TPM2_Import`, because the key is decrypted in the service's memory to sign and root can take it.
- No migration: keys from earlier milestones are purged, with one journal entry each.
- Imported keys cannot leave the TPM: empty `authPolicy`, so `TPM2_Duplicate` fails. Grades and
  checks in `docs/reports/polkit-custodian-linux.md` section 8.
- No PCR policy on the imported keys: PCR 7 also measures `dbx`, which `fwupd` updates, and a key
  that stops loading cannot be imported again without the `.p12`. No PIN either: polkit is already
  the barrier, and against a stolen machine full-disk encryption does the same at no cost.

## M5 — The encrypted fallback on real machines

M4's encrypted fallback was proven only in containers and with stand-ins for `systemd-creds`
(`docs/milestones/M4/SPEC_DEVIATIONS.md`, F110 and F134). Before M6:

- One end-to-end target on a VM: the Ubuntu 26.04 minimal cloud image with a virtual TPM. On
  systemd 259 and later the daemon seals `encrypted-tpm` with no PCR, the same route as Fedora 44
  and Arch, so the cases of F134, F135, F137, F138, F140 and F141 run with that kind, RSA-PSS
  included. No other distribution gets a VM: on systemd 257 the kind cannot exist (the service
  refuses the PCR 7 binding). The minimal image's kernel may lack the TPM drivers; if so, a finding
  says which image or kernel package to use instead.
- The VM run is a release test: CI runs it on the release, never on each PR. Within the milestone,
  it runs only at the checkpoint and the last feature.
- The `.deb` depends on `libtss2-rc0t64`. systemd loads it by `dlopen` and Ubuntu only recommends
  it, so on an install without recommends (the minimal cloud image) `systemd-creds` cannot use the
  TPM and an import that needs `encrypted-tpm` fails with a binding mismatch.
- By hand, once: on Debian 13 with a TPM, read the PCR mask of a credential the daemon seals, to
  confirm or refute the inferred PCR 7 binding.
- Ubuntu 24.04 without a TPM: import fails, since systemd 255 gives a non-root service no host-bound
  credential. Fix it or document it as a limitation.

## M6 — Public release

- Written threat model and security policy (`SECURITY.md`, how to report a vulnerability). The
  threat model says that without full-disk encryption whoever takes the machine can use the keys,
  though not copy them.
- Warn when the state directory is not on an encrypted device (dm-crypt in its `lsblk` chain).
- External review of the authorization path and the FFI layer.
- Repository made public, user README (what Custodio protects against and what it does not),
  release notes.
- Packages published in repositories next to rFirma's channel on `rfirma.com`.
- rFirma integration, built in rFirma's repository against the M3 API: it detects Custodio, imports
  a `.p12` into it and offers to delete the original, and its flatpak ships the module with
  `--system-talk-name=com.rfirma.Custodio1`. Without Custodio, rFirma works as today.

## Unassigned

- **Firefox snap:** the confined Firefox cannot load the module. Needs its own investigation
  (snap interfaces, a module inside the snap's reach) or a documented limitation.
- **Firefox Flatpak:** the sandboxed Firefox does not see the host's module (seen on Fedora in F54);
  on atomic systems such as Bazzite every browser is a Flatpak. Needs its own investigation (the
  module inside the sandbox's reach, `--system-talk-name=com.rfirma.Custodio1` through
  `flatpak override`) or a documented limitation.
- **Firefox without p11-kit:** Mozilla's builds bundle their own NSS, and Arch's and Debian's NSS
  load no p11-kit proxy (`docs/findings/F56.md`), so Firefox ignores `.module` files there. M2
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
- **Composed RSA-PSS:** `CKM_SHA256_RSA_PKCS_PSS` and peers (`CKM_RSA_PKCS_PSS` is in M4), once a
  target client needs them.
- **Refuse the encrypted kinds:** an administrator setting, deferred by M4's SPEC; an organisation
  may prefer no key over a weaker one. Worth deciding before the public release.
- **Key loss:** what happens to the keys when the disk dies (no export by design). Listing, deleting
  and replacing are in M3.
- **Keys born in the TPM:** `C_GenerateKeyPair` and a CSR, so the key never exists outside the TPM
  (`fixedTPM`, `fixedParent`), as in Windows Hello. The FNMT Configurador cannot generate the key
  in a generic PKCS#11 token; the remaining routes are in `docs/reports/fnmt-configurador.md`.
- **PCR policy with signed policies** (`PolicyAuthorize`, `systemd-pcrlock`): keys that survive
  updates but refuse a foreign boot. Only once lost keys can be recovered (M4 has no PCR policy).
- **Presence without polkit:** the service talking to `fprintd` or a FIDO key directly, so the
  barrier does not depend on the system PAM stack.
