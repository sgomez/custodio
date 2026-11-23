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
  refuses the PCR 7 binding). The image's `generic` kernel has the TPM drivers built in; it lacks
  only the `libtss2` libraries, which the package brings.
- The VM run is a release test: CI runs it on the release, never on each PR. Within the milestone,
  it runs only at the checkpoint and the last feature.
- The `.deb` depends on `libtss2-rc0t64`. systemd loads it by `dlopen` and Ubuntu only recommends
  it, so on an install without recommends (the minimal cloud image) `systemd-creds` cannot use the
  TPM and an import that needs `encrypted-tpm` fails with a binding mismatch.
- By hand, once: on Debian 13 with a TPM, read the PCR mask of a credential the daemon seals, to
  confirm or refute the inferred PCR 7 binding.
- systemd 257 is the floor: Ubuntu 24.04 (systemd 255) and older systems are dropped. Every package
  requires systemd 257, and the service's 255 path (the `systemd-creds` CLI with a TPM device), the
  `ubuntu2404` end-to-end target and the Ubuntu 24.04 install steps go. This supersedes M2's
  support for Ubuntu 24.04 with `dbus-broker`.

## M6 — Browsers and public release

Ubuntu's Firefox snap and Firefox builds without p11-kit use Custodio; route and rejected
alternatives in `docs/reports/firefox-snap.md`.

- The service also listens on `/run/snap.firefox/custodio.sock`: list and sign only, a peer only
  with the Firefox snap's exact AppArmor label, polkit on a `unix-process` subject from the peer's
  pidfd. Directory root `0755` from `tmpfiles.d`.
- Inside a snap the module talks to that socket instead of the bus.
- A `custodio` command registers the module in the user's NSS profiles: native Firefox and its
  derivatives, and the Firefox snap through a copy of the module in `~/snap/firefox/common/`, kept
  fresh by a per-user trigger.
- End-to-end on the Ubuntu 26.04 VM: a client under the Firefox snap's confinement signs through the
  socket. The socket rests on a snapd rule that no document promises; this test watches it.
- Written threat model; `SECURITY.md` exists. The threat model says that without full-disk
  encryption whoever takes the machine can use the keys, though not copy them.
- Warn when the state directory is not on an encrypted device (dm-crypt in its `lsblk` chain).
- User README (what Custodio protects against and what it does not, the three storage kinds, the
  limits of the snap route, Firefox Flatpak, key loss) and release notes.

By a person, after the features:

- External review of the authorization path, the FFI layer and the snap socket.
- Repository made public; packages published in repositories next to rFirma's channel on
  `rfirma.com`.
- rFirma integration, built in rFirma's repository against the M3 API: it detects Custodio, imports
  a `.p12` into it and offers to delete the original, and its flatpak ships the module with
  `--system-talk-name=com.rfirma.Custodio1`. Without Custodio, rFirma works as today.
- Ask on the snapcraft forum whether host services may rely on `/run/snap.<snap>/`.

## M7 — A release a person can use end to end (done)

A person on Ubuntu 26.04 with a fingerprint reader gets from the package to a signed login following
only the documentation. Scope and acceptance in `docs/milestones/M7/SPEC.md`; released as v0.9.0.

- `custodio setup fingerprint enable` and `disable`: the finger for polkit only.
- `custodio doctor`: what is missing, in six checks.
- A self-explanatory command line: help for every command, a readable `list`, two-line errors,
  completions for bash, zsh and fish.
- The import error split, the storage classifier fix, and decrypted keys kept out of swap and core
  dumps.

## Unassigned

- **Firefox sees key changes without a restart:** the module's slot is fixed and it has no
  `C_WaitForSlotEvent`, so Firefox reads the token once. A removable slot that reports the token as taken out
  and put back is the usual technique; not tried here, nor its effect on LibreOffice and rFirma. M7 only
  says that a restart is needed.
- **Chromium and Thunderbird snaps:** the same snapd rules should let them use a socket of their own
  in `/run/snap.<snap>/` (inferred, `docs/reports/firefox-snap.md`); M6 ships only Firefox.
- **Firefox Flatpak:** the sandboxed Firefox does not see the host's module (seen on Fedora in F54);
  on atomic systems such as Bazzite every browser is a Flatpak. Needs its own investigation (the
  module inside the sandbox's reach, `--system-talk-name=com.rfirma.Custodio1` through
  `flatpak override`) or a documented limitation.
- **Several dialogs per page in TLS client authentication:** correct by design, but tiring on real
  sites. Each new TLS connection signs once; over HTTP/1.1 Firefox opens several in parallel (page,
  favicon, assets), so client.badssl.com asked for the finger several times in F211, where HTTP/2 or a
  resumed session would ask once. `network.http.max-persistent-connections-per-server=1` reduces it, at
  the cost of every site. A short grace window, scoped to one client process and one key, would conflict
  with "never cache an authorization": a decision for the person, not a build session.
- **Document details in the dialog:** what polkit can show safely, and whether it is worth it when
  the hash cannot be proven.
- **Snap and systemd-sysext** packages.
- **More key types:** RSA 3072/4096, P-384.
- **Fingerprint acceptance:** M0's SPEC acceptance 6 on a machine with a reader.
- **Composed RSA-PSS:** `CKM_SHA256_RSA_PKCS_PSS` and peers (`CKM_RSA_PKCS_PSS` is in M4), once a
  target client needs them.
- **Refuse the encrypted kinds:** an administrator setting, deferred by M4's SPEC; an organisation
  may prefer no key over a weaker one. Not in the first release (`docs/decisions.md`).
- **Key loss:** what happens to the keys when the disk dies (no export by design). Listing, deleting
  and replacing are in M3.
- **Keys born in the TPM:** `C_GenerateKeyPair` and a CSR, so the key never exists outside the TPM
  (`fixedTPM`, `fixedParent`), as in Windows Hello. The FNMT Configurador cannot generate the key
  in a generic PKCS#11 token; the remaining routes are in `docs/reports/fnmt-configurador.md`.
- **PCR policy with signed policies** (`PolicyAuthorize`, `systemd-pcrlock`): keys that survive
  updates but refuse a foreign boot. Only once lost keys can be recovered (M4 has no PCR policy).
- **Presence without polkit:** the service talking to `fprintd` or a FIDO key directly, so the
  barrier does not depend on the system PAM stack.
