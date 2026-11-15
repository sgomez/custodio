Milestone: M6

M6 makes Custodio usable in the browsers most desktop users have, and prepares the public release.
Ubuntu's default Firefox is a snap that cannot reach Custodio: it cannot load a module from the
host's `/usr/lib`, and AppArmor denies its calls to `com.rfirma.Custodio1` on the system bus.
Mozilla's own Firefox builds, and Firefox on Debian and Arch, load no p11-kit module at all, so today
the user registers the module by hand. The route is chosen and tried on a VM; evidence and rejected
alternatives in `docs/reports/firefox-snap.md`:

- **A socket for snaps.** Besides the bus, the service listens on `/run/snap.<snap>/custodio.sock`
  for each known snap: `firefox`, `chromium` and `thunderbird`. The directories are root `0755`,
  created by `tmpfiles.d` (`RuntimeDirectory=` would remove them when the service stops). The socket
  offers only listing and signing, never import or delete. It accepts only a peer whose AppArmor label
  belongs to that snap; unconfined processes keep the bus. Every signature asks polkit with a
  `unix-process` subject built from the peer's pidfd (`SO_PEERPIDFD`) and uid (`SO_PEERCRED`), so
  polkit authorizes Firefox itself, as it does on the bus; the journal entry also records the label.
  Preferred protocol: peer-to-peer D-Bus with the same interface, so the module keeps one client.
- **The module finds the socket.** Inside a snap (`SNAP_INSTANCE_NAME` set) it talks to
  `/run/snap.$SNAP_INSTANCE_NAME/custodio.sock` instead of the bus.
- **A `custodio` command that registers the module in the user's browsers:** the NSS profiles of
  native Firefox and its derivatives (Mozilla's `.deb`, Debian, Arch), and for each snap a copy of the
  module in `~/snap/<snap>/common/` registered in that snap's profile. It can be run again and
  never duplicates an entry. A copy left behind by a package upgrade must not fail silently: the spec
  decides how a stale copy is detected and refreshed.
- **End-to-end on the Ubuntu 26.04 VM target:** a PKCS#11 client run under the Firefox snap's
  confinement (`snap run --shell firefox`, the client in `~/snap/firefox/common/`) lists and signs
  through the socket, and is denied on the bus. The socket rests on a snapd rule that no document
  promises, so this test is what catches it changing. Manual acceptance with the real Firefox snap on
  a desktop VM: TLS client authentication and a signature.
- **Release documents:** the threat model; the warning when the state directory is not on a dm-crypt
  device; a user README that says what Custodio protects against and its limits (the snap route is
  not a supported snapd interface, Firefox Flatpak cannot use it, lost keys need the original `.p12`,
  several dialogs per page in TLS client authentication); release notes. The README explains the
  three storage kinds and what each protects against: a TPM key cannot be copied even by root, while
  `encrypted-tpm` and `encrypted-host` are decrypted in the service's memory to sign. Import keeps
  falling back to them without asking (`docs/decisions.md`); `custodio list` already shows each
  key's kind.

Outside the agents, by a person: the external review of the authorization path, the FFI layer and the
new socket, after these features; publishing the packages; making the repository public; rFirma's
integration in its own repository; and a question on the snapcraft forum about relying on
`/run/snap.<snap>/`.

Earlier milestones are archived in docs/milestones/; build on the code that already exists.
Number this milestone's features from F170.
