# Threat model

This is the threat model of Custodio as released. It stands alone: you do not need the milestone specifications to read
it. To report a vulnerability, see [SECURITY.md](../SECURITY.md). For how to use the product, see the [README](../README.md).

## What is protected, and from whom

Custodio keeps the private key of a certificate in a service of its own, under its own uid, and asks you through polkit
before every use of it. The thing it protects is **the use of your keys without your knowledge**. The threat it is
built against is a process running as you, an AI agent with a shell or a script that went wrong included, that signs, imports,
deletes or replaces something **by mistake**, or that looks for ways around the dialog (reading the keyring, finding
a `.p12`). Such a process cannot read or copy the key, cannot sign without a polkit approval for that one call, and cannot
sign without leaving an entry in the journal.

Each key belongs to the uid that imported it. Another uid cannot list it, sign with it, delete it or learn that it exists:
to that caller it looks exactly like a key that does not exist.

## In scope

- **A process of the user that signs by mistake.** Every signature, import, deletion and certificate replacement needs
  a polkit approval for that call. Nothing is cached: an approval is never reused for a later call. None of these
  operations happens without a journal entry, and a process of the user cannot remove or rewrite the entries the service wrote.
- **Another uid.** Ownership follows the uid the bus reports. A caller cannot list, sign with, delete, replace the
  certificate of, or learn whether there is a key of another uid. The service does not try an import's password before polkit
  has approved the call, so import is not a password oracle.
- **Hostile input.** A client may send arbitrary or malformed PKCS#11 input to the module, arbitrary sizes and call
  sequences, and may shape everything the service reads about it, such as the contents and type of `/.flatpak-info` as
  seen through its own mount namespace. The parsers are bounded and fuzzed.
- **Reading the state directory.** Root, a backup of `/var/lib` and a copy of the disk can read what is in
  `/var/lib/custodio`. For a `tpm` key nothing there, alone or with anything else on the disk, lets anyone rebuild the
  private key or use it on another machine, and the TPM's own export commands fail for it.
- **Storage downgrade.** The service never stores a key with weaker protection than the machine can give without saying
  so: an import that needs `encrypted-tpm` fails rather than storing a host-bound credential under that kind, and the kind
  is always visible (`custodio import` prints it, `custodio list` shows it).
- **Firmware updates.** No stored credential is bound to a PCR, so a firmware or `dbx` update does not make a key unusable.
- **Installing where authorization is weak.** Where the system bus lacks `ProcessFD`, polkit falls back to process ids,
  which can be raced. The packages refuse such a system, and the service refuses to sign on one if it was installed anyway.
- **The package lifecycle.** An upgrade, reinstall, removal or purge does not delete, rewrite, re-own or loosen the
  state directory or the key files, and the maintainer scripts, which run as root, do not read, copy or log key material.
- **The Firefox snap socket** (below): a peer that is not the Firefox snap, a call beyond listing and signing, a socket
  replaced by the snap, and a peer that exhausts the service.
- **The registration command** (below): it must not write outside the user's own browser profiles and snap directory.

## Out of scope

Custodio does not defend against:

- **A hostile process running as your uid, outside any sandbox.** It can register its own polkit authentication agent
  and answer the dialog itself, replace the module copy in your home, edit your browser profiles and drive the browser.
- **Root controlling the running machine.** Root can use a key of any kind while the machine runs, and can read an
  `encrypted-tpm` or `encrypted-host` key from the service's memory.
- **Physical access, a compromised kernel,** attacks on the TPM or its bus (interposers, fault injection), firmware TPM
  vulnerabilities and TPM side channels.
- **Tampering with the journal by root** or by members of a group allowed to change journal files; the Linux audit
  subsystem; forwarding entries off the machine.
- **A compromise of snapd, of AppArmor or of the snap's publisher,** and a snap whose confinement was loosened
  (devmode, classic confinement). Escapes from the flatpak sandbox and flaws in `xdg-dbus-proxy`.
- **A hostile package mirror,** the integrity of package downloads, and an administrator who deliberately switches the
  system bus to a daemon that lacks `ProcessFD` after installing.

## Not guaranteed

- **Intent.** The dialog cannot prove what is being signed. The module hashes inside the client's process, so a client
  can hand the service any hash it likes, and the dialog does not show which key or file is involved: you approve "a
  signature" by the calling program.
- **That an entry identifies a person.** It records the uid and pid of the calling process at the time of the call;
  a pid can be reused. Journal rate limiting, a full disk, volatile storage or rotation can drop entries after the service
  submitted them, and any local process can write entries with the same text: only the journal's trusted fields (unit,
  sender uid) show that an entry came from the service. Administrators filter on those fields (`docs/audit.md`).
- **That the app-id is authentic.** For a flatpak caller it is a record of what the caller's filesystem claimed, never an
  authorization. The pid in such an entry is the proxy's.
- **That root cannot use a `tpm` key.** It can: the key has no PIN and no PCR policy, by design, because polkit is the barrier
  to use. Whoever can talk to the TPM and read the state directory can load the key and sign on that machine. They
  cannot copy it.
- **That the encrypted kinds protect as much as a TPM key.** They do not. `encrypted-tpm` and `encrypted-host` are decrypted
  in the service's memory to sign, so root can take the key. An `encrypted-host` key, bound to the host key and not to a TPM,
  protects against almost nothing beyond a copy of the state directory alone: a backup of `/var/lib` or a copy of the disk
  carries the key and the host key together. Import falls back to these kinds without asking.
- **That keys survive a TPM clear.** A TPM clear, some firmware updates of firmware TPMs or a replaced motherboard change the
  TPM's owner hierarchy, and every key wrapped under it is lost. Keys cannot be exported, so the only recovery is importing
  the `.p12` again. Keys bound to the host key are lost with it or with a change of machine id.
- **Erasure.** Deleting a key removes it from the service and its file from the state directory; copies of its bytes
  may survive in filesystem blocks, snapshots and backups.
- **Ownership across uid reuse.** Ownership follows the numeric uid. If an account is removed and its uid is later given
  to someone else, the new account owns the old keys.
- **SELinux confinement.** Custodio ships no SELinux policy. SELinux adds no protection for it.
- **Import.** The `.p12` and its password pass through your session and, once, through the service's memory. If the
  original `.p12` stays on disk, Custodio protects nothing: delete it after importing.
- **Platforms.** `encrypted-tpm` was run end to end on a virtual TPM on Ubuntu 26.04, not on real firmware, and not on
  Fedora or Arch. On Debian 13 (run) and RHEL/Alma 10 (inferred from Debian 13, not run), with systemd 257, the daemon binds user credentials to a PCR when a TPM is present, the
  service refuses them, and the `encrypted-tpm` kind is unavailable. Systems with a systemd older than 257 are not supported.
- **Several dialogs per page.** TLS client authentication signs once per handshake, and every signature asks.

## The Firefox snap socket

The Firefox snap is confined by AppArmor. It cannot call the service on the system bus, and it sees its own base's
`/usr`, not `/usr/lib/custodio`. For it the service listens on one more socket, `/run/snap.firefox/custodio.sock`, and
`custodio register` places a copy of the module in `~/snap/firefox/common/` that connects there. The report that
established this is [docs/reports/firefox-snap.md](reports/firefox-snap.md).

**What the service checks.** On every connection it reads from the kernel the peer's credentials, its pidfd and its security
label, once per connection, and serves the connection only if all three exist and the label is exactly one plain AppArmor
profile of the `firefox` snap in enforce mode. An unconfined process, a process of another snap, a stacked label
(`snap.firefox.firefox//&unconfined`, which is what a user's process gets by entering the profile with `aa-exec`), a child
profile, an SELinux context, a peer with a uid that does not map to the real one: refused before any call, whatever the uid, root
included. The socket offers `ListKeys` and `Sign` only; import, delete and certificate replacement fail as unknown methods and ask
nothing. Every signature asks polkit about the peer itself, pinned by its pidfd, and nothing the peer sends (a pid, uid, label or
name) is trusted. Connections, message size and handshake time are bounded, so a peer cannot stop the service from serving the
bus or other peers.

**The socket cannot be replaced by the snap.** AppArmor lets the snap write in `/run/snap.firefox/`, so the directory is
owned by root, mode 0755, and the service refuses to serve a socket whose directory is not owned by root and writable by
root alone. DAC then stops the snap from replacing the socket.

**The undocumented snapd rule.** The snap can reach the socket because snapd's AppArmor template gives every strict snap
the rule `/run/snap.@{SNAP_INSTANCE_NAME}/** mrwklix` for its own scratch directory. It dates from snapd 2.36.1 (2018). No
snapd documentation promises it, and it is not a supported snapd interface. The supported interfaces cannot carry this: the `dbus`
interface needs a slot that is a snap and a plug from Mozilla, and the `pkcs11` interface is Ubuntu Core only.

**If snapd changes the rule,** the connection from the snap is denied and the module's copy finds no service. Nothing is
exposed: the failure is closed. It shows as **the registered copy sees no slot**: Firefox's security devices list the module and
no token, and no key is offered. It does not show as an error in the service. The end-to-end test on Ubuntu 26.04 is what detects the
day it changes. The same rule would let other strict snaps in, but only the `firefox` snap gets a socket: Chromium, Thunderbird, a
Firefox Flatpak and a parallel instance (`firefox_x`) see no slot.

**What stays true even with the socket working.**

- A compromised Firefox snap, or code that runs inside it, can list your keys and ask for signatures. Each request shows
  a polkit dialog, as on the bus. If you approve a dialog without reading it, you have authorized the snap.
- Inside the snap, the module copy is code in your home. The browser loads it as you, as it loads any module you register,
  so its integrity rests on your account. A hostile process of your uid can replace it (out of scope above).
- The socket itself exposes no more than the bus does to a caller with your uid: listing and signing.

## The registration command

`custodio register` writes into the home of the user who runs it. It touches only the user's own browser profiles
(Firefox, its derivatives and the Firefox snap) and the snap directory `~/snap/firefox/common/`. It refuses to run as root or
under `sudo`, because it would write into a home that is not the invoking user's. It does not edit a profile a running browser
holds (the profile lock) and tells you to close it. It writes the module copy and each profile through a scratch copy and
`rename(2)`, so an interruption leaves the old state or the new one, never a mix. It changes only entries that point to a Custodio
module, and it uses NSS's own tool, `modutil`, to write the NSS database.

A copy of the module left in `~/snap/firefox/common/` after the package is removed is inert: the socket is gone, so the
browser sees no slot. Run `custodio register --remove` before you uninstall to remove it with the registrations. Do not load
the module through the Firefox "Browse" button: it goes through the document portal and the snap is then denied access to the file.

## Full-disk encryption

Without it, whoever takes the machine, or its disk and TPM together, can use the keys: a `tpm` key cannot be copied
out of the TPM, but the TPM will sign with it for whoever holds the machine, and the other kinds are files that anyone who can
read the disk can try to use. Full-disk encryption (LUKS, also under LVM) is what keeps a stolen disk or a stolen powered-off
machine from being used, and it is yours to set up: encrypt the disk that holds `/var/lib/custodio` with your distribution's installer
or `cryptsetup`.

When it starts, the service checks, without an external tool, whether the block devices under its state directory include
dm-crypt, and journals the result. `custodio import` and `custodio list` print a warning on standard error when the result is `not-encrypted` or
`unknown`, and the warning blocks nothing. `unknown` on an encrypted disk the service cannot classify (btrfs, a
filesystem's own encryption, a network filesystem) is a reason to look, not proof of a problem. The rules are in the
[README](../README.md#full-disk-encryption) and `docs/findings/F180.md`.
