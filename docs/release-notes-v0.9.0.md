# Custodio v0.9.0 — release notes

This release lets a finger answer the polkit dialogs, and adds a command that checks the system. Custodio still keeps your
signing keys in a service with its own uid and asks you through polkit before every signature. What it is, and what it protects
you from, is in the [README](../README.md) and the [threat model](threat-model.md). The previous release is described in
[the notes of the first public release](release-notes-v0.8.0.md).

## Supported systems

- Debian 13
- Ubuntu 26.04
- Fedora 44
- RHEL/Alma 10
- Arch

x86_64, one package per family (`.deb`, `.rpm`, Arch `.pkg.tar.zst`). Each needs systemd 257 or later, polkit 124 or
later and a system bus that provides `ProcessFD`. [docs/install.md](install.md) has the install command for each.

Debian 13 and Alma 10 were not run in a VM with a fingerprint sensor: the runs with a virtual sensor were made on
Ubuntu 26.04, Fedora 44, Bazzite and Omarchy. What is said of Debian 13 and Alma 10 comes from installing their packages
and from the container runs of the test suite; where their polkit keeps its PAM file was not checked.

## What is new

- **`custodio setup`.** The setup commands are grouped under one command. `register` became
  `setup browsers enable` (with `--module`); `register --remove` became `setup browsers disable`, and
  `register --refresh-only` became `setup browsers refresh`. `fingerprint` moved under `setup`:
  `setup fingerprint enable` and `disable`. The old names are not commands any more and have no alias.
- **`custodio setup fingerprint enable` and `disable`.** One command writes `/etc/pam.d/polkit-1` so that a finger answers
  every polkit dialog, not only Custodio's (three tries in 30 s, then the password), and one removes it. It refuses rather than guesses on a system it does not know,
  and never touches a file it did not write. See [docs/fingerprint.md](fingerprint.md).
- **`custodio doctor`.** It checks the reader, the enrolled finger, the PAM file, the Firefox registration, the journal and
  the storage, tells you what is wrong and what to do, and changes nothing. See [docs/doctor.md](doctor.md).
- **Shell completions** for bash, zsh and fish, shipped in every package. They ask nothing of polkit and fail silently.
- **Decrypted keys stay out of swap and core dumps.** custodiod sets its core limit to 0 and clears its dumpable flag when it
  starts, so a crash leaves no core file and no apport or systemd-coredump report with a key in it, and its unit sets
  `LimitCORE=0` and `MemorySwapMax=0`. The `encrypted-tpm` and `encrypted-host` kinds still need encrypted swap and an encrypted
  hibernation image; see [the threat model](threat-model.md#not-guaranteed).
- **Clearer errors and messages** from the API and the journal, and a guide for Ubuntu 26.04 that goes from the package to a
  signature: [docs/guide-ubuntu-2604.md](guide-ubuntu-2604.md).

## Firefox needs a restart

Firefox reads the list of keys from Custodio's module when it starts. After `custodio import` or `custodio delete`, quit Firefox
completely and start it again, or the new key does not show (or the deleted one still shows) in its certificate dialog.

## Known limits

The limits are in the [threat model](threat-model.md#not-guaranteed). In short for this release: the finger answers every polkit
action, not only Custodio's; a finger is a weaker secret than a password; a finger at the machine can approve a request that
came over ssh; the login and lock screens are not Custodio's; if the vendor PAM file vanishes, polkit's password path breaks and
only `custodio doctor` notices. The limits of the previous release stand, including that the Firefox snap route is not a
supported snapd interface.

## Upgrading

An upgrade changes no key and no file in the state directory. `custodio setup fingerprint` is off until you run `enable`. If you
turned the finger on with 0.8.0, the finger keeps its one try in 10 s: `sudo custodio setup fingerprint disable`, then
`sudo custodio setup fingerprint enable`, gives it three tries in 30 s. After an upgrade, `custodio setup browsers enable` brings the copy of the module the snap runs up to date:

```console
$ custodio setup browsers enable
ok    Firefox         abcd1234.default-release: registered
ok    Firefox (snap)  module copy: placed
ok    Firefox (snap)  efgh5678.default: registered
      Restart the browsers to see the change.
```
