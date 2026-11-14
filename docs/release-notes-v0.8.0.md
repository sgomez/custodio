# Custodio v0.8.0 — release notes

The first public release. Custodio keeps your signing keys in a service with its own uid and asks you through polkit
before every signature. What it is, and what it protects you from, is in the [README](../README.md) and the
[threat model](threat-model.md). A review by someone outside the project follows this release, so it is `v0.8.0`
and not 1.0.

## Supported systems

- Debian 13
- Ubuntu 26.04
- Fedora 44
- RHEL/Alma 10
- Arch

x86_64, one package per family (`.deb`, `.rpm`, Arch `.pkg.tar.zst`). Each needs systemd 257 or later, polkit 124 or
later and a system bus that provides `ProcessFD`; the package manager refuses an older system and installs nothing.
[docs/install.md](install.md) has the install command for each.

## What is new since M5

- **The Firefox snap.** The service listens on a socket for the Firefox snap (`/run/snap.firefox/custodio.sock`), and
  the PKCS#11 module copy that the snap runs uses it. The service reads the label of the connecting process and accepts
  the Firefox snap's alone. Entries from this route say `socket` as their transport and carry the peer label
  (see [audit.md](audit.md)).
- **`custodio register`.** One command registers the module in the profiles of Firefox, its derivatives and the Firefox
  snap, and `custodio register --remove` undoes it. Run it as yourself, with the browser closed; its output is shown below.
- **Copies that stay current.** A package upgrade replaces the module but not the copy the snap runs. `custodio register`
  refreshes every stale copy, and two user units shipped by the package do it at login and when the installed module
  changes.
- **A warning about a disk that is not encrypted.** The service checks, with no external tool, whether the state
  directory is on dm-crypt, and records the result in the journal. `custodio import` and `custodio list` warn on
  standard error when it is not encrypted or cannot be told.
- **Documents.** The README for users, the threat model, `SECURITY.md`, [docs/install.md](install.md) with the
  registration command, and these notes.

The registration command prints what it did in each profile:

```console
$ custodio register
Firefox /home/ana/.mozilla/firefox/abcd1234.default-release: registered
Firefox (snap) /home/ana/snap/firefox/common/libcustodio_pkcs11.so: copy placed
Firefox (snap) /home/ana/snap/firefox/common/.mozilla/firefox/efgh5678.default: registered
```

## Known limits

The limits are the README's, which says them in full: see [Limits](../README.md#limits). In short: the Firefox snap
route is not a supported snapd interface and a snapd update may close it; only the Firefox snap is supported; Mozilla's
own Firefox on Fedora and RHEL/Alma needs the manual route in [docs/install.md](install.md#firefox); every TLS client
signature shows one polkit dialog; a lost key needs the original `.p12`.

## Upgrading

Keys that an earlier build than M4 stored were **purged**, not migrated: once a build of M4 or later has run, no key file
of the old format remains in the state directory, and those keys are gone from the API. Import them again from the
original `.p12` files. Each purged key left a journal entry with its id, and with its owner for a key stored by
M3 (the M0–M2 layout had no owner), which you can still read
(`CUSTODIO_OPERATION=purge`, see [audit.md](audit.md)). Keys stored by M4 and later builds are kept.

After an upgrade, `custodio register` brings a copy that the snap runs up to date at once (the units do it at the next
login otherwise), and registers nothing that you did not register.
