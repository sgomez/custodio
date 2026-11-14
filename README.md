# Custodio

A Linux system service that keeps your signing keys out of your reach and asks you through
polkit before every signature.

A key in a `.p12` file or an NSS database can be used by any process running as you, an AI agent
with a shell included, without you noticing. Custodio imports the `.p12` into a service with its
own uid, so your processes can ask it to sign but cannot read or copy the key. Every signature,
import, deletion and certificate replacement needs your approval for that one call, and leaves an
entry in the journal. Each key belongs to the user who imported it.

Programs use it as a PKCS#11 token: Firefox, LibreOffice and anything else that speaks PKCS#11.
Keys are RSA 2048 or ECDSA P-256.

It stops a process running as you from signing by mistake. It does not protect against an attacker
running as the same uid, against root, or your intent: the dialog cannot prove what is being
signed. What it protects, from whom and what it leaves out is in the [threat model](docs/threat-model.md); to
report a vulnerability, see [SECURITY.md](SECURITY.md). Roadmap in [docs/milestones.md](docs/milestones.md); what the first public release contains is in the
[release notes](docs/release-notes-v0.8.0.md).

## Names

- System D-Bus name: `com.rfirma.Custodio1`
- polkit actions: `com.rfirma.custodio.sign`, `com.rfirma.custodio.import-certificate`,
  `com.rfirma.custodio.delete-certificate`, `com.rfirma.custodio.replace-certificate`

## Installing and removing

Administrators: see [docs/install.md](docs/install.md) for installing on each supported system, the system bus
requirement, upgrading, what removal leaves behind, and the journal setting the audit trail needs.

## Using it

Import a `.p12` file. The command asks for the file's password on the terminal, then polkit asks you to approve:

```console
$ custodio import --id ana ana.p12
Imported key 'ana' (ecdsa-p256).
Storage: encrypted-host. This key is weaker than a TPM key: this machine has no TPM, so the key is a file encrypted with the host key. Root, and anyone with a copy of /var/lib, can use it.
Now delete the original file: it still holds your private key.
  shred -u ana.p12   (or remove it with your file manager and empty the trash)
```

Delete the original after the import, as it says: whoever can read that file can use the key without Custodio. If you
lose the key in Custodio, only the original `.p12` brings it back; Custodio cannot export it.

`custodio list` shows your keys, each with its storage kind:

```console
$ custodio list
id: ana
  type: ecdsa-p256
  kind: encrypted-host
  note: This key is weaker than a TPM key: this machine has no TPM, so the key is a file encrypted with the host key. Root, and anyone with a copy of /var/lib, can use it.
  subject: CN=custodio test p256
  valid until: 2126-10-03T16:05:48Z
```

`custodio delete <key id>` asks you to type `yes` and then polkit. You only see and sign with your own keys. Over SSH or on
a console without a graphical polkit agent, `import` and `delete` ask for the password on the terminal. Details in
`man custodio`.

```console
$ custodio delete ana
Deleted key 'ana'.
$ custodio list
You have no keys in the custodio service.
```

### Storage kinds

Every key has one of three kinds, and `custodio list` shows it:

- `tpm`: the private key is inside the TPM and cannot be copied out of it, not even by root. Whoever has the running
  machine can still ask the TPM to sign, which is why every signature goes through polkit.
- `encrypted-tpm`: a file in `/var/lib/custodio`, encrypted with a key bound to this machine's TPM. The service
  decrypts it in its memory to sign, so root can use it while the machine runs.
- `encrypted-host`: a file in `/var/lib/custodio`, encrypted with a key of this host, for a machine with no TPM.
  The service decrypts it in its memory to sign; root, and anyone with a copy of `/var/lib`, can use it.

Import falls back to the encrypted kinds without asking: for your own certificate a working import beats a refusal. It
is not silent, because the command prints the kind, as above, and `custodio list` shows it for every key later. A
`tpm` key is only possible on a machine whose TPM supports the key type (`docs/api.md`, "TPM capabilities").

## Registering your browsers

Programs sign through the PKCS#11 module, which p11-kit loads where the system supports it. Firefox keeps its own
list of modules in each profile, so it must have Custodio registered. Close Firefox and run, as yourself (not as root
and not with `sudo`: it writes into your home):

```console
$ custodio register
Firefox /home/ana/.mozilla/firefox/abcd1234.default-release: registered
Firefox (snap) /home/ana/snap/firefox/common/libcustodio_pkcs11.so: copy placed
Firefox (snap) /home/ana/snap/firefox/common/.mozilla/firefox/efgh5678.default: registered
```

It finds the profiles of Firefox, its derivatives and the Firefox snap, and prints what it did in each. Run it again
whenever you like: what is already registered stays as it is. A profile that a running browser holds is skipped and the
command exits with an error that names it; close the browser and run it again.

To remove the registration, run this before you uninstall the package:

```console
$ custodio register --remove
Firefox /home/ana/.mozilla/firefox/abcd1234.default-release: removed 1 entry
Firefox (snap) /home/ana/snap/firefox/common/.mozilla/firefox/efgh5678.default: removed 1 entry
Firefox (snap) /home/ana/snap/firefox/common/libcustodio_pkcs11.so: copy removed
```

Always use these two commands. Do not load the module through Firefox's "Browse" button in the device manager: the
button goes through the document portal and the snap is then denied access to the file.

### Limits

- The Firefox snap route is not a supported snapd interface. The snap is given a copy of the module and a socket that
  its confinement happens to allow; a snapd update may close it. The [threat model](docs/threat-model.md) says what
  that depends on and how it shows.
- Only the Firefox snap is supported: not Chromium, Thunderbird or Firefox as a Flatpak.
- Mozilla's own Firefox build on Fedora and RHEL/Alma uses its bundled NSS and does not see Custodio. Register it by
  hand as [docs/install.md](docs/install.md) ("Firefox") describes. Their packaged Firefox needs nothing: the
  system NSS loads p11-kit, which already shows Custodio, and `custodio register` says so and leaves those profiles alone.
- TLS client authentication with a Custodio key shows one polkit dialog for every signature, which can be several for
  one page.
- A lost key needs the original `.p12`.

## Full-disk encryption

Custodio keeps its keys under `/var/lib/custodio`. A `tpm` key cannot be copied out of the TPM, but whoever takes the
machine can still ask the TPM to sign with it, and the other kinds (`encrypted-tpm`, `encrypted-host`) are files that
anyone who can read the disk can try to use. Full-disk encryption (LUKS, also under LVM) is what keeps a stolen disk
or a stolen powered-off machine from being used.

When it starts, the service checks, with no external tool, whether the block devices under its state directory include
dm-crypt, and journals the result (`CUSTODIO_STATE_STORAGE`, see [docs/audit.md](docs/audit.md)). `custodio import` and
`custodio list` print a warning on standard error when the result is `not-encrypted`, or `unknown` (a chain the service
cannot read, RAID or dm-integrity it does not classify, a network, overlay or in-memory filesystem, a filesystem's own
encryption such as fscrypt or ZFS native encryption, btrfs). The warning blocks nothing. Encrypt the disk that holds
`/var/lib/custodio` with your distribution's installer or `cryptsetup`; `unknown` on an encrypted disk the service
cannot classify is a reason to look, not proof of a problem. The rules are in `docs/findings/F180.md`.

## Writing a client

Client authors: see [docs/api.md](docs/api.md) for detecting the service (on the host and from a flatpak), every
method with its arguments, bounds, results and errors, the polkit dialogs, ownership, what is journalled, and a
`busctl` example per operation.

## Development

Linux only. Install [mise](https://mise.jdx.dev), rustup and the system packages the package tests
need (Debian/Ubuntu: `rpm libarchive-tools zstd python3-yaml`), activate mise in your shell
(`eval "$(mise activate bash)"` or `zsh`), then once:

```bash
just setup
```

`just` lists every task; `just check` runs the fast checks.
