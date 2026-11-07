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
signed.

Not ready for use yet: it runs only in test machines until the public release (M6). Roadmap in
[docs/milestones.md](docs/milestones.md).

## Names

- System D-Bus name: `com.rfirma.Custodio1`
- polkit actions: `com.rfirma.custodio.sign`, `com.rfirma.custodio.import-certificate`,
  `com.rfirma.custodio.delete-certificate`, `com.rfirma.custodio.replace-certificate`

## Installing and removing

Administrators: see [docs/install.md](docs/install.md) for installing on each supported system, the system bus
requirement, upgrading, what removal leaves behind, and the journal setting the audit trail needs.

## Using it

```bash
custodio import [--id <key id>] file.p12   # asks for the file password, then polkit
custodio list                              # your keys: id, type, subject, end of validity
custodio delete <key id>                   # asks for confirmation, then polkit
```

You only see and sign with your own keys. Over SSH or on a console without a graphical polkit
agent, `import` and `delete` ask for the password on the terminal. Details in `man custodio`.

Programs sign through the PKCS#11 module, which p11-kit loads where the system supports it; Firefox
sometimes needs it registered by hand ([docs/install.md](docs/install.md), "Firefox").

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
