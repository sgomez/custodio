# Custodio

A Linux system service that holds signing keys imported from a `.p12` file and asks for polkit
authorization on every signature. It shows up as a PKCS#11 token, so any program that speaks
PKCS#11 can use it.

It stops a process running as the user, such as an AI agent with a shell, from signing by mistake.
It does not protect against an attacker running as the same uid, against root, or the user's
intent: the dialog cannot prove what is being signed.

## Names

- System D-Bus name: `com.rfirma.Custodio1`
- polkit actions: `com.rfirma.custodio.sign`, `com.rfirma.custodio.import-certificate`,
  `com.rfirma.custodio.delete-certificate`, `com.rfirma.custodio.replace-certificate`

## Installing and removing

Administrators: see [docs/install.md](docs/install.md) for installing on each supported system, the system bus
requirement, upgrading, what removal leaves behind, and the journal setting the audit trail needs.

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
