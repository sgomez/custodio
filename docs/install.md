# Installing and removing Custodio

This page is for administrators. It covers installing the package on each supported system, the
system bus requirement, upgrading, what removal leaves behind, and the journal setting that the
audit trail depends on. For the entries the service writes, see [audit.md](audit.md).

Custodio is one package per family, built from the same files: a `.deb`, an `.rpm` and an Arch
`.pkg.tar.zst`, for x86_64. Installing needs root. The examples use `sudo`; replace the file names
with the ones you downloaded.

## Supported systems

Debian 13, Ubuntu 26.04, Fedora 44, RHEL/Alma 10 and Arch are maintained and tested. Every package
requires systemd 257 or later, for the user-scoped credential calls that the service makes over Varlink.
Older systems, Ubuntu 24.04 among them (it has systemd 255), are not supported and are refused by the package
manager; nothing is installed. The package also needs a running polkit 124 or later
and a system bus that provides `ProcessFD`
(see [Why a bus without ProcessFD is refused](#why-a-bus-without-processfd-is-refused)).

On Debian 13 (systemd 257) with a TPM, the credential service binds a user-scoped credential to PCR 7, verified in
[`docs/findings/F166.md`](findings/F166.md), so the service refuses it and the kind `encrypted-tpm` is unavailable: an
import ends in `CredentialsUnavailable`. RHEL/Alma 10 (also systemd 257) is inferred from that reading, not run.

## Installing

Use the tool of your system, so that dependencies are resolved from your distribution.

### Debian 13

```bash
sudo dpkg -i custodio_0.1.0-1_amd64.deb
```

`dpkg -i` does not fetch dependencies. If it stops because some are missing, run
`sudo apt-get -f install` to install them and finish the configuration.

### Ubuntu 26.04

```bash
sudo apt-get install ./custodio_0.1.0-1_amd64.deb
```

`apt-get install` with a path resolves the dependencies. The leading `./` is required: without it
apt looks for a package of that name in its repositories.

### Fedora 44

```bash
sudo dnf install ./custodio-0.1.0-1.x86_64.rpm
```

### RHEL and Alma 10

```bash
sudo dnf install ./custodio-0.1.0-1.x86_64.rpm
```

It is the same `.rpm` as on Fedora.

### Arch

```bash
sudo pacman -U custodio-0.1.0-1-x86_64.pkg.tar.zst
```

On Arch, pacman installs a package even when its pre-install script fails, and a hook shipped
in the package does not run on its own first installation. So the first installation only warns
when the bus has no `ProcessFD`, and goes on. Every later upgrade or reinstall is refused by a
pacman hook. The service itself refuses to sign on such a bus, so the first installation is safe,
but fix the bus (see below).

### rpm-ostree

On rpm-ostree systems (Fedora Atomic, Bazzite) layer the `.rpm` and reboot into the new deployment:

```bash
sudo rpm-ostree install ./custodio-0.1.0-1.x86_64.rpm
sudo systemctl reboot
```

rpm-ostree runs the package scripts in a build environment where no system bus is running, so the
bus check prints a notice and does not refuse. The service checks again every time it runs.
`rpm-ostree uninstall custodio` runs no erase scriptlet of the removed package, so it prints no notice
that the keys stay on disk and does not stop the service; reboot after it. The keys stay, as described in
[Removing and purging](#removing-and-purging).

## TPM2 Software Stack

Custodio links the TPM2 Software Stack (`libtss2-esys`, `libtss2-tctildr`, `libtss2-mu`) and loads the
device TCTI (`libtss2-tcti-device`) at run time to reach `/dev/tpmrm0`. The package declares these
dependencies, so your package manager installs them; nothing else is needed. The `tss` group, which the
service unit names so that the service may open the TPM, comes from the TPM package of the family
(`tpm-udev` on Debian and Ubuntu, `tpm2-tss` on Fedora, RHEL/Alma and Arch). The `systemd` bound is what
`systemd-creds` needs: every package needs the user-scoped calls of systemd 257.

- deb: `libtss2-esys-3.0.2-0t64`, `libtss2-tctildr0t64`, `libtss2-mu-4.0.1-0t64`, `libtss2-tcti-device0t64`, `libtss2-rc0t64`, `tpm-udev`, `systemd (>= 257)`
- rpm: `tpm2-tss`, `systemd >= 257`
- arch: `tpm2-tss`, `systemd>=257`

On the `.deb`, `libtss2-rc0t64` is listed because systemd loads it by `dlopen` when it seals a credential
to the TPM, so no link names it. Ubuntu only recommends it, so an installation without recommends would
lack it and `systemd-creds` would fail.

## Firefox

Firefox finds the module by itself only where the system NSS loads p11-kit's proxy. Fedora and RHEL/Alma
do: their NSS reads `/etc/crypto-policies/back-ends/nss.config`, which loads `p11-kit-proxy.so`, and the proxy
loads every module in `/usr/share/p11-kit/modules/`, Custodio's among them. Arch's and Debian's NSS read no
such file, so there Firefox needs the module registered by hand, once per profile. Checked on Arch (Omarchy 4);
not tried on Debian or Ubuntu.

With Firefox closed:

```bash
modutil -dbdir sql:<profile directory> -add Custodio -libfile /usr/lib/custodio/libcustodio_pkcs11.so
```

The profile directory is the "Root Directory" shown in `about:profiles`. `modutil` is in Arch's `nss` package
and in Debian's `libnss3-tools`. The same can be done in Firefox under Settings > Privacy & Security > Security
Devices > Load, with the same path (not tried). Firefox's derivatives (LibreWolf, Thunderbird and others) take
the same command with their own profile directory (not tried). A Flatpak or snap Firefox does not see the
module at all.

## Why a bus without ProcessFD is refused

polkit identifies the process that asks for a signature from what the bus tells it. Newer buses
(`dbus-broker`, and `dbus-daemon` 1.16 or later) return a `ProcessFD` in the connection credentials: a
pidfd that stays bound to that process. Without it polkit falls back to a plain PID, and a PID can be
reused. A process could then race the check and be authorized as another one. That would defeat the
polkit prompt that Custodio asks for on every signature.

So a bus without `ProcessFD` is refused twice:

- The package checks at install time, before it changes anything, and the installation fails with a message
  that points here. The check tests the capability, not the name or version of the daemon.
- The service checks at run time and refuses to sign, whatever the package check saw. This is what keeps
  the first installation on Arch, and an installation with no bus running, safe.

The install-time check can end in four ways, and each message points to this page:

- `no system bus is running, so ProcessFD support was not checked`: a chroot, an image build or rpm-ostree.
  The installation goes on with a notice. The service refuses to sign until a bus with `ProcessFD` runs.
- `neither busctl nor dbus-send is installed`: the check has no tool to ask the bus. Install `systemd` (for
  `busctl`) or `dbus` (for `dbus-send`) and retry.
- `the system bus could not be queried for ProcessFD`: the tool failed for a reason other than a missing
  bus. The message includes its output. Fix that, for example a bus that is stuck, and retry.
- `the system bus does not provide ProcessFD`: switch to a bus that does, such as `dbus-broker` or
  `dbus-daemon` 1.16 or later. None of the supported systems is in this case with its default bus.

To check by hand, on a booted system:

```bash
busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus \
    GetConnectionCredentials s org.freedesktop.DBus
```

The reply must contain `"ProcessFD" h`.

## Upgrading

Install the new package with the same command as for a first installation. The state directory and the
`custodio` account stay as they are, and no manual step is needed. If the service was running it is restarted
once the new files are in place, so the service that answers afterwards is the new binary. If it was not
running, D-Bus activation starts the new one at the next call.

A signature that is waiting for polkit at that moment fails closed: the restart ends the request, the caller
gets an error, and nothing is signed. A signature never succeeds without its journal entry. Ask again after the
upgrade; the authorization of the earlier request is not kept, because every signature calls polkit.

## Removing and purging

Removal (`apt-get remove`, `dnf remove`, `pacman -R`, `rpm-ostree uninstall`) stops the service and
removes every packaged file. On Debian and Ubuntu, `apt-get purge` is the same as removal. Both leave
three things behind, on purpose:

- the state directory `/var/lib/custodio`, whose real directory is `/var/lib/private/custodio`;
- the signing keys inside it. They cannot be exported or recreated, so no script deletes them;
- the `custodio` account, because the keys belong to its uid.

The package prints a notice that says so, except on rpm-ostree, where `uninstall` runs no scriptlet and
so prints no notice. Reinstalling finds the keys where they were.

To destroy the keys deliberately, after removal, on purpose and knowing the keys are gone for good:

```bash
sudo systemctl stop custodio.service
sudo rm -rf --one-file-system /var/lib/private/custodio
sudo rm -f /var/lib/custodio
sudo userdel custodio
```

This is irreversible: the keys cannot be recovered from Custodio, and you need the original `.p12` files
to import them again. Deleting a file is not secure erasure. The data may stay on the disk, in snapshots,
backups or the wear-levelling area of an SSD. If the keys must not be recoverable, use full-disk
encryption and destroy its key, or sanitize the device.

## Journal storage and the audit trail

Every signing request writes one entry to the systemd journal, whatever the result. That is the audit trail.
If the journal is volatile, it lives in `/run/log/journal` and is lost at reboot, and so is the trail.
Check how your system stores it:

```bash
journalctl --disk-usage
ls -d /var/log/journal
grep -rs '^Storage' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/
```

If `/var/log/journal` exists, the journal is persistent. The default `Storage=auto` is persistent only when
that directory exists, and some distributions do not create it. To make it persistent, set
`Storage=persistent` in `/etc/systemd/journald.conf` (or a file in `/etc/systemd/journald.conf.d/`) and
restart `systemd-journald`.

The package does not change journald's configuration; that is the administrator's choice. For the queries, see
[audit.md](audit.md).
