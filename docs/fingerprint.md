# Fingerprint for polkit dialogs

Custodio asks polkit before every signature. `custodio fingerprint` lets a finger answer those dialogs. The commands below are run
by `scripts/test-docs-fingerprint.sh` as written, on a fixture system with a fake fprintd; the lines under each command are what it
prints.

## Turn it on

Enrol a finger first with your desktop's tools (GNOME Settings, Users, Fingerprint Login; or `fprintd-enroll` from a terminal).
Then:

```console
$ sudo custodio fingerprint enable
Wrote /etc/pam.d/polkit-1. Every polkit dialog (the ones that ask for your password, Custodio's among them) now accepts a finger.
A wrong finger, or 10 s without a touch, falls back to the password. sudo and the login are unchanged.
To undo it: sudo custodio fingerprint disable
```

## What it changes

One file, `/etc/pam.d/polkit-1`, and nothing else. This is the file, byte for byte:

```text
#%PAM-1.0
# Written by 'custodio fingerprint enable'. Remove it with 'sudo custodio fingerprint disable'.
# If you edit this file, Custodio treats it as yours and will not touch it again.
auth     [success=done default=ignore] pam_fprintd.so max-tries=1 timeout=10
auth     include /usr/lib/pam.d/polkit-1
account  include /usr/lib/pam.d/polkit-1
password include /usr/lib/pam.d/polkit-1
session  include /usr/lib/pam.d/polkit-1
```

It applies to every polkit action, not only Custodio's: any dialog that asks for your password accepts a finger. It does not touch
`sudo` and it does not touch the login screen: both keep asking for the password. A wrong finger, or ten seconds without a touch,
falls back to the password prompt of the same dialog. Running `enable` again changes nothing.

## Turn it off

```console
$ sudo custodio fingerprint disable
Removed /etc/pam.d/polkit-1. Polkit dialogs ask for the password only.
To turn it on again: sudo custodio fingerprint enable
```

It removes the file only if it is Custodio's. After it the system is as it was before `enable`.

## What the fingerprint does not guarantee

A fingerprint is a convenience, not a stronger proof than the password. It can be copied from surfaces and some readers are
fooled by a copy; whoever can make you touch the reader, or has your finger, can approve a dialog. It never replaces the
password where the password is the only way in (a failed finger always falls back to it). Custodio cannot see which finger or
which reader answered. See the [threat model](threat-model.md) for the full list of what is not guaranteed.

The finger only answers the polkit dialog; every limit of the threat model's "Not guaranteed" list still holds with it:

- The dialog cannot prove what is being signed, and does not show which key or file is involved.
- An audit entry records the uid and pid of the calling program, not a person; the app-id of a flatpak caller is a claim, not an authorization.
- Root can use a `tpm` key; the `encrypted-tpm` and `encrypted-host` kinds protect less, because root can take the key from the service's memory.
- A TPM clear, some firmware updates or a new motherboard lose the keys wrapped by the TPM; import the `.p12` again.
- Deleting a key does not erase its bytes from filesystem blocks, snapshots or backups.
- Ownership follows the numeric uid, so a reused uid owns the old keys.
- SELinux adds no protection: Custodio ships no policy.

## When `enable` refuses

`enable` refuses, changes nothing and exits with status 1. Each message below is exactly what it prints.

Not run as root:

```console fails=yes fixture=debian
$ custodio fingerprint enable 2>&1
custodio fingerprint: this changes a system file and must run as root
Run it again with sudo: 'sudo custodio fingerprint enable' (or 'disable').
```

The file is someone else's (an administrator's own `polkit-1`, or Omarchy's setup, which ships one that already asks for the
finger). Look at who owns it and remove or merge it yourself:

```console fails=yes fixture=debian-foreign
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: /etc/pam.d/polkit-1 exists and is not Custodio's (or is not a regular file); nothing was changed
Look at who owns it ('dpkg -S', 'rpm -qf' or 'pacman -Qo' on that path) and remove or merge it yourself, then run 'sudo custodio fingerprint enable' again.
```

```console fails=yes fixture=omarchy
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: /etc/pam.d/polkit-1 exists and is not Custodio's (or is not a regular file); nothing was changed
Look at who owns it ('dpkg -S', 'rpm -qf' or 'pacman -Qo' on that path) and remove or merge it yourself, then run 'sudo custodio fingerprint enable' again.
```

Fingerprint is already on for the whole system (the global switch), so the override would be redundant. Turn the global switch
off first. On the Debian family it is `pam_fprintd` in `common-auth` (`pam-auth-update`):

```console fails=yes fixture=global-debian
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: fingerprint is already on for the whole system, so this override would be redundant (and might ask for the finger twice after a mismatch); nothing was changed
Turn the global switch off (pam-auth-update, authselect disable-feature with-fingerprint, or your distribution's tool), then run 'sudo custodio fingerprint enable' again.
```

On the Fedora family it is `with-fingerprint` in authselect; on Arch it is `pam_fprintd` in `system-auth`. The message is the same.

The PAM module or fprintd is not installed. The message names the packages of the system:

| System | Packages |
|---|---|
| Debian 13, Ubuntu 26.04 | `libpam-fprintd` and `fprintd` |
| Fedora 44, AlmaLinux 10 | `fprintd-pam` and `fprintd` |
| Arch | `fprintd` |

```console fails=yes fixture=nomodule-debian
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: pam_fprintd.so is not installed; nothing was changed
Install libpam-fprintd and fprintd and run 'sudo custodio fingerprint enable' again.
```

```console fails=yes fixture=nomodule-fedora
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: pam_fprintd.so is not installed; nothing was changed
Install fprintd-pam and fprintd and run 'sudo custodio fingerprint enable' again.
```

```console fails=yes fixture=nomodule-arch
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: pam_fprintd.so is not installed; nothing was changed
Install fprintd and run 'sudo custodio fingerprint enable' again.
```

## The GNOME lock screen on Ubuntu

On GNOME, an enrolled finger may also unlock the lock screen, because GDM and the lock screen use their own PAM file
(`/etc/pam.d/gdm-fingerprint`) and the GNOME setting `org.gnome.login-screen enable-fingerprint-authentication`, not
`polkit-1`. `custodio fingerprint` changes neither. To turn the finger off on the lock screen and the login screen:

```console
$ gsettings set org.gnome.login-screen enable-fingerprint-authentication false
```

The setting of the `gdm` user (the login screen itself) is a separate one, set as that user; that step is untested on Ubuntu
26.04 here.

## Restart Firefox after importing or deleting a key

Firefox reads the list of keys from Custodio's module when it starts. After `custodio import` or `custodio delete`, quit
Firefox completely and start it again, or the new key does not show (or the deleted one still shows) in its certificate dialog.

## Other systems

The commands are the same on every supported system; only the package names differ (the table above). The tests that run this
page use a fixture system and a fake fprintd, so nothing here was tried with a real reader. Debian 13 and AlmaLinux 10 were not
run in a virtual machine; Ubuntu 26.04 is the system the Ubuntu 26.04 guide is written for.
