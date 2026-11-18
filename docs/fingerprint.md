# Fingerprint for polkit dialogs

Custodio asks polkit before every signature. `custodio fingerprint` lets a finger answer those dialogs. The commands below are run
by `scripts/test-docs-fingerprint.sh` as written, on a fixture system with a fake fprintd; the lines under each command are what it
prints.

## Turn it on

Enrol a finger first with your desktop's tools (GNOME Settings, Users, Fingerprint Login; or `fprintd-enroll` from a terminal).
Then:

```console
$ sudo custodio fingerprint enable
ok    polkit  finger on for every polkit dialog
      A wrong finger, or 10 s without a touch, falls back to the password.
      sudo and the login are unchanged.
      Undo: sudo custodio fingerprint disable
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

It applies to every polkit action, not only Custodio's: any dialog that asks for your password accepts a finger, `pkexec`,
software installation and disk management included, and the actions that ask for an administrator too. Custodio cannot narrow it
to its own actions: PAM has one service for polkit. It does not touch `sudo`, which keeps asking for the password, nor the login
and lock screens, which have their own settings ([below](#the-gnome-lock-screen-on-ubuntu)). A wrong finger, or ten seconds
without a touch, falls back to the password prompt of the same dialog. Running `enable` again changes nothing.

On GNOME, `enable` adds a line about the lock screen; with no reader it still writes the file and warns, with `doctor`'s reader line, that polkit keeps
asking for the password until there is a reader and an enrolled finger.

Run `sudo custodio fingerprint disable` before removing the package.

## Turn it off

```console
$ sudo custodio fingerprint disable
ok    polkit  off, polkit asks for the password only
      Undo: sudo custodio fingerprint enable
```

It removes the file only if it is Custodio's. After it the system is as it was before `enable`.

## What the fingerprint does not guarantee

- **It is weaker than a password.** A fingerprint can be lifted from surfaces and some readers are fooled by a copy; it can be
  taken from a person who is asleep or coerced. If you need the password barrier, keep the fingerprint off. Custodio cannot see
  which finger or which reader answered.
- **It answers every polkit action**, not only Custodio's (above).
- **A finger at the machine can approve a remote request.** On Ubuntu a polkit authentication started from an ssh session also
  asks for the finger, and a touch on the local reader approves it. On Fedora, `pam_fprintd` skips remote sessions.
- **The login and lock screens are not Custodio's.** On Ubuntu, enrolling a finger is enough for the lock screen to accept it,
  with or without the override ([below](#the-gnome-lock-screen-on-ubuntu)). Fedora and Bazzite keep it off through authselect;
  Omarchy uses a separate file.
- **If the vendor file disappears** after `enable` (`/usr/lib/pam.d/polkit-1`, for example moved by a future polkit package), the
  password path of polkit fails while the finger still works. `sudo` is unaffected, so the system can be recovered:
  `sudo custodio fingerprint disable`. `custodio doctor` detects it; nothing watches for it between its runs.
- **Debian 13 and AlmaLinux 10 were not run** in a virtual machine (below). On them `enable` proceeds only when the files are as
  on the systems where it was run, and refuses otherwise.

The other limits of the [threat model](threat-model.md)'s "Not guaranteed" list still hold with a finger: the dialog does not show
which key or what is signed; an audit entry records a uid and pid, not a person; root can use a key; a TPM clear loses the
TPM-wrapped keys; deleting a key does not erase its bytes; a reused uid owns the old keys; SELinux adds nothing; and the `.p12`
you imported stays on disk until you delete it.

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

On the Fedora family it is `with-fingerprint` in authselect:

```console fails=yes fixture=global-fedora
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: fingerprint is already on for the whole system, so this override would be redundant (and might ask for the finger twice after a mismatch); nothing was changed
Turn the global switch off (pam-auth-update, authselect disable-feature with-fingerprint, or your distribution's tool), then run 'sudo custodio fingerprint enable' again.
```

On Arch it is `pam_fprintd` in `system-auth`:

```console fails=yes fixture=global-arch
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: fingerprint is already on for the whole system, so this override would be redundant (and might ask for the finger twice after a mismatch); nothing was changed
Turn the global switch off (pam-auth-update, authselect disable-feature with-fingerprint, or your distribution's tool), then run 'sudo custodio fingerprint enable' again.
```

On Arch the global switch can also be `pam_fprintd` in `/etc/pam.d/sudo`. On Debian and Ubuntu,
`sudo pam-auth-update --disable fprintd` turns it off.

The vendor file `/usr/lib/pam.d/polkit-1`, which the override includes, is missing or is not a regular file (on a system where
polkit keeps it elsewhere, such as an untested one):

```console fails=yes fixture=novendor-debian
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: /usr/lib/pam.d/polkit-1 is missing or is not a regular file, so the override has nothing to include; nothing was changed
Check that polkit is installed and where its PAM file is ('rpm -ql polkit' or 'dpkg -L polkit'), and report it if it is elsewhere.
```

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

```console fails=yes fixture=nofprintd-debian
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: fprintd is not installed; nothing was changed
Install libpam-fprintd and fprintd and run 'sudo custodio fingerprint enable' again.
```

```console fails=yes fixture=nomodule-ubuntu
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: pam_fprintd.so is not installed; nothing was changed
Install libpam-fprintd and fprintd and run 'sudo custodio fingerprint enable' again.
```

```console fails=yes fixture=nomodule-fedora
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: pam_fprintd.so is not installed; nothing was changed
Install fprintd-pam and fprintd and run 'sudo custodio fingerprint enable' again.
```

```console fails=yes fixture=nomodule-alma
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: pam_fprintd.so is not installed; nothing was changed
Install fprintd-pam and fprintd and run 'sudo custodio fingerprint enable' again.
```

```console fails=yes fixture=nomodule-arch
$ sudo custodio fingerprint enable 2>&1
custodio fingerprint: pam_fprintd.so is not installed; nothing was changed
Install fprintd and run 'sudo custodio fingerprint enable' again.
```

`disable` refuses, and changes nothing, when the file is not Custodio's:

```console fails=yes fixture=debian-foreign
$ sudo custodio fingerprint disable 2>&1
custodio fingerprint: /etc/pam.d/polkit-1 is not Custodio's (or is not a regular file); nothing was changed
Find who owns it with 'dpkg -S', 'rpm -qf' or 'pacman -Qo' on that path, and remove it yourself if you mean to.
```

## The GNOME lock screen on Ubuntu

On GNOME, an enrolled finger may also unlock the lock screen, because GDM and the lock screen use their own PAM file
(`/etc/pam.d/gdm-fingerprint`) and the GNOME setting `org.gnome.login-screen enable-fingerprint-authentication`, not
`polkit-1`. `custodio fingerprint` changes neither. To turn the finger off on the lock screen:

```console
$ gsettings set org.gnome.login-screen enable-fingerprint-authentication false
```

The login screen reads the same setting of the `gdm` user, a separate one set as that user; that step was not tested on Ubuntu
26.04, so this page does not show it.

## Restart Firefox after importing or deleting a key

Firefox reads the list of keys from Custodio's module when it starts. After `custodio import` or `custodio delete`, quit
Firefox completely and start it again, or the new key does not show (or the deleted one still shows) in its certificate dialog.

## Other systems

The commands are the same on every supported system; only the package names differ (the table above). The tests that run this
page use a fixture system and a fake fprintd. Ubuntu 26.04, Fedora 44, Bazzite and Arch with Omarchy were run (Ubuntu 26.04 in a
virtual machine with a virtual fingerprint sensor); Debian 13 and AlmaLinux 10 were not run in a virtual machine, and what this
page says of them comes from their packages' files.
