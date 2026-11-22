# `custodio doctor`

`custodio doctor` looks at what decides whether Custodio and its fingerprint work on this system, says what it found and, when
something is wrong, what to do. It changes nothing. Run it as the person who will use the fingerprint (not with `sudo`): two of the
checks are about you. The commands below are run by `scripts/test-docs-fingerprint.sh` as written, on a fixture system with a fake
fprintd.

## Reading the report

The checks are grouped under three headings. Each check is one line: its state, its name and what was found. Under a line that is
not `ok` comes a `Fix:` line with what to do; a few add a line that says what the problem means, or a `Warning:` with its own `Fix:`
(see [polkit](#polkit)). When something is wrong, the report ends with how many problems and warnings it found.

| State | Meaning |
|---|---|
| `ok` | The check passed. |
| `FAIL` | The check found a problem; the `Fix:` line says what to do. |
| `warn` | It works, with a risk you should know of; the `Fix:` line says how to remove it. It does not change the exit status. |
| `?` | The check could not get an answer (for example, there is no reader to ask). The `Fix:` line says what to do first. |

The exit status is 0 unless a polkit include is broken, or a check under Browsers or System is `FAIL` or `?`; then it is 1. The
fingerprint is optional, so its checks never change the exit status, `?` included; a broken include stops every polkit dialog, so
it always does.

A system where everything is fine, with the fingerprint turned on:

```console fixture=ok
$ custodio doctor
Fingerprint (optional)
  ok    reader       1 reader
  ok    finger       1 finger enrolled
  ok    polkit       on
Browsers
  ok    profiles     none found, nothing to register
System
  ok    journal      persistent
  ok    key storage  on an encrypted disk
```

## The checks

### reader

Asks fprintd how many readers it sees. If it sees none, plug the reader in or enable it in the firmware setup, and check that
libfprint supports it (<https://fprint.freedesktop.org/supported-devices.html>). When fprintd is not installed, the fix names the
package of your system (see [the table of packages](fingerprint.md#when-enable-refuses)). When fprintd is installed but nothing
answers for it on the bus, or the bus cannot be asked, the state is `?` and the fix is to look at `systemctl status fprintd` (`systemctl status dbus fprintd` when the bus
could not be asked).

```console fixture=noreader
$ custodio doctor
Fingerprint (optional)
  FAIL  reader       none found
        Fix: plug it in or enable it in the firmware; libfprint must support it
  ?     finger       no reader to ask
        Fix: fix the reader first
  FAIL  polkit       off
        Fix: sudo custodio setup fingerprint enable
Browsers
  ok    profiles     none found, nothing to register
System
  ok    journal      persistent
  ok    key storage  on an encrypted disk

3 problems.
```

### finger

Asks fprintd whether you have a finger enrolled. Enrol one with your desktop's tools (GNOME: Settings, Users, Fingerprint Login)
or with `fprintd-enroll`. Without a reader the state is `?`, as above. Over ssh fprintd refuses to say, and the state is `?`, not
`FAIL`: run `custodio doctor` again from the desktop session of the person who will use the finger.

```console fixture=nofinger
$ custodio doctor
Fingerprint (optional)
  ok    reader       1 reader
  FAIL  finger       none enrolled
        Fix: Settings > Users > Fingerprint Login, or fprintd-enroll
  FAIL  polkit       off
        Fix: sudo custodio setup fingerprint enable
Browsers
  ok    profiles     none found, nothing to register
System
  ok    journal      persistent
  ok    key storage  on an encrypted disk

2 problems.
```

### polkit

Looks at `/etc/pam.d/polkit-1`. `off` with `sudo custodio setup fingerprint enable` as the fix means Custodio's file is not there (the
output above). Other states:

- `on`: Custodio's file is there.
- The file is someone else's and asks for the finger (Omarchy's, for example): `ok`, and the line says it is not Custodio's.
- The file is someone else's and does not ask for the finger: `FAIL`, and the fix says to find its owner, because `enable` refuses
  to replace it:

```console fixture=foreign
$ custodio doctor
Fingerprint (optional)
  ok    reader       1 reader
  ok    finger       1 finger enrolled
  FAIL  polkit       off, and /etc/pam.d/polkit-1 is not Custodio's
        Fix: remove or merge it ('dpkg -S', 'rpm -qf' or 'pacman -Qo' name its owner), then: sudo custodio setup fingerprint enable
Browsers
  ok    profiles     none found, nothing to register
System
  ok    journal      persistent
  ok    key storage  on an encrypted disk

1 problem.
```

- The fingerprint is on for the whole system (`common-auth`, `system-auth`, authselect or `/etc/pam.d/sudo`): `ok`, and the line
  names where it is set and says that `sudo` uses the finger too.
- Both the polkit file and `common-auth` ask for the finger: a `Warning:` line (after a wrong finger or no touch the finger is asked
  for twice) with its own `Fix:`: `sudo custodio setup fingerprint disable` when the file is Custodio's, otherwise remove its
  `pam_fprintd.so` line or run `sudo pam-auth-update --disable fprintd`.
- A broken include. Custodio's file includes the polkit file of your system, and without it no polkit dialog can authenticate,
  not even with the password. It is the first line of the report, and the exit status is 1:

```console fails=yes fixture=brokeninclude
$ custodio doctor
Fingerprint (optional)
  FAIL  polkit       /etc/pam.d/polkit-1 includes /usr/lib/pam.d/polkit-1, which is missing
        No polkit dialog works, not even with the password.
        Fix: reinstall polkit, or: sudo custodio setup fingerprint disable
  ok    reader       1 reader
  ok    finger       1 finger enrolled
Browsers
  ok    profiles     none found, nothing to register
System
  ok    journal      persistent
  ok    key storage  on an encrypted disk

1 problem.
```

### profiles

Looks for your browser profiles (Firefox, its snap, Thunderbird and the browsers like them) with the same discovery as
`custodio setup browsers enable`, and prints one line per profile under Browsers: the browser, the profile's directory and, when it is not
`ok`, why. The fix, `custodio setup browsers enable` and then a restart of the browsers, comes once, under the last profile that needs it. With
no profile there is one line, `profiles`, as in every report above.

A profile is `FAIL` when the module is not registered in it, when it is registered at a path that no longer exists, or, for the
Firefox snap, when the snap's own copy of the module is missing or older than the installed module. A system where NSS loads the
p11-kit proxy is `ok` without registration.

A profile is `?` when its `pkcs11.txt`, or the snap's copy of the module, cannot be read; the line says which file and why, and the
fix is to correct that and run `custodio doctor` again. The single `profiles` line is `?` when the profiles cannot be looked for: a
`profiles.ini` that cannot be read or parsed (the line names it; fix or remove it), or `HOME` not set (run `custodio doctor` as
yourself, in a session where `HOME` is set). A `?` here counts against the exit status, as a `FAIL` does.

### journal

Custodio's audit trail is in the system journal. The check reads `journald.conf` and its drop-ins. `Storage=persistent` is `ok`.
`Storage=auto` with no `/var/log/journal`, `Storage=volatile` and `Storage=none` are `FAIL`: the entries are lost at reboot, or at
once with `none`, the audit entries of the signatures included. The fix creates the directory, or names the line to change, or
the drop-in `/etc/systemd/journald.conf.d/50-persistent.conf` with `Storage=persistent` under `[Journal]`, and then restarts
systemd-journald. It reads the files itself, so it does not need the service; a file it cannot read makes the state `?`.

### key storage

Asks the service whether its state directory, `/var/lib/custodio`, where the keys live, is on an encrypted disk. Not encrypted is
`warn`, not a failure: Custodio works, but whoever takes the machine can use your keys (a tpm key cannot be copied, but it can be
used on this machine). The risk is yours to accept, so it does not change the exit status. The fix is full-disk encryption (LUKS),
which most installers offer; `cryptsetup` does it on an existing system.

When the service cannot tell, the state is `warn` too, with the reason it gave in a few words and its code (see [api.md](api.md))
under it, and a fix for that reason:

```console fixture=plainstorage
$ custodio doctor
Fingerprint (optional)
  ok    reader       1 reader
  ok    finger       1 finger enrolled
  FAIL  polkit       off
        Fix: sudo custodio setup fingerprint enable
Browsers
  ok    profiles     none found, nothing to register
System
  ok    journal      persistent
  warn  key storage  cannot tell if encrypted
        The service gave no reason.
        Fix: update the service, or use disk encryption (LUKS)

1 problem, 1 warning.
```

When the service gives a reason, the report says what it means, and the fix changes with it:

```console fixture=plainreason
$ custodio doctor
Fingerprint (optional)
  ok    reader       1 reader
  ok    finger       1 finger enrolled
  FAIL  polkit       off
        Fix: sudo custodio setup fingerprint enable
Browsers
  ok    profiles     none found, nothing to register
System
  ok    journal      persistent
  warn  key storage  cannot tell if encrypted
        Not on a single disk (tmpfs, overlay, btrfs or network) (not-block-filesystem).
        Fix: move it to ext4, xfs or similar, or use disk encryption (LUKS)

1 problem, 1 warning.
```

The reasons the service can give are in [api.md](api.md). When the service is not running, or does not answer, the state is `?`
and the exit status is 1: check that the package is installed and the service runs (`systemctl status custodio.service`), then
run `custodio doctor` again.
