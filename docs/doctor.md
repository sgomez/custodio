# `custodio doctor`

`custodio doctor` looks at the six things that decide whether Custodio and its fingerprint work on this system, says what it found
and, when something is wrong, what to do. It changes nothing. Run it as the person who will use the fingerprint (not with `sudo`):
two of the checks are about you, and the commands below are run by `scripts/test-docs-fingerprint.sh` as written, on a fixture
system with a fake fprintd.

## Reading the report

Each check prints one line, `STATE  NAME: what was found`, and a `fix:` line under it when the state is not `ok`.

| State | Meaning |
|---|---|
| `ok` | The check passed. |
| `not ok` | The check found a problem; the `fix:` line says what to do. |
| `could not check` | The check could not get an answer (for example, there is no reader to ask). The `fix:` line says what to do first. |

The exit status is 0 unless a polkit include is broken, or one of the last three checks (module in Firefox, persistent journal,
state directory storage) is not `ok`; then it is 1. The first three checks belong to the fingerprint, which is optional, so
they never change the exit status, "could not check" included; a broken include stops every polkit dialog, so it always does.

A system where everything is fine, with the fingerprint turned on:

```console fixture=ok
$ custodio doctor
ok              fingerprint reader: fprintd lists 1 reader
ok              enrolled finger: 1 finger enrolled for you
ok              fingerprint for polkit: active through Custodio's override /etc/pam.d/polkit-1
ok              module in Firefox: no browser profile was found, so there is nothing to register
ok              persistent journal: the journal is persistent (Storage=persistent)
ok              state directory storage: the service's state directory is on an encrypted device
```

## The checks

### fingerprint reader

Asks fprintd how many readers it sees. If it sees none, plug the reader in or enable it in the firmware setup, and check that
libfprint supports it. When fprintd is not installed, the fix names the package of your system (see
[the table of packages](fingerprint.md#when-enable-refuses)).

```console fixture=noreader
$ custodio doctor
not ok          fingerprint reader: fprintd reports no fingerprint reader
                fix: Plug the reader in or enable it in the firmware setup, and check that libfprint supports it (https://fprint.freedesktop.org/supported-devices.html).
could not check enrolled finger: there is no reader to ask (see the line above)
                fix: Fix the reader first, then run 'custodio doctor' again.
not ok          fingerprint for polkit: fingerprint is not active for polkit
                fix: Run: sudo custodio fingerprint enable
ok              module in Firefox: no browser profile was found, so there is nothing to register
ok              persistent journal: the journal is persistent (Storage=persistent)
ok              state directory storage: the service's state directory is on an encrypted device
```

### enrolled finger

Asks fprintd whether you have a finger enrolled. Enrol one with your desktop's tools (GNOME: Settings, Users, Fingerprint
Login) or with `fprintd-enroll`. Without a reader the check says `could not check`, as above.

```console fixture=nofinger
$ custodio doctor
ok              fingerprint reader: fprintd lists 1 reader
not ok          enrolled finger: no finger is enrolled for you
                fix: Enrol one in the desktop's settings (GNOME: Settings, Users, Fingerprint Login) or run 'fprintd-enroll'.
not ok          fingerprint for polkit: fingerprint is not active for polkit
                fix: Run: sudo custodio fingerprint enable
ok              module in Firefox: no browser profile was found, so there is nothing to register
ok              persistent journal: the journal is persistent (Storage=persistent)
ok              state directory storage: the service's state directory is on an encrypted device
```

### fingerprint for polkit

Looks at `/etc/pam.d/polkit-1`. `not ok` with `sudo custodio fingerprint enable` as the fix means the override is not there (the
output above). Other states: the file is someone else's (the fix says to look at who owns it); the fingerprint is on for the whole
system, in which case `sudo` and the login ask for the finger too; and a broken include, which is the one that exits with status 1:

```console fails=yes fixture=brokeninclude
$ custodio doctor 2>&1
not ok          fingerprint for polkit: Custodio's override /etc/pam.d/polkit-1 includes /usr/lib/pam.d/polkit-1, which is missing: no polkit dialog can authenticate
                fix: Reinstall polkit (it ships that file), or remove the override: sudo custodio fingerprint disable
ok              fingerprint reader: fprintd lists 1 reader
ok              enrolled finger: 1 finger enrolled for you
ok              module in Firefox: no browser profile was found, so there is nothing to register
ok              persistent journal: the journal is persistent (Storage=persistent)
ok              state directory storage: the service's state directory is on an encrypted device
custodio doctor: a polkit include is broken (the first line of the report)
Do what its fix says, then run 'custodio doctor' again.
```

### module in Firefox

Looks for your Firefox profiles (the normal install and the snap) and whether Custodio's module is registered in each. With no
profile it says so, as in every report above. Otherwise the fix is `custodio register`, or, after Firefox moved or the snap was
updated, the same command again. A stale copy of the module in the snap's directory is replaced by it.

### persistent journal

Custodio's audit trail is in the system journal. The check reads `journald.conf` and its drop-ins. `Storage=persistent` is `ok`.
`Storage=auto` with no `/var/log/journal`, `Storage=volatile` and `Storage=none` are `not ok`: the entries are lost at reboot, or
at once with `none`, the audit entries of the signatures included. The fix names the line to set, or the directory to create
(`mkdir -p /var/log/journal`), and the drop-in `/etc/systemd/journald.conf.d/50-persistent.conf` with `Storage=persistent`.

### state directory storage

Asks the service whether its state directory (where the keys live) is on an encrypted device. `unknown`, which the service
answers when it cannot tell, is not `ok`: the report says so, with the reason the service gave when it gave one, and the fix is
full-disk encryption (see the [README](../README.md#full-disk-encryption)). This is the other way to exit with status 1:

```console fails=yes fixture=plainstorage
$ custodio doctor 2>&1
ok              fingerprint reader: fprintd lists 1 reader
ok              enrolled finger: 1 finger enrolled for you
not ok          fingerprint for polkit: fingerprint is not active for polkit
                fix: Run: sudo custodio fingerprint enable
ok              module in Firefox: no browser profile was found, so there is nothing to register
ok              persistent journal: the journal is persistent (Storage=persistent)
not ok          state directory storage: the service's state directory is not known to be on an encrypted device (the service gave no reason it knows)
                fix: Update the service if it is old, or use full-disk encryption (README.md#full-disk-encryption).
custodio doctor: a check that decides the exit status is not satisfied (checks 4 to 6)
Do what the fix under it says, then run 'custodio doctor' again.
```

When the service is not running, or does not answer, this check and the one on the journal say `could not check` and the exit status
is 1: start the service (`systemctl start custodio.service`) and run `custodio doctor` again.
