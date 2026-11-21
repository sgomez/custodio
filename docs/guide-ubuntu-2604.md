# Custodio on Ubuntu 26.04: from the package to your first signature

This guide takes you from nothing to a key that Firefox uses to sign, and back again, on Ubuntu 26.04 with the GNOME desktop. Every
command in a `console` block is run, as written, by `scripts/test-docs-guide.sh` on a fixture system (the real `dpkg` and the real
`custodio` on private buses); the lines under a command are what it prints. Steps only a person can do (touching the reader,
exporting a file from Firefox, signing in to a site) are prose. Home directory names below are `/home/ana`: yours is your own.

## 1. Install the package

Download `custodio_0.9.0-1_amd64.deb` to the directory you are in, then:

```console
$ sudo apt-get install ./custodio_0.9.0-1_amd64.deb
custodio: Custodio's dialogs ask for your password; the fingerprint is off.
custodio: to let a finger answer them, and every other polkit dialog, run: sudo custodio setup fingerprint enable
custodio: to check the setup at any time, run: custodio doctor
```

`apt-get` prints its own progress too; the lines above, which start with `custodio:`, are the package's own notice, shown on a first install only.

## 2. Check the system

```console fails=yes
$ custodio doctor
Fingerprint (optional)
  ok    reader          1 reader
  ok    finger          1 finger enrolled
  FAIL  polkit          off
        Fix: sudo custodio setup fingerprint enable
Browsers
  FAIL  Firefox         abcd1234.default-release: not registered
  FAIL  Firefox (snap)  efgh5678.default: the snap's copy of the module is missing
        Fix: custodio setup browsers enable, then restart the browsers
System
  ok    journal         persistent
  ok    key storage     on an encrypted disk

3 problems.
```

Each `FAIL` has a `Fix:` under it; [doctor.md](doctor.md) explains every check. The Browsers lines are fixed in step 5.
The reader and the finger are your desktop's to set up: in GNOME Settings, Users, Fingerprint Login, enrol a finger
(or run `fprintd-enroll` in a terminal). Then run `custodio doctor` again.

## 3. Let a finger answer the polkit dialogs (optional)

```console
$ sudo custodio setup fingerprint enable
ok    polkit  finger on for every polkit dialog
      A wrong finger, or 10 s without a touch, falls back to the password.
      sudo and the login are unchanged.
      On GNOME the finger may also unlock the lock screen (org.gnome.login-screen enable-fingerprint-authentication); Custodio leaves that setting alone.
      Undo: sudo custodio setup fingerprint disable
```

The "On GNOME" line is about the lock screen, which this command does not change;
[fingerprint.md](fingerprint.md#the-gnome-lock-screen-on-ubuntu) says how to turn the finger off there. What this changes and what
it does not guarantee is in [fingerprint.md](fingerprint.md). Skip this step if you prefer the password.

## 4. Export your key from Firefox and import it

In Firefox open Settings, Privacy & Security, Certificates, View Certificates, tab Your Certificates. Select your certificate and
choose Backup. Save it as `ana.p12` in the directory you are in and choose a password for it. Then:

```console
$ custodio import --id ana ana.p12
warn  ana  ecdsa-p256  encrypted-host
      Root, and anyone with a copy of /var/lib, can use this key.
      Delete the original: shred -u ana.p12
      Restart Firefox, and any program using Custodio, to see the key.
```

Delete the original file as the message says. Close Firefox completely and open it again: a running Firefox sees the new key only after it restarts.

## 5. Register the module and sign in

```console
$ custodio setup browsers enable
ok    Firefox         abcd1234.default-release: registered
ok    Firefox (snap)  module copy: placed
ok    Firefox (snap)  efgh5678.default: registered
      Restart the browsers to see the change.
```

Restart Firefox, and sign in to the site that asks for your certificate; the polkit dialog asks for your password (or your finger,
if you did step 3). Then:

```console
$ custodio list
ana  ecdsa-p256  encrypted-host  custodio test p256  2126-10-03

Note: encrypted-tpm and encrypted-host keys are files that root can use while the machine runs.
```

The package also installs the shell completions; open a new terminal, type `custodio`, a space and `li`, and press Tab; it completes:

```console
$ source /usr/share/bash-completion/completions/custodio
$ COMP_WORDS=(custodio li) COMP_CWORD=1
$ _custodio; echo "${COMPREPLY[@]}"
list
```

The last two lines are what the Tab key does for you: they ask the completion for the words that start with `li`.

## 6. Take it all away

Delete the key (it asks you to confirm), undo the registration and the fingerprint, then remove the package. Do these before removing the package:

```console
$ custodio delete ana
ok    ana  deleted
      Restart Firefox, and any program using Custodio, to see the change.
```

```console
$ custodio setup browsers disable
ok    Firefox         abcd1234.default-release: removed
ok    Firefox (snap)  efgh5678.default: removed
ok    Firefox (snap)  module copy: removed
      Restart the browsers to see the change.
```

```console
$ sudo custodio setup fingerprint disable
ok    polkit  off, polkit asks for the password only
      Undo: sudo custodio setup fingerprint enable
```

```console
$ sudo apt-get remove custodio
custodio: the signing keys are still on disk in /var/lib/custodio (the real directory is /var/lib/private/custodio).
custodio: the account custodio was kept too, because the keys belong to its uid.
custodio: deleting that directory by hand destroys the keys for good; they cannot be exported or recreated.
```

Removal leaves the state directory and the `custodio` account on purpose, and so does purge:

```console
$ sudo ls -d /var/lib/private/custodio
/var/lib/private/custodio
$ getent passwd custodio | cut -d: -f1
custodio
```

```console
$ sudo apt-get purge custodio
custodio: the signing keys are still on disk in /var/lib/custodio (the real directory is /var/lib/private/custodio).
custodio: the account custodio was kept too, because the keys belong to its uid.
custodio: deleting that directory by hand destroys the keys for good; they cannot be exported or recreated.
$ sudo ls -d /var/lib/private/custodio
/var/lib/private/custodio
$ getent passwd custodio | cut -d: -f1
custodio
```

The keys in the state directory cannot be recovered once destroyed; [install.md](install.md#removing-and-purging) says how to destroy them on purpose.
