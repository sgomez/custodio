# Manual acceptance steps (M01 acceptance 11 to 13, M2 acceptance 12 to 15)

This page has two parts. Sections 1 to 9 are the M01 steps. A person follows them in a graphical Debian 13 or
Ubuntu 26.04 session. They cover the M01 SPEC.md acceptance 11 (rFirma), 12 (LibreOffice) and 13 (the
`journalctl` query). Sections 10 to 15 are the M2 steps for `fedora44`, `bazzite`, `omarchy` and
`ubuntu2404` (the M2 acceptance 12 to 15); start at section 10. Nothing here is
automated. Commands that were run while writing this page (openssl, `certutil`, `modutil`, the
`custodio import` flags) say so; everything else is marked **unverified**: adjust it to your NSS,
LibreOffice and rFirma version and write down what you changed.

Write each observation in the tables as you go. Section 9 is the form to return.

## 1. Prerequisites and test material

- A graphical session (GNOME or similar) with a polkit authentication agent running. The dialog
  must appear when a signature is requested; if none appears, stop and note it.
- Two accounts: the person who signs, and an administrator who reads the journal (section 7).
- Packages: `opensc` (`pkcs11-tool`), `libnss3-tools` (`modutil`, `certutil`), `libreoffice-writer`
  and `libreoffice-gnome` or the equivalent for your desktop, `openssl`.
- Record the versions (section 9): OS release, polkit (`pkaction --version`), LibreOffice
  (`soffice --version`), the rFirma build (section 4) and the `.deb` file name.

### Test CA and keys

The commands were run when this page was written; they produce a test CA, an RSA 2048 and a P-256
key, and one `.p12` for each. The certificates are signed by the CA (not self-signed) and carry
`keyUsage=digitalSignature,nonRepudiation`. The `pkcs12 -export` options are those of
`e2e/guest.sh`. `test-password` is a throwaway; `custodio import` asks for it on the terminal.

```sh
mkdir -p ~/custodio-acceptance && cd ~/custodio-acceptance
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
openssl req -new -x509 -key ca.key -subj "/CN=Custodio test CA" -days 30 \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n' > leaf.ext
for kind in rsa2048 p256; do
  case $kind in
    rsa2048) genopt=(-algorithm RSA -pkeyopt rsa_keygen_bits:2048) ;;
    p256)    genopt=(-algorithm EC -pkeyopt ec_paramgen_curve:P-256) ;;
  esac
  openssl genpkey "${genopt[@]}" -out $kind.key
  openssl req -new -key $kind.key -subj "/CN=Custodio test $kind" -out $kind.csr
  openssl x509 -req -in $kind.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 \
    -extfile leaf.ext -out $kind.crt
  openssl verify -CAfile ca.crt $kind.crt
  openssl pkcs12 -export -inkey $kind.key -in $kind.crt -name $kind \
    -passout pass:test-password -out $kind.p12
done
```

Expected: `rsa2048.crt: OK` and `p256.crt: OK`, and the files `rsa2048.p12` and `p256.p12`.

### Trusting the test CA

Without this, LibreOffice and rFirma report the signatures as not valid. For LibreOffice, trust
the CA in the NSS database it uses (found in section 6; command checked here against a temporary
database):

```sh
certutil -A -d sql:<nssdb dir> -n "Custodio test CA" -t "C,C,C" -i ca.crt
certutil -L -d sql:<nssdb dir>
```

Expected: the CA is listed with trust `C,C,C`. LibreOffice checks the signer as S/MIME (the
middle flag); with `C,,` it reports the signature as not valid. How rFirma trusts a CA (its own store or the
system's) is **unverified**; use what the rFirma documentation says and record it.

## 2. Install the .deb

`just package` writes `target/packages/custodio_0.1.0-1_amd64.deb` (the name is `custodio_<version>-1_<arch>.deb`).
Copy the file the maintainers gave you, or the one built from the milestone commit, and run (unverified here,
there is no graphical session in the build environment):

```sh
sudo apt install ./custodio_0.1.0-1_amd64.deb      # or: sudo dpkg -i custodio_0.1.0-1_amd64.deb
```

Check:

```sh
ls /usr/lib/custodio/libcustodio_pkcs11.so /usr/share/p11-kit/modules/custodio.module
pkaction --action-id com.rfirma.custodio.sign       # the polkit action is installed
systemctl status custodio.service                   # starts on first use (D-Bus activation); may be inactive
```

Expected: the files exist and `pkaction` prints the action. Note any error.

## 3. Import the keys

As the person who signs, in a terminal (the password is asked on the terminal, never as an
argument; the flags equal the usage text of the command: `custodio import [--id <key id>] <file.p12>`):

```sh
custodio import --id rsa2048 rsa2048.p12
custodio import --id p256 p256.p12
pkcs11-tool --module /usr/lib/custodio/libcustodio_pkcs11.so --list-objects
```

Expected: the import asks for the password (`test-password`) and succeeds; the listing shows
a certificate and a key for `rsa2048` and for `p256`. Running `--list-objects` against the installed
module is unverified here. If a polkit dialog appears for a listing, write it down.

## 4. The rFirma build

Acceptance 11 needs a build of rFirma without the two workarounds of the M0 run
(`docs/findings.md`, section 4 "Manual acceptance run (M01)"):

1. a fallback from `CKM_SHA256_RSA_PKCS` to raw `CKM_RSA_PKCS` over a `DigestInfo` (Custodio offers
   only raw mechanisms for RSA);
2. skipping `C_Login` when the token lacks `CKF_LOGIN_REQUIRED` (Custodio's `C_Login` returns
   `CKR_FUNCTION_NOT_SUPPORTED`).

The rFirma maintainers must provide the build (SPEC open question "Which rFirma build"): either
a release from before the workarounds or a build with them reverted. To confirm the build lacks
them (unverified): ask the maintainers for the commit, or check that it is a release tag older
than the workarounds. A build that works only after one of the two would show up as a failure
in section 5; write the error text.

Record: release or workarounds reverted; version or commit: ______________________

## 5. rFirma run

Open rFirma, select the Custodio module (how: **unverified**, the menu path depends on the build),
and for each key sign a document.

| # | Key | Step | Expected | Result (pass/fail, notes) |
|---|---|---|---|---|
| 1 | RSA 2048 (`rsa2048`) | Certificate listed | the certificate appears in rFirma | |
| 2 | RSA 2048 | Sign, approve | polkit dialog seen, signature made | |
| 3 | RSA 2048 | Sign again, approve | polkit dialog again, signature made | |
| 4 | RSA 2048 | Sign, cancel the dialog | signature fails | |
| 5 | P-256 (`p256`) | Certificate listed | the certificate appears in rFirma | |
| 6 | P-256 | Sign, approve | polkit dialog seen, signature made | |
| 7 | P-256 | Sign again, approve | polkit dialog again, signature made | |
| 8 | P-256 | Sign, cancel the dialog | signature fails | |

While each signature is open, run `pgrep -a rfirma` (unverified: the process name may differ) and
write down the pid and the time of day for section 7. Also write down any PIN or password dialog.

## 6. LibreOffice run

### Register the module in the NSS database LibreOffice uses

Find the database (unverified: depends on the LibreOffice version). Candidates are the profile's
`cert9.db` (for example `~/.config/libreoffice/4/user/`) and the shared `~/.pki/nssdb`. In
LibreOffice, Tools > Options > Security > Certificate shows which directory it uses (**unverified**
menu path). Then, with LibreOffice closed:

```sh
modutil -dbdir sql:<nssdb dir> -add custodio -libfile /usr/lib/custodio/libcustodio_pkcs11.so
modutil -dbdir sql:<nssdb dir> -list
```

The library path equals the one in `/usr/share/p11-kit/modules/custodio.module`. Expected: `-list`
shows a module `custodio`. The two commands were run against a temporary database and the release build of the library when the page
was written (without `-force`, `modutil` asks for confirmation: answer `y`; with `-force` it does not). Trust the CA in this database (section 1).

### Sign ODF documents

For each key: create a Writer document, save it as ODF (`.odt`), then File > Digital Signatures >
Sign Document (**unverified** menu path), choose the certificate of that key, and sign. Save,
close LibreOffice, and reopen the document. Check the signature status.

| # | Key | Step | Expected | Result (pass/fail, notes) |
|---|---|---|---|---|
| 1 | RSA 2048 | Certificate offered in the signing dialog | the certificate of `rsa2048` is listed | |
| 2 | RSA 2048 | Sign, approve | polkit dialog seen, signature made | |
| 3 | RSA 2048 | Save, close, reopen | signature shown as valid | |
| 4 | RSA 2048 | Sign, cancel the dialog | signing fails, no signature added | |
| 5 | P-256 | Certificate offered in the signing dialog | the certificate of `p256` is listed | |
| 6 | P-256 | Sign, approve | polkit dialog seen, signature made | |
| 7 | P-256 | Save, close, reopen | signature shown as valid | |
| 8 | P-256 | Sign, cancel the dialog | signing fails, no signature added | |

Write down the pid of the LibreOffice process during each signature (`pgrep -a soffice`; it may
be `soffice.bin`) and the time.

## 7. Journal comparison

After sections 5 and 6, an administrator runs the query from `docs/audit.md` ("Queries"), with
the window set around the run (replace the two times):

```sh
journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401 \
  --since "YYYY-MM-DD HH:MM" --until "YYYY-MM-DD HH:MM" -o verbose
```

`-o verbose` shows the fields `CUSTODIO_UID`, `CUSTODIO_PID`, `CUSTODIO_KEY_ID`,
`CUSTODIO_OUTCOME` (verified in the F35 run). By key, add `CUSTODIO_KEY_ID=rsa2048`.

Fill in one row per step of sections 5 and 6, and one per journal entry found:

| Step taken (section, #) | Time | Client | Key | Approved / cancelled | Entry found: uid | pid | key | outcome |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |

Rule: one entry per signature and per cancellation, none extra, none missing. A signature the
person approved has outcome `signed`; a cancelled one has `denied` (`docs/audit.md`, "Outcomes").
The uid is the person's (`id -u`), the pid is the one from `pgrep`, the key is `rsa2048` or
`p256`. List every mismatch, extra entry and missing entry.

## 8. What to record for the open questions

Write the answers in the blanks; they settle the SPEC open questions.

### PIN dialog in LibreOffice

Did any PIN or password dialog appear, other than the polkit dialog? When (opening the signing
dialog, listing certificates, signing), with what text, and did it accept an empty input?

Answer: ______________________

### LibreOffice with ECDSA

Did LibreOffice sign with the P-256 key? Error text if not; was the signature valid after
reopening? If it did not sign, repeat with a software NSS token holding the same key (import
`p256.p12` into a temporary NSS database with `pk12util -d sql:<dir> -i p256.p12` and sign with
that, **unverified**) to tell a Custodio fault from a LibreOffice one.

Answer: ______________________

### Repeated login and session state

Did any client (rFirma, LibreOffice, `pkcs11-tool`) call `C_Login` twice in a session, and what
happened: did it prompt, fail, or continue? A trace helps: `pkcs11-spy` from `opensc`, via
`PKCS11SPY=/usr/lib/custodio/libcustodio_pkcs11.so` and the spy library as the module (unverified).
Note whether the spy log shows `C_GetSessionInfo` and what state it reported. This run records only what clients do with today's
behaviour; trying `CKR_USER_ALREADY_LOGGED_IN` needs another build and is out of scope. Also
write down whether any client sent `CKU_SO` (visible in the trace).

Answer: ______________________

## 9. Result form

Versions: OS ________ polkit ________ LibreOffice ________ rFirma build ________ .deb ________

| Acceptance | Pass / fail / not run | Notes (reference table rows) |
|---|---|---|
| 11 rFirma, RSA 2048 and P-256 | | |
| 12 LibreOffice, RSA 2048 and P-256 | | |
| 13 journal entries match | | |

Report the filled form, the tables of sections 5 to 7 and the answers of section 8 to the
milestone approver (issue or pull request on the repository). Do not paste key files or
passwords.

## 10. What every run records (M2)

Each M2 run (sections 11 to 14) starts by recording, in the form of section 15, these five items.
The commands are standard tools and **unverified** here: there is no such machine in the build
environment.

| Item | Command |
|---|---|
| OS release | `cat /etc/os-release` (`PRETTY_NAME`, `VERSION_ID`) |
| kernel | `uname -r` |
| bus daemon and version | `busctl status \| head -n 3`, then `dbus-broker --version` or `dbus-daemon --version` (whichever runs) |
| polkit version | `pkaction --version` |
| package file names | the exact file names given to the installer, for example `ls -l custodio*` in the directory used |

Install commands are those of `docs/install.md`, which also explains each message. Packages come from
the maintainers or from `just package` (`target/packages/`); do not rebuild them on the machine.
Test material (CA, `rsa2048.p12`, `p256.p12`) is made as in section 1; import with
`custodio import --id rsa2048 rsa2048.p12` (the password, `test-password`, is asked on the terminal).
Write down the time of day of every signature and cancellation: the audit comparison uses it.

## 11. fedora44, SELinux enforcing (acceptance 12)

Record first (section 10):

```sh
cat /etc/os-release; uname -r; dbus-broker --version; pkaction --version; ls -l custodio*
```

Write the package file names. Fedora's own Firefox (`dnf install firefox` if missing), not a Flatpak
or a download from Mozilla, and its NSS tools (`dnf install nss-tools`).

1. SELinux first, before installing anything. `getenforce` must print `Enforcing`. If not, stop and
   note it: the run does not count. Write down the time of day as the start of the audit window.

   ```sh
   getenforce
   ```
2. Install the `.rpm` (command from `docs/install.md`):

   ```sh
   sudo dnf install ./custodio-0.1.0-1.x86_64.rpm
   ```
3. Import both keys (section 3 of this page, `custodio import`).
4. Firefox lists the certificate without manual registration. Open Firefox; do not run `modutil` and do
   not add the module in Settings > Privacy & Security > Security Devices. Look in
   Settings > Privacy & Security > Certificates > View Certificates > Your Certificates for
   `Custodio test rsa2048` and `Custodio test p256` (**unverified** menu path). If they appear only after
   manual registration, that is a failure of acceptance 12: write the steps you needed in the notes, and do
   not count the run as passed.
5. TLS client authentication: visit a site that asks for a client certificate (a local
   `openssl s_server -Verify 1 -CAfile ca.crt -www` with a server certificate signed by the same CA is
   enough; **unverified**), pick the certificate and check that the page loads.
6. Each signature shows the polkit dialog: repeat step 5 twice for each key, approving; the dialog must
   appear each time. Then repeat once and cancel the dialog: the connection must fail.
7. SELinux denials over the whole run, from the start time of step 1 (**unverified** flags):

   ```sh
   sudo ausearch -m AVC,USER_AVC --start "HH:MM:SS" | grep -Ei 'custodio|polkit|libcustodio_pkcs11'
   sudo ausearch -m AVC,USER_AVC --start "HH:MM:SS" | wc -l
   ```

   Expected: no line names the service (`custodio`), polkit or the module (`libcustodio_pkcs11`) during import, signing and denial. Any AVC at all: copy it into the notes, with the step it happened in.
8. The audit comparison, the base query of `docs/audit.md` ("Queries") with the window of the run:

   ```sh
   journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401 \
     --since "YYYY-MM-DD HH:MM" --until "YYYY-MM-DD HH:MM" -o verbose
   ```

   Expected: one entry per signature and per cancellation, none extra, none missing; approved ones have
   outcome `signed`. The cancellations alone: the same query with `CUSTODIO_OUTCOME=denied` in place of
   `MESSAGE_ID=...`. Use the table of section 7.

## 12. bazzite, the .rpm layered (acceptance 13)

Record first (section 10): `cat /etc/os-release; uname -r; dbus-broker --version; pkaction --version; rpm-ostree status`, and the
package file names of the old and the newer package. Do everything on the host, in a terminal of the
desktop session; do not use a toolbox or distrobox: a signature from inside a toolbox does not count.

1. `getenforce` prints `Enforcing`; write down the time of day. Layer the package (`docs/install.md`, rpm-ostree)
   and reboot into the new deployment:

   ```sh
   sudo rpm-ostree install ./custodio-0.1.0-1.x86_64.rpm
   sudo systemctl reboot
   ```
2. After the reboot, `rpm-ostree status` shows `custodio` as a layered package in the booted deployment. Import both keys.
3. A signature through the module from the host: use the client of your choice (Firefox as in section 11 step 5, or
   `pkcs11-tool --module /usr/lib/custodio/libcustodio_pkcs11.so --sign` with the `rsa2048` key, **unverified**).
   The polkit dialog must appear. Then cancel one: the signature must fail.
4. Replace the layered package with a newer version (**unverified**: it needs a newer `.rpm`, for example
   `custodio-0.1.1-1.x86_64.rpm`) and reboot:

   ```sh
   sudo rpm-ostree uninstall custodio --install ./custodio-0.1.1-1.x86_64.rpm
   sudo systemctl reboot
   ```

   After the reboot, the same keys (`custodio import` again is not allowed) sign: repeat step 3 with the polkit dialog.
5. OS update: `sudo rpm-ostree upgrade`, then `sudo systemctl reboot`. After the reboot, the same keys
   sign again, with the dialog, and a cancel fails. If the upgrade offers nothing, write that and use `rpm-ostree rebase` to another image
   (**unverified**) or mark this step not run.
6. No SELinux denial involves the service, after each reboot and at the end:

   ```sh
   sudo ausearch -m AVC,USER_AVC --start "HH:MM:SS" | grep -Ei 'custodio|polkit|libcustodio_pkcs11'
   ```

   Expected: no line. Run the command after each reboot, with `--start` set to the time of the run so that
   it covers the reboots, and record the output of each.

## 13. omarchy (acceptance 14)

Record first (section 10): `cat /etc/os-release; uname -r; dbus-broker --version; pkaction --version; ls -l custodio*`, and the
package file names. A polkit dialog is expected for every signature.

1. Install (command from `docs/install.md`):

   ```sh
   sudo pacman -U custodio-0.1.0-1-x86_64.pkg.tar.zst
   ```
2. Check the polkit agent: Omarchy's Quickshell agent, not polkit-gnome. `pgrep -a quickshell` shows it
   (**unverified**: the process name may differ) and `pgrep -a polkit-gnome` shows nothing. Write down what runs.
3. Import both keys. Sign with Firefox (section 11 step 5): the Quickshell dialog appears for each signature, a second signature asks again,
   and a cancel makes it fail. Fill the table:

   | # | Key | Step | Expected | Result |
   |---|---|---|---|---|
   | 1 | `rsa2048` | Sign, approve | dialog seen, signature made | |
   | 2 | `rsa2048` | Sign again, approve | dialog again | |
   | 3 | `rsa2048` | Sign, cancel | signature fails | |
4. Firefox lists the certificate and does TLS client authentication (section 11 steps 4 and 5).
5. Manual registration needed: yes / no. If yes, how (the exact steps, for example the module added in Settings >
   Privacy & Security > Security Devices, or `modutil`)? ______________________
   The milestone approver settles the open question from this answer; do not decide it in the notes.

## 14. ubuntu2404, dbus-broker (acceptance 15)

Record first (section 10), before and after the switch (the bus daemon changes): `cat /etc/os-release; uname -r;
dbus-daemon --version; pkaction --version; ls -l custodio*` (the package file names), then `dbus-broker --version` after the switch.

1. Before the switch, install the `.deb`; it must be refused (`dpkg -i` runs the package's `preinst` check directly and shows its message, without resolving dependencies first):

   ```sh
   sudo dpkg -i custodio_0.1.0-1_amd64.deb
   ```

   Expected: non-zero exit and the message `does not provide ProcessFD`. The account and the state are not created:
   `getent passwd custodio` prints nothing, and `/var/lib/custodio` does not exist. Write the output.
2. Switch to `dbus-broker` and reboot, as in `docs/install.md` ("Ubuntu 24.04: switching to dbus-broker"):

   ```sh
   sudo apt-get install dbus-broker
   sudo systemctl reboot
   ```
3. After the reboot, what to check, with the commands (**unverified**). Write what broke:

   | Check | Command | Expected | What broke |
   |---|---|---|---|
   | the desktop session | log in; `echo $XDG_SESSION_TYPE` | the desktop starts | |
   | logind | `loginctl list-sessions` | your session is listed, `active` | |
   | the polkit agent | `pgrep -a polkit`; run `pkexec true` | the agent runs, the dialog appears | |
   | NetworkManager | `systemctl is-active NetworkManager; nmcli general status` | `active`, connected | |
   | bus daemon | `busctl status \| head -n 3`; `systemctl status dbus-broker` | `dbus-broker` | |
4. Install (`apt-get` here, so that any missing dependency is installed too):

   ```sh
   sudo apt-get install ./custodio_0.1.0-1_amd64.deb
   ```

   Import both keys (`custodio import`). Sign with the polkit dialog each time
   (twice for each key) and cancel once for each: the signature fails.
5. Whether switching to dbus-broker is acceptable on Ubuntu 24.04, from the table above: ______________________
   The milestone approver settles the open question on refusing Ubuntu 24.04 altogether.

## 15. M2 result form

One copy per machine.

Machine ________ OS release ________ kernel ________ bus daemon and version ________ polkit version ________
package file names ________

| Acceptance | Pass / fail / not run | Notes |
|---|---|---|
| 12 fedora44 (SELinux, Firefox, journal) | | |
| 13 bazzite (layering, replace, OS update) | | |
| 14 omarchy (Quickshell, Firefox) | | |
| 15 ubuntu2404 (refusal, switch, signing) | | |

Report the filled forms to the milestone approver as in section 9. Do not paste key files or passwords.
