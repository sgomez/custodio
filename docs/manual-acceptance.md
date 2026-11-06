# Manual acceptance steps (M01 acceptance 11 to 13, M2 acceptance 12 to 15, M3 acceptance 14 to 16, M4 acceptance 13 to 15)

This page has four parts. Sections 1 to 9 are the M01 steps. A person follows them in a graphical Debian 13 or
Ubuntu 26.04 session. They cover the M01 SPEC.md acceptance 11 (rFirma), 12 (LibreOffice) and 13 (the
`journalctl` query). Sections 10 to 15 are the M2 steps for `fedora44`, `bazzite`, `omarchy` and
`ubuntu2404` (the M2 acceptance 12 to 15); start at section 10. Sections 16 to 19 are the M3 steps (the M3
acceptance 14 to 16: the client API by hand, a flatpak, Firefox and LibreOffice with a second account); start at
section 16. Sections 20 to 23 are the M4 steps (the M4 acceptance 13 to 15: a hardware TPM, a VM without a TPM and a copy of
the state directory); start at section 20. Nothing here is automated. Commands that were run while writing this page (openssl, `certutil`, `modutil`, the
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
(`docs/findings/M01-acceptance.md`):

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
   note it: the run does not count. The second command prints the start of the audit window (date and
   time, as `ausearch` reads them); write it down.

   ```sh
   getenforce
   LC_ALL=C date '+%x %T'
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
7. SELinux denials over the whole run, from the start of step 1 (replace `MM/DD/YY HH:MM:SS` with
   what it printed; checked in the F54 run). `--input-logs` makes `ausearch` read the log even when
   its input is not a terminal (over `ssh`); without it, it reads nothing and prints `<no matches>`. The
   first command must find the polkit authentications of step 6; if it finds none, the query is wrong.

   ```sh
   sudo LC_ALL=C ausearch -m USER_AUTH --input-logs --start MM/DD/YY HH:MM:SS | grep -c USER_AUTH
   sudo LC_ALL=C ausearch -m AVC,USER_AVC --input-logs --start MM/DD/YY HH:MM:SS | grep -Ei 'custodio|polkit|libcustodio_pkcs11'
   sudo LC_ALL=C ausearch -m AVC,USER_AVC --input-logs --start MM/DD/YY HH:MM:SS | grep -c AVC
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

### F61 fedora44: old-path .rpm upgrade, labels

Proves that the service starts from `/usr/libexec/custodio/custodiod` in `unconfined_service_t`, and that key files written by the old
package under `init_t` get the label `var_lib_t` back (F61). Needs the two packages of the milestone commit: the old-path fixture
(`scripts/package-oldpath.sh` writes it to `target/packages-oldpath/`: the current .rpm with the daemon at `/usr/lib/custodio/custodiod`) and the
newer package (`target/packages-next/`, which `just e2e` builds). Copy both to the machine (the old-path fixture has the name of package N, `custodio-0.1.0-1.x86_64.rpm`; the newer one is `custodio-0.1.1-1.x86_64.rpm`). Commands copied from `docs/install.md` and the e2e scripts
are checked; the `ls -Z`, `ps -eZ` and `matchpathcon` lines are **unverified** until this run.

1. Remove any custodio package (`sudo dnf remove custodio`, and `sudo rm -rf /var/lib/private/custodio` on this test machine only), then install the old-path package and import a key:

   ```sh
   sudo dnf install ./custodio-0.1.0-1.x86_64.rpm
   custodio import --id rsa2048 rsa2048.p12
   ps -eZ | grep custodiod
   ls -Z /var/lib/private/custodio
   ```

   Expected: `ps -eZ` shows `system_u:system_r:init_t` for `custodiod` (the old path is `lib_t`), and the key file under
   `/var/lib/private/custodio` has `init_var_lib_t`. Copy both outputs. If you see anything else, stop: the run does not show the problem F61 fixes.
2. Upgrade to the newer package:

   ```sh
   sudo dnf upgrade ./custodio-0.1.1-1.x86_64.rpm
   ls /usr/libexec/custodio/custodiod; ls /usr/lib/custodio/custodiod
   systemctl status custodio --no-pager | grep -E 'Main PID|Active'
   ps -eZ | grep custodiod
   ```

   Expected: the first `ls` finds the file, the second says `No such file or directory`; the service is active with a new main PID; `ps -eZ` shows
   `system_u:system_r:unconfined_service_t`. `ls -Z /var/lib/private/custodio` already shows `var_lib_t`: systemd's rpm file trigger runs `systemd-tmpfiles --create` at the end of the transaction (F62).
3. Restore the labels and check them. The tmpfiles line runs at every boot; to see its effect at once, and to check that nothing but the label changes:

   ```sh
   stat -c '%a %u:%g %s %n' /var/lib/private/custodio /var/lib/private/custodio/*
   sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/custodio.conf
   stat -c '%a %u:%g %s %n' /var/lib/private/custodio /var/lib/private/custodio/*
   ls -Z /var/lib/private/custodio
   matchpathcon /var/lib/private/custodio
   ```

   Expected: the two `stat` outputs are equal (mode, owner, size); `ls -Z` shows `var_lib_t` (what `matchpathcon` prints as the default); the key listing
   still works (`pkcs11-tool --module /usr/lib/custodio/libcustodio_pkcs11.so --list-objects`). The `stat` and `ls -Z` lines need root (`/var/lib/private` is `0700 root`;
   run them under `sudo sh -c '…'` so the glob expands as root). dnf's file trigger already restored the label, so the boot path is shown on bazzite (next section).
4. Sign with the dialog and cancel it (acceptance 12, steps 5 and 6 of the section above): the dialog appears, approving signs, cancelling fails.
5. Record in `docs/findings/F61.md`: the date, the machine, and for each command above its result with the lines that show it.

## 12. bazzite, the .rpm layered (acceptance 13)

Record first (section 10): `cat /etc/os-release; uname -r; dbus-broker --version; pkaction --version; rpm-ostree status`, and the
package file names of the old and the newer package. Do everything on the host, in a terminal of the
desktop session; do not use a toolbox or distrobox: a signature from inside a toolbox does not count.

1. `getenforce` prints `Enforcing`; write down what `LC_ALL=C date '+%x %T'` prints, the start of the audit
   window (section 11 step 1). Layer the package (`docs/install.md`, rpm-ostree) and reboot into the new deployment:

   ```sh
   getenforce
   LC_ALL=C date '+%x %T'
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
6. No SELinux denial involves the service, after each reboot and at the end. The flags are those of section 11
   step 7 (checked on Fedora 44, not on bazzite); `MM/DD/YY HH:MM:SS` is what step 1 printed, so the window covers
   the reboots even across midnight. The first command must find authentications (the desktop login after each
   reboot, the polkit dialogs); if it finds none, the query is wrong:

   ```sh
   sudo LC_ALL=C ausearch -m USER_AUTH --input-logs --start MM/DD/YY HH:MM:SS | grep -c USER_AUTH
   sudo LC_ALL=C ausearch -m AVC,USER_AVC --input-logs --start MM/DD/YY HH:MM:SS | grep -Ei 'custodio|polkit|libcustodio_pkcs11'
   ```

   Expected: no line from the second command. Run both after each reboot and at the end, and record the output of each.

### F61 bazzite: old-path .rpm layered with rpm-ostree, labels

The same proof on the image-based system, where `%post` runs in a build root and no scriptlet touches `/var` at deploy time, so only the tmpfiles line
(`/usr/lib/tmpfiles.d/custodio.conf`, run by the boot) can restore the label. Do everything on the host (no toolbox). Commands are **unverified** until this run
(`rpm-ostree install` of a local file and the replace step are the ones section 12 already marks as such).

1. Layer the old-path package and reboot; import a key; look at the domain and the label:

   ```sh
   sudo rpm-ostree install ./custodio-0.1.0-1.x86_64.rpm
   systemctl reboot
   custodio import --id rsa2048 rsa2048.p12
   ps -eZ | grep custodiod
   ls -Z /var/lib/private/custodio
   ```

   Expected: `init_t` and `init_var_lib_t`, as on fedora44 (copy both outputs).
2. Replace it with the newer package, reboot, and check:

   ```sh
   rpm-ostree uninstall custodio --install ./custodio-0.1.1-1.x86_64.rpm
   systemctl reboot
   ls /usr/libexec/custodio/custodiod
   ps -eZ | grep custodiod
   ls -Z /var/lib/private/custodio
   stat -c '%a %u:%g %s %n' /var/lib/private/custodio /var/lib/private/custodio/*
   ```

   Expected: the file exists; `unconfined_service_t`; **after the reboot** `var_lib_t` for the key files (the boot ran `systemd-tmpfiles-setup`), with the same
   mode, owner and size as before the upgrade (take the `stat` line before step 2 too and compare).
3. The same keys still list and sign with the dialog, and a cancel fails (acceptance 12; sections 11 and 12 above): sign twice with the dialog open each time, cancel once.
4. Record in `docs/findings/F61.md`: the date, the machine, and for each command above its result with the lines that show it.

## 13. omarchy (acceptance 14)

Record first (section 10): `cat /etc/os-release; uname -r; dbus-broker --version; pkaction --version; ls -l custodio*`, and the
package file names. A polkit dialog is expected for every signature.

1. Install (command from `docs/install.md`):

   ```sh
   sudo pacman -U custodio-0.1.0-1-x86_64.pkg.tar.zst
   ```
2. Check the polkit agent: Omarchy's Quickshell agent, not polkit-gnome. `pgrep -a quickshell` shows it
   (`quickshell -n -p /usr/share/omarchy/shell` on Omarchy 4.0.6, checked in the F56 run) and `pgrep -a polkit-gnome` shows nothing.
   Write down what runs.
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
3. After the reboot, what to check, with the commands (checked in the F57 run). Write what broke:

   | Check | Command | Expected | What broke |
   |---|---|---|---|
   | the desktop session | log in; `echo $XDG_SESSION_TYPE` | the desktop starts | |
   | logind | `loginctl list-sessions` | your session is listed, `active` | |
   | the polkit agent | run `pkexec true` in the session | the dialog appears; approved, exit 0 (GNOME's agent is in `gnome-shell`: `pgrep -a polkit` shows only `polkitd`) | |
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

## 16. M3 acceptance 14: the client API by hand

A person detects the service, imports a key, lists it, replaces its certificate, signs and deletes it with
`busctl`, following only `docs/api.md`: if a step needs anything that page does not say, write that down as a
failure of acceptance 14. `docs/api.md` gives `busctl` commands only, so there is no `gdbus` variant here. Run the
steps as the one user who signs, in a graphical session with a polkit agent. See each dialog and each error and write
it into the table below. Commands that were not run while writing this page are **unverified**.

Make the files first: the six `openssl` commands of the first block of "Examples" in `docs/api.md` give `demo.p12`
(password `secret`), `renewed.der` (a second certificate for the same key) and `other.der` (a certificate for
another key). Then the `<DER>` argument forms of the commands below are the ones of that page.

1. Detect. Follow the five steps of the "Detection" part of `docs/api.md` in order and write down the result of each.
   With the service running, step 2 is:

   ```sh
   busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s com.rfirma.Custodio1
   ```

   Expected: `b true`. If it is `false`, do the other steps of "Detection" and write down what they print.
2. List with nothing imported. Dialog: none (`ListKeys` asks polkit nothing). Expected `a(sssay) 0`.

   ```sh
   busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ListKeys
   ```
3. Import, and refuse the dialog. Dialog: `com.rfirma.custodio.import-certificate`; press Cancel. Expected error
   `PolkitDenied` (`Call failed: not authorized`). Nothing is imported.

   ```sh
   busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ImportP12 says demo $(wc -c < demo.p12) $(od -An -v -tu1 demo.p12) secret
   ```
4. Import with a wrong password: the same command with `wrong` instead of `secret`. Dialog:
   `com.rfirma.custodio.import-certificate`; approve it. Expected error `WrongPasswordOrBadP12`; it is only reported
   after the approval.
5. Import with a bad id: the same command with `'bad id'` instead of `demo`. Dialog: none, the call fails before
   polkit is asked. Expected error `InvalidArgs`.
6. Import, and approve. Dialog: `com.rfirma.custodio.import-certificate`. Expected `s "ecdsa-p256"`. This is the
   command of step 3.
7. Import again with the same id (the command of step 3). Dialog: none. Expected error `KeyIdTaken`.
8. List again (the command of step 2). Expected one key, `demo`, `ecdsa-p256`, with its certificate.
9. Replace the certificate with the certificate of another key, approving the dialog. Dialog:
   `com.rfirma.custodio.replace-certificate`. Expected error `CertificateMismatch`.

   ```sh
   busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ReplaceCertificate say demo $(wc -c < other.der) $(od -An -v -tu1 other.der)
   ```
10. Replace the certificate with the right one (`renewed.der` in place of `other.der`), approving the dialog.
    Dialog: `com.rfirma.custodio.replace-certificate`. Expected: no output. List again: the certificate is the new one.
11. Sign, and approve. Dialog: `com.rfirma.custodio.sign`. Expected `ay 64` and 64 bytes. Sign a second time: the
    dialog shows again (nothing is cached).

    ```sh
    digest=$(head -c 32 /dev/zero | od -An -v -tu1)
    busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 Sign suuuay demo 4161 0 0 32 $digest
    ```
12. Sign with an id you do not have: the command of step 11 with `nobody` instead of `demo`. Dialog: none. Expected
    error `NoSuchKey` (the full name is `com.rfirma.Custodio1.Error.NoSuchKey`).
13. Delete, and refuse the dialog. Dialog: `com.rfirma.custodio.delete-certificate`; press Cancel. Expected error
    `PolkitDenied`; the key is still listed.

    ```sh
    busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 DeleteKey s demo
    ```
14. Delete, and approve (the command of step 13). Dialog: `com.rfirma.custodio.delete-certificate`. Expected: no
    output; the list (step 2) is empty again.
15. `AuthorizationUnavailable`: not reproduced manually, because it needs polkit to be stopped or unreachable, which
    cannot be done safely on a person's session; the automated tests of the polkit failure cases prove it.

| # (step) | Dialog seen (action) | Error or result seen | Expected | Result (pass/fail, notes) |
|---|---|---|---|---|
| 1 | none | | `b true` | |
| 2 | none | | `a(sssay) 0` | |
| 3 | import-certificate, cancelled | | `PolkitDenied` | |
| 4 | import-certificate, approved | | `WrongPasswordOrBadP12` | |
| 5 | none | | `InvalidArgs` | |
| 6 | import-certificate, approved | | `s "ecdsa-p256"` | |
| 7 | none | | `KeyIdTaken` | |
| 8 | none | | one key listed | |
| 9 | replace-certificate, approved | | `CertificateMismatch` | |
| 10 | replace-certificate, approved | | no output, new certificate | |
| 11 | sign, approved (twice) | | `ay 64`, dialog both times | |
| 12 | none | | `NoSuchKey` | |
| 13 | delete-certificate, cancelled | | `PolkitDenied`, key kept | |
| 14 | delete-certificate, approved | | no output, list empty | |

## 17. M3 acceptance 15: a flatpak calls Custodio

A test application in a flatpak calls Custodio. The manifest the repository ships is
`packaging/flatpak/com.rfirma.CustodioTest.json`; its app-id is `com.rfirma.CustodioTest` and its only extra permission is
`--system-talk-name=com.rfirma.Custodio1` (the permission "From a flatpak" in `docs/api.md` names). The runtime
has no `busctl`, so the application and the steps here use `gdbus`, as "From a flatpak" in `docs/api.md` shows.

Prepare: install `flatpak` and `flatpak-builder` (distribution packages of those names on Fedora), the runtimes from
flathub, and import the key `p256` on the host as in section 3 (`custodio import`).

```sh
flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install --user flathub org.freedesktop.Platform//25.08 org.freedesktop.Sdk//25.08
flatpak-builder --user --install --force-clean build-dir packaging/flatpak/com.rfirma.CustodioTest.json
flatpak run com.rfirma.CustodioTest
flatpak run --command=sh com.rfirma.CustodioTest
```

If `flatpak-builder` stops with `Failure spawning rofiles-fuse` (seen on fedora44), run it again with
`--disable-rofiles-fuse`, after removing `.flatpak-builder` (`fusermount3 -u` any mount left in it), and write that down.

1. Detection. The first command runs the detection steps of the "Detection" part of `docs/api.md` from inside the
   sandbox (the application prints the result of `NameHasOwner` and `ListActivatableNames`). Expected: `(true,)` and
   the name listed, as on the host. Write down the output. A `(false,)` and `not listed` mean the permission is not
   in effect ("From a flatpak" in `docs/api.md`).
2. In the shell of the third command, sign:

   ```sh
   digest="[$(printf 'byte 0x00, %.0s' $(seq 31))byte 0x00]"
   gdbus call --system --dest com.rfirma.Custodio1 --object-path /com/rfirma/Custodio1 --method com.rfirma.Custodio1.Sign p256 4161 0 0 "$digest"
   ```
3. The polkit dialog shows for the action `com.rfirma.custodio.sign`. Write down what it shows, approve it, and
   write down the result (`([byte 0x…, …],)` with 64 bytes).
4. Only after the dialog, an administrator reads the journal. The base query of `docs/audit.md`:

   ```sh
   journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401
   ```

   Find the entry of the signature (add `-o verbose` to see the fields). Expected: `CUSTODIO_APP_ID=com.rfirma.CustodioTest`
   with `CUSTODIO_APP_ID_STATE=read`, and `CUSTODIO_UID` equal to `id -u` of the person who ran the sandbox. The
   `CUSTODIO_PID` is the pid of the `xdg-dbus-proxy`, not of the application (`docs/audit.md`, "Flatpak app-id"); do not
   compare it with the application. By app-id: add `CUSTODIO_APP_ID=com.rfirma.CustodioTest` to the query.

If `CUSTODIO_APP_ID_STATE` is `undetermined` or `none`, or the app-id is another, that is a failure of acceptance 15:
write down the whole entry (without key material).

| # | Step | Expected | Seen | Result (pass/fail, notes) |
|---|---|---|---|---|
| 1 | Detection inside the flatpak | `(true,)`, name listed | | |
| 2 | Sign: dialog action | `com.rfirma.custodio.sign` | | |
| 3 | Sign: result | 64 bytes | | |
| 4 | Journal: app-id | `com.rfirma.CustodioTest`, state `read` | | |
| 5 | Journal: uid | `id -u` of the person | | |
| 6 | Journal: pid | the proxy's, not the application's | | |

## 18. M3 acceptance 16: Firefox, LibreOffice and a second account

Firefox and LibreOffice still sign with a key that the person imported through the M3 service.

1. Import a key as in section 3 (`custodio import`), if it is not still there.
2. Firefox: follow the Firefox steps of `## 11. fedora44, SELinux enforcing (acceptance 12)`
   (the registration and TLS client authentication). Expected: a polkit dialog, then the sign-in works. Write down the dialog.
3. LibreOffice: follow `## 6. LibreOffice run` (registration and "Sign ODF documents"). Expected: a dialog for each
   signature and a valid signature after reopening.
4. Compare the journal with `## 7. Journal comparison`: one entry per signature and per cancellation.
5. A second account on the same machine (another login, with no keys imported): log in as that account, register the
   module as in `## 6. LibreOffice run` in that account's database, and list the tokens:

   ```sh
   modutil -dbdir sql:<nssdb dir> -list
   pkcs11-tool --module /usr/lib/custodio/libcustodio_pkcs11.so --list-objects
   ```

   Expected: no token and no object for the key of the first account, and no certificate offered in Firefox or
   LibreOffice. These listings were not run against the M3 service when the page was written (**unverified**).
6. In the same account, `ListKeys` (the command of section 16, step 2):

   ```sh
   busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ListKeys
   ```

   Expected: `a(sssay) 0`, an empty list.

| # | Step | Expected | Result (pass/fail, notes) |
|---|---|---|---|
| 1 | Firefox signs, dialog seen | signature made | |
| 2 | LibreOffice signs, dialog seen | valid signature | |
| 3 | Journal comparison | none extra, none missing | |
| 4 | Second account: token listing | no token | |
| 5 | Second account: `ListKeys` | `a(sssay) 0` | |

## 19. M3 result form

One copy per machine. Machine ________ OS release ________ kernel ________ bus daemon and version ________ polkit
version ________ flatpak version ________

| Acceptance | Pass / fail / not run | Every dialog and every error seen (notes) |
|---|---|---|
| M3 14 client API by hand (section 16) | | |
| M3 15 flatpak, app-id and uid in the journal (section 17) | | |
| M3 16 Firefox, LibreOffice, second account (section 18) | | |

Report the filled forms to the milestone approver as in section 9. Do not paste key files or passwords.

## 20. M4 acceptance 13: hardware TPM

On a machine with a hardware TPM. Needs root, `tpm2-tools` and the repository (the helper script below). Write the
machine's `TPM2TOOLS_TCTI` down if it is not the default (the kernel resource manager `/dev/tpmrm0` is). The commands of
`tpm2-tools` were run while writing this page against a software TPM (`scripts/with-swtpm.sh`); the test of this page runs
them again there. Nothing on this page was run on a hardware TPM, a `fwupd`, a reboot, Firefox or LibreOffice
(**unverified**): adjust and write down what you changed.

1. Import an RSA 2048 and a P-256 `.p12` as in section 3 (`.p12` files of section 1, password asked on the terminal):

   ```sh
   custodio import --id rsa2048 rsa2048.p12
   custodio import --id p256 p256.p12
   custodio list
   ```

   Expected: each import prints the storage line below, and `custodio list` shows `kind: tpm` for both keys.

   ```text
   Storage: tpm. The key is in the TPM and cannot be copied out of it.
   ```

2. As root, with the repository as the current directory, check the stored record of each key (the state directory is
   `/var/lib/private/custodio`, the real directory behind `/var/lib/custodio`, see `docs/install.md`):

   ```sh
   sudo -s
   scripts/tpm-record-check.sh /var/lib/private/custodio rsa2048
   scripts/tpm-record-check.sh /var/lib/private/custodio p256
   ```

   The helper reads the stored record, loads the key under the same parent as the service, prints `tpm2_readpublic` of
   it and runs `tpm2_duplicate` under a policy session on `TPM2_CC_Duplicate`. Expected for each key: the line
   `authPolicy: empty`, the line `tpm2_duplicate: failed with TPM_RC_POLICY_FAIL (0x99D)` and `tpm-record-check: pass`
   (exit 0). Exit 1 means the check failed or a command did not work, exit 2 means bad usage or no record of kind `tpm`
   with that id. Any other error, or any exit other than 0, is a failed step: write the message down. A `tpm2_duplicate`
   that fails with another error is not "fails as expected".
3. Then, in this order, three events. Before and after each one read PCR 7:

   ```sh
   tpm2_pcrread sha256:7
   ```

   - Event 1, reboot: `sudo systemctl reboot`.
   - Event 2, upgrade to the next M4 package: the install steps of `docs/install.md` for the machine's system (section
     "Upgrading": the same command as for a first installation).
   - Event 3, a `fwupd` `dbx` update:

     ```sh
     fwupdmgr refresh
     fwupdmgr get-updates
     fwupdmgr update
     ```

     Where the update list holds no `dbx` update ("UEFI Secure Boot Forbidden Signature Database"), use the substitute
     that changes PCR 7 (it lasts until the next reboot, so it is not a lasting change of the machine):

     ```sh
     tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000001
     ```

   After the `dbx` update or the substitute, PCR 7 must differ from the value read before; if it does not,
   the event proved nothing: write that down and do not tick the rows of this event. After a reboot or an upgrade a changed value is
   noted, not required.
4. After each of the three events: `custodio list` still shows both keys with `kind: tpm`, and Firefox and LibreOffice sign
   with both keys after the polkit dialog:
   - Firefox: follow the Firefox steps of `## 11. fedora44, SELinux enforcing (acceptance 12)` (the registration and TLS
     client authentication) once with `rsa2048` and once with `p256`.
   - LibreOffice: follow `## 6. LibreOffice run` ("Sign ODF documents") once with each key.

| Event | Check | Expected | Result (pass/fail, notes) |
|---|---|---|---|
| import | `custodio list`, both keys | `kind: tpm` | |
| import | helper, both keys | `authPolicy: empty`, `TPM_RC_POLICY_FAIL`, exit 0 | |
| reboot | PCR 7 before and after | both values written down | |
| reboot | `custodio list` | both keys, `kind: tpm` | |
| reboot | Firefox, both keys | dialog, then signed | |
| reboot | LibreOffice, both keys | dialog, then valid signature | |
| upgrade | PCR 7 before and after | both values written down | |
| upgrade | `custodio list` | both keys, `kind: tpm` | |
| upgrade | Firefox, both keys | dialog, then signed | |
| upgrade | LibreOffice, both keys | dialog, then valid signature | |
| dbx or substitute | PCR 7 before and after | the value differs | |
| dbx or substitute | `custodio list` | both keys, `kind: tpm` | |
| dbx or substitute | Firefox, both keys | dialog, then signed | |
| dbx or substitute | LibreOffice, both keys | dialog, then valid signature | |

## 21. M4 acceptance 14: a VM without a TPM

In a virtual machine with no TPM (`ls /dev/tpm*` finds nothing). Install as in section 2 and make a `.p12` as in section 1.
Nothing on this page was run in such a VM (**unverified**).

1. Import a key and list it:

   ```sh
   custodio import --id rsa2048 rsa2048.p12
   custodio list
   ```

2. Expected: the import prints the notice below, word for word (the text of `kind_text` in `crates/custodio-cli/src/lib.rs`):

   ```text
   Storage: encrypted-host. This key is weaker than a TPM key: this machine has no TPM, so the key is a file encrypted with the host key. Root, and anyone with a copy of /var/lib, can use it.
   ```

3. Expected: `custodio list` shows the line below for the key. It prints the kind and no sentence about a weaker key
   (`crates/custodio-cli/src/list.rs`), while SPEC.md acceptance 14 says `custodio list` says the key is weaker. Do not tick
   the `custodio list` row for text the command never printed: write down what it printed, and the milestone approver decides
   whether `kind: encrypted-host` alone meets acceptance 14.

   ```text
   kind: encrypted-host
   ```

4. Reboot (`sudo systemctl reboot`), then `custodio list` again: the key is still listed with `kind: encrypted-host`.
5. After the reboot, sign from Firefox (`## 11. fedora44, SELinux enforcing (acceptance 12)`) or from LibreOffice
   (`## 6. LibreOffice run`) with the key: a polkit dialog, then a signature.

| # | Step | Expected | Result (pass/fail, notes) |
|---|---|---|---|
| 1 | Import output | the notice of step 2, word for word | |
| 2 | `custodio list` | `kind: encrypted-host` (decision on "weaker" for the approver) | |
| 3 | After the reboot: `custodio list` | the key, `kind: encrypted-host` | |
| 4 | After the reboot: sign from Firefox or LibreOffice | dialog, then signed | |

## 22. M4 acceptance 15: a copy of the state directory

On both machines (the hardware TPM machine of section 20 and the VM without a TPM of section 21), with the `.p12` of each
imported key and its password. As root, with the repository as the current directory. The check ran for real on a
fixture state directory while writing this page; on the two machines it is **unverified**.

```sh
sudo -s
umask 077
copy=$(mktemp -d /var/tmp/custodio-copy.XXXXXX)
cp -a /var/lib/private/custodio/. "$copy"/
read -rs -p 'password of the .p12: ' pw; echo
printf '%s\n' "$pw" | scripts/check-no-plaintext.sh "$copy" rsa2048.p12
printf '%s\n' "$pw" | scripts/check-no-plaintext.sh "$copy" p256.p12
unset pw
rm -rf "$copy"
```

The usage of the check is `scripts/check-no-plaintext.sh STATE_DIR P12 < password`: the password goes on standard input and
never in an argument. Run the check for every imported `.p12` of the machine: on the VM of section 21 only the `rsa2048.p12` line, since only that key was imported there. The copy and the password must
not reach a log, a terminal recording or a file you keep; the copy is removed by the last line. Expected: exit 0 for each `.p12`.
Exit 1 means a match: the files are named on standard output, and the step failed (write the file names down, never
their content). Exit 3 means the check did not run (a wrong password, a file that is not a `.p12`): it is never a pass, run
it again. Any other exit is also a failed step.

| Machine | `.p12` | Expected | Result (pass/fail, notes) |
|---|---|---|---|
| hardware TPM | `rsa2048.p12` | exit 0 | |
| hardware TPM | `p256.p12` | exit 0 | |
| VM without a TPM | `rsa2048.p12` | exit 0 | |

## 23. M4 result form

One copy per machine. Machine ________ OS release ________ kernel ________ TPM (model, or none) ________ package versions
(before and after the upgrade) ________

| Acceptance | Pass / fail / not run | Every dialog and every error seen (notes) |
|---|---|---|
| M4 13 hardware TPM (section 20) | | |
| M4 14 VM without a TPM (section 21) | | |
| M4 15 copy of the state directory (section 22) | | |

Report the filled forms to the milestone approver as in section 9. Do not paste key files, copies of the state directory or
passwords.
