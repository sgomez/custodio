# Manual acceptance steps (M01, acceptance 11 to 13)

A person follows these steps in a graphical Debian 13 or Ubuntu 26.04 session. They cover SPEC.md
acceptance 11 (rFirma), 12 (LibreOffice) and 13 (the `journalctl` query). Nothing here is
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

`just package` writes `target/debian/custodio_0.1.0-1_amd64.deb` (the name is `custodio_<version>-1_<arch>.deb`).
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
`CUSTODIO_OUTCOME`. (`-o verbose` is unverified here; `journalctl` has no journal in the build
environment.) By key, add `CUSTODIO_KEY_ID=rsa2048`.

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
