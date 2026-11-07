## Acceptance 6 (fingerprint) with libfprint's virtual device, ubuntu2604 (2026-11-01)

No reader is needed: libfprint ships a `virtual_device` driver for its own tests, enabled by `FP_VIRTUAL_DEVICE=<socket>`. Ubuntu's
`libfprint-2-2` is built with it (the library holds `FP_VIRTUAL_DEVICE` and `virtual-device-listener.c`). `fprintd`, `pam_fprintd` and
the polkit agent are the real ones; only the sensor is simulated.

Machine: labvm `ubuntu2604`, Ubuntu 26.04.1 LTS GNOME, polkit 127, fprintd 1.94.5-4, libfprint-2-2 1:1.95.1+tod1-0ubuntu2, libpam-fprintd 1.94.5-4.
Package `custodio_0.1.0-1_amd64.deb` from `just package` at `15dec13` (sha256 `096cf9421265b761e9e46d41b2874b3be304b540b0453bfeaa1dc967afb50d10`).

Setup, in the VM only:

1. Drop-in `/etc/systemd/system/fprintd.service.d/virt.conf`: `Environment=FP_VIRTUAL_DEVICE=/run/fpvirt/sock`, `RuntimeDirectory=fpvirt`,
   and `ExecStart=/usr/libexec/fprintd --no-timeout`. The unit has `ProtectSystem=strict`, so a socket straight under `/run` is never
   created; without `--no-timeout` fprintd exits when idle and takes the socket with it. The socket exists only while the device is open.
2. `pam-auth-update --enable fprintd`: `pam_fprintd.so max-tries=1 timeout=10` enters `common-auth`, which `/usr/lib/pam.d/polkit-1` includes.
3. Enroll as root over ssh (`sudo fprintd-enroll -f right-index-finger user`); as the user, polkit asks for the password to enroll.
4. A touch is the text `SCAN <id>` written to the socket and the write side closed. Enrollment takes 5 scans; a later `SCAN` with the
   enrolled id matches, any other id does not.

| Step | Result |
|---|---|
| `pkcs11-tool --sign --mechanism ECDSA-SHA256` with key `p256`, started with `labvm-gui` | polkit dialog "sign with a key held by Custodio" asks to swipe the right index finger, no password field |
| enrolled id | signature made, `Verified OK` by OpenSSL |
| a second signature right after | the dialog asks for the finger again; signature made, `Verified OK` |
| unenrolled id | "Failed to match fingerprint", the dialog falls back to the password (`max-tries=1`); Escape: `C_SignFinal` `CKR_FUNCTION_FAILED` |

Journal (`-t custodiod`): 2 `signature made`, 1 `signature denied`, uid 1000, key `p256`; none extra, none missing.

Acceptance 6 passes with a simulated sensor. Not covered: a real reader's driver, and the image matching that `virtual_image` would
exercise. The same setup works for `pkexec`.

