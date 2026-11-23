# Fingerprint for polkit only, per distro (lab VMs, 2026-11-15)

Every result below was **run** in a lab VM unless marked **read** (from a file or a script's source in the VM) or
**not tested**. No change was made on the host. The user name in the VMs is shown as `<user>`.

## Summary

| | Ubuntu 26.04 | Fedora 44 | Bazzite (Fedora Atomic 44) | Arch (Omarchy) | Debian 13 | Alma 10 |
|---|---|---|---|---|---|---|
| Vendor file | `/usr/lib/pam.d/polkit-1` (polkitd 127) | `/usr/lib/pam.d/polkit-1` (polkit 127) | `/usr/lib/pam.d/polkit-1` (polkit 127) | `/usr/lib/pam.d/polkit-1` (polkit 128) | not tested | not tested |
| `/etc/pam.d/polkit-1` takes precedence | yes | yes | yes | yes | not tested | not tested |
| Fingerprint works via override | yes | yes | yes | yes | not tested | not tested |
| `sudo` unaffected | yes | yes | yes | yes | not tested | not tested |
| Distro tool conflict | no (`pam-auth-update`) | no (`authselect`) | no (`authselect`); file kept across deployments | yes: Omarchy's own fingerprint scripts edit the same file | not tested | not tested |
| Safe fallback when fprintd pieces are missing | yes | yes | yes | yes | not tested | not tested |

No VM exists for Debian 13 or Alma 10 (`labvm list`: none for Debian, `alma9` "not created"), and the lab skill
reserves `create` for a person. Nothing is claimed for them.

## Override that worked on all four

```
#%PAM-1.0
auth     [success=done default=ignore] pam_fprintd.so max-tries=1 timeout=10
auth     include /usr/lib/pam.d/polkit-1
account  include /usr/lib/pam.d/polkit-1
password include /usr/lib/pam.d/polkit-1
session  include /usr/lib/pam.d/polkit-1
```

Mode 0644 root:root. Undo: delete it. `include` with an absolute path is accepted by Linux-PAM (run on all four).
The first form tried on Ubuntu, a full copy of the vendor file with the `pam_fprintd` line in front, also worked
(run, Ubuntu only).

## Method (same on every VM)

- Virtual sensor as in `docs/findings/acceptance-6-fingerprint.md`: drop-in
  `/etc/systemd/system/fprintd.service.d/virt.conf` with `Environment=FP_VIRTUAL_DEVICE=<socket>`,
  `RuntimeDirectory=fpvirt`, `ExecStart=<fprintd> --no-timeout`; `sudo fprintd-enroll -f right-index-finger <user>`
  with 5 × `SCAN fingerA` written to the socket. A touch is `SCAN fingerA` (matches) or `SCAN fingerB` (does not).
  All four libfprint builds contain the virtual driver (`grep -c FP_VIRTUAL_DEVICE libfprint-2.so.2` = 4).
- Polkit authentication for `org.freedesktop.policykit.exec` (auth_admin, no keep), two ways:
  - **Text agent**: over ssh, `pkttyagent --process <pid>` under a pty driven by a script, plus
    `pkcheck --action-id org.freedesktop.policykit.exec --process <pid> --allow-user-interaction`.
    (`pkexec` over ssh with its built-in agent fails on Ubuntu with "No session for cookie"; `pkttyagent` works.)
  - **Graphical agent**: `systemd-run --user pkexec /bin/true` in the desktop session, screenshots of the dialog,
    password typed with `virsh send-key`, result from the unit's exit status. Used on Ubuntu (GNOME Shell),
    Fedora and Bazzite (GNOME Shell) and Omarchy (its Quickshell agent).
  - A negative control (dialog left alone) stays pending on every distro, so exit 0 means the touch or the
    password authorised it.
- Precedence proof: override = `auth optional pam_warn.so` + the vendor lines. The journal shows
  `pam_warn(polkit-1:auth): ... service=[polkit-1]` for the polkit authentication and nothing for a `sudo -k true`
  run right after (with the lab's NOPASSWD drop-in moved aside so sudo really authenticates).
- Fallback cases, each with the override in place: module missing (`.so` moved away; on Bazzite, where `/usr` is
  read-only, the override names a non-existent module instead), daemon unavailable (`systemctl mask --runtime
  fprintd` + stop), no reader (virtual-device drop-in removed), no finger enrolled (`fprintd-delete <user>`).

## Ubuntu 26.04 (`ubuntu2604`)

1. Vendor file `/usr/lib/pam.d/polkit-1`, package `polkitd` 127 (run: `dpkg -S`). Content: `@include common-auth`,
   `common-account`, `common-password`, `session required pam_env.so readenv=1 user_readenv=0`,
   `@include common-session-noninteractive`. No `/etc/pam.d/polkit-1`. Not a conffile (`dpkg-query -W
   -f='${Conffiles}' polkitd` is empty).
2. Precedence: yes (run, `pam_warn` marker; text agent).
3. Fingerprint: yes, text and graphical agent (run). Match: authorised ~1 s after the touch. Mismatch: "Failed to
   match fingerprint", then `Password:`; correct password authorises, cancelling denies. No touch: "Verification
   timed out" after 10 s, then the password field (also seen in the GNOME dialog).
4. `sudo`: prompts `[sudo: authenticate] Contraseña:` only, no marker (run). Login/lock screen: **affected by
   enrolment, not by the override** (run): with a finger enrolled and **no** `/etc/pam.d/polkit-1`, the GNOME lock
   screen shows "(o pase el dedo por el lector)" and a `SCAN fingerA` unlocked it. GDM uses its own
   `/etc/pam.d/gdm-fingerprint` (`auth required pam_fprintd.so`) whenever
   `org.gnome.login-screen enable-fingerprint-authentication` is true, which is the schema default. Setting it to
   false for the user (`gsettings set ...`) removed the fingerprint hint from the lock screen and a touch no longer
   unlocked it (run). The GDM login screen itself reads the `gdm` user's settings (not tested).
5. `pam-auth-update`: manages only `common-*`. `--enable fprintd`, `--disable fprintd`, `--force --package` left the
   override byte-identical (run, md5). `--enable fprintd` adds `auth [success=3 default=ignore] pam_fprintd.so
   max-tries=1 timeout=10` to `common-auth`, i.e. global (sudo too). Profile `fprintd` has `Default: no` (read).
6. `pam_fprintd.so` and `fprintd`: packages `libpam-fprintd` and `fprintd` 1.94.5-4, both installed on the desktop
   image (`ubuntu-desktop-minimal` pulls `libpam-fprintd`, read). All four fallback cases go straight to
   `Password:` about 0.07 s after the dialog opens; password authorises (run). Journal: "PAM adding faulty module:
   pam_fprintd.so" (module missing), "GetDevices failed: Unit fprintd.service is masked" (daemon).
7. SELinux: n/a.
8. Upgrade: `apt-get install --reinstall polkitd` left the override untouched, no `.dpkg-*` file (run). With the
   include form the override follows vendor changes. **But** if the included path disappears, PAM fails to load
   the stack: fingerprint still works, the password path fails with "pam_authenticate failed: Permission denied"
   (run, by pointing the include at a missing file). `sudo` is unaffected, so it is recoverable. A full copy instead
   never breaks but goes stale.
9. Detection: see the Detection section.

Surprises: the helper is socket-activated (`polkit-agent-helper.socket`, not setuid), so `pam_fprintd` also prompts
when the authentication comes from an ssh session.

## Fedora 44 Workstation (`fedora44`)

1. Vendor file `/usr/lib/pam.d/polkit-1`, package `polkit` 127-2.fc44 (run: `rpm -qf`). Content: `auth|account|
   password|session include system-auth`. No `/etc/pam.d/polkit-1`; `rpm -qc polkit` lists no config files.
2. Precedence: yes (run, `pam_warn`).
3. Fingerprint: yes with the graphical agent (run): match, mismatch → "Failed to match fingerprint" + password field,
   timeout → "Verification timed out" + password field after 10 s; password authorises in both. With the text
   agent over ssh, `pam_fprintd` is skipped and the password is asked directly (run): the helper here is setuid and
   runs inside the remote ssh session, and `pam_fprintd` ignores remote sessions.
4. `sudo`: password only, no marker (run). Lock screen: not affected (run): authselect writes
   `/etc/authselect/dconf-db` with `enable-fingerprint-authentication=false` and locks the key
   (`/etc/authselect/dconf-locks`); with a finger enrolled the lock screen did not start fingerprint verification
   (the virtual socket was never opened) and stayed locked after a touch.
5. `authselect`: `/etc/pam.d/system-auth` and `fingerprint-auth` are symlinks into `/etc/authselect/`;
   `/etc/pam.d/polkit-1` is not one of them. `authselect check` (valid), `apply-changes`,
   `enable-feature with-fingerprint`, `disable-feature`, `select local --force` all left the override
   byte-identical (run, md5). `with-fingerprint` puts `pam_fprintd` in `system-auth` (global).
6. `fprintd` and `fprintd-pam` 1.94.5-5 installed by default (run, `rpm -q`). Fallback: all four cases show the
   password field at once in the GNOME dialog and the password authorises (run, screenshots).
7. SELinux enforcing. The override created by `tee` gets `system_u:object_r:etc_t` / `unconfined_u:...:etc_t`, the
   same as `matchpathcon`; `restorecon -nv` changes nothing. No AVC for polkit or the helper (run). The virtual
   sensor needed `semanage permissive -a fprintd_t` (fprintd may not create the socket); that is a test-rig issue,
   not one of the override.
8. Upgrade: `dnf reinstall polkit` left the override untouched, no `.rpmnew` (run). The vendor file is under
   `/usr/lib`, so rpm never touches `/etc/pam.d/polkit-1`.

## Bazzite, Fedora Atomic 44 (`bazzite`)

Same packages and files as Fedora 44 (polkit 127-2.fc44, fprintd 1.94.5-5, fprintd-pam, libfprint 1.94.100;
authselect profile `local`). Results identical to Fedora: precedence (run, `pam_warn`), graphical match / mismatch
/ timeout (run, screenshots), `sudo` password only (one run of the sudo script failed the password once and passed
on the rerun, a harness timing flake), all four fallback cases go to the password field (run), label `etc_t`.

5. rpm-ostree: `/etc` is writable by root; `ostree admin config-diff` lists `A pam.d/polkit-1`. A new deployment
   (`rpm-ostree kargs --append=...` + reboot, booted with the new kernel argument) kept the file byte-identical, and
   fingerprint for polkit worked after the reboot (run). No `/usr/etc/pam.d/polkit-1` exists, so the 3-way `/etc`
   merge has nothing to conflict with. A rebase to a different image was not tested.

## Arch (Omarchy 4.0.6, `omarchy`)

1. Vendor file `/usr/lib/pam.d/polkit-1`, package `polkit` 128-1 (run: `pacman -Qo`), `include system-auth` ×4.
   `pacman -Qii polkit`: no backup files.
2. Precedence: yes (run, `pam_warn`).
3. Fingerprint: yes, text agent and Omarchy's graphical agent (run, screenshots: a fingerprint square, then the
   password field after a mismatch or the 10 s timeout).
4. `sudo`: password only, no marker (run). Lock screen: Omarchy's lock uses fingerprint only when
   `/etc/pam.d/omarchy-lock-fingerprint` exists (read, `Service.qml`); `loginctl lock-session` did not lock the
   session, so not tested.
5. Conflict: Omarchy ships `omarchy-setup-security-fingerprint` and `omarchy-remove-security-fingerprint` (read).
   Setup prepends `auth sufficient pam_fprintd.so` (and a lid-closed `pam_exec` gate) to **`/etc/pam.d/sudo`** and to
   `/etc/pam.d/polkit-1` if it exists, or writes a `pam_unix`-only `/etc/pam.d/polkit-1` if not; remove deletes those
   lines with `sed` and uninstalls fprintd. Both tools own the same file. Omarchy's polkit agent decides to show
   fingerprint mode by reading `/etc/pam.d/polkit-1` for an `auth ... pam_fprintd.so` line (read,
   `PolkitModel.js`), so our override is shown correctly.
6. `fprintd` (which ships `pam_fprintd.so`) is **not installed** by default (run). Installed with
   `pacman -S fprintd` (1.94.5-2, libfprint 1.94.100-1) for the test. Fallback: all four cases go to the password
   field and the password authorises (run).
8. Upgrade: `pacman -S polkit` (reinstall) left the override untouched (run); `/etc/pam.d/polkit-1` is owned by no
   package.

## Detection for `custodio doctor` (run on Ubuntu; same tools on the others)

- Reader present: `gdbus call --system --dest net.reactivated.Fprint --object-path /net/reactivated/Fprint/Manager
  --method net.reactivated.Fprint.Manager.GetDevices` returns a non-empty list. No root, no prompt, works even from
  ssh. Activates fprintd; fails if fprintd is not installed (Arch default).
- Finger enrolled: `fprintd-list "$USER"` (or `ListEnrolledFingers` on the device). From the graphical session as the
  user: works, no prompt. From ssh: "PermissionDenied: Not Authorized: net.reactivated.fprint.device.verify". As
  root it works anywhere.
- Active for polkit: `/etc/pam.d/polkit-1` exists and has an `auth` line with `pam_fprintd.so` (world-readable, no
  root). Global: `pam_fprintd` in `/etc/pam.d/common-auth` (Debian family), `authselect current` lists
  `with-fingerprint` (Fedora family, no root needed), `pam_fprintd` in `/etc/pam.d/sudo` or `system-auth` (Arch).
- Packages: `dpkg -s libpam-fprintd fprintd`, `rpm -q fprintd fprintd-pam`, `pacman -Q fprintd`.

## Recommendation

- **One technique is enough** for every distro tested: write `/etc/pam.d/polkit-1` as above; `disable` deletes it.
  The vendor file is `/usr/lib/pam.d/polkit-1` on all four, so the file is the same everywhere. The command can
  support now: Ubuntu 26.04, Fedora 44, Fedora Atomic/Bazzite, Arch. Debian 13 and Alma 10 need a VM run first.
- `enable` must refuse when `/etc/pam.d/polkit-1` already exists (Omarchy's own setup, an admin's edit, or a distro
  that ships the vendor file in `/etc`), and when the vendor file is not at `/usr/lib/pam.d/polkit-1`. `disable`
  should delete only a file it wrote (check a marker comment or the exact content).
- Include form vs full copy: the include form follows vendor changes but breaks the password path if
  `/usr/lib/pam.d/polkit-1` ever moves (finger still works, `sudo` still works). The copy never breaks but can go
  stale. Prefer the include form plus a `doctor` check that the included file exists.
- `enable` should require `pam_fprintd.so` and fprintd installed, a reader, and an enrolled finger; but a missing
  piece is not dangerous: in every case tested the dialog fell through to the password with no visible delay.
- "Not login" cannot be guaranteed by this file alone: on Ubuntu (and on any GNOME whose
  `enable-fingerprint-authentication` stays at its default `true`) enrolling a finger is enough for the lock screen to
  accept it. Fedora and Bazzite are protected by authselect's locked dconf key; Omarchy by its separate PAM file.
  The command should say so and either leave it or set the key to false (system dconf for both the user session
  and GDM; only the per-user key was tested).
- If the global fingerprint is also on (`pam-auth-update --enable fprintd`, `authselect with-fingerprint`,
  Omarchy setup), the override is redundant and probably asks for the finger twice after a mismatch (not tested).
  `enable` should detect it and say so.

## Not verified

- Debian 13 and Alma/RHEL 10: nothing run (no VM). Whether their polkit ships `/usr/lib/pam.d/polkit-1` or a
  `/etc/pam.d/polkit-1` conffile is unknown.
- A real reader and real image matching (only libfprint's virtual device).
- GDM login screen (only the lock screen, and only on Ubuntu and Fedora); Omarchy lock screen (read only).
- Double fingerprint prompt when the global fingerprint and the override are both on.
- Behaviour on a real polkit package upgrade that changes the vendor file (only reinstall of the same version).
- Bazzite rebase to another image (only a new deployment of the same image).
- The GDM-user dconf setting to disable fingerprint at the login screen.
- `pam_fprintd` skipping remote sessions: observed on Fedora over ssh; the reason (setuid helper inside the ssh
  session vs socket-activated helper outside it) is inferred, not read in the source.
