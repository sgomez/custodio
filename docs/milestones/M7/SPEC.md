# Custodio — Milestone 7: A release a person can use end to end

M7 builds on the code of M0–M6 (specs and results in `docs/milestones/`, `docs/findings.md` and
`docs/findings/`, `docs/decisions.md`, `docs/decisions/packaging.md`, `docs/api.md`, `docs/audit.md`,
`docs/threat-model.md`, `docs/install.md`). Everything those milestones established stays true unless
this document says otherwise. The fingerprint technique was tried on lab VMs before this spec: the
runs, the exact file, the refusals and the read-only checks are in `docs/reports/polkit-fingerprint.md`
(called "the report" below), and the virtual-sensor method is in
`docs/findings/acceptance-6-fingerprint.md`. This milestone's features are numbered from F189.

## Problem

Release 0.8.0 works, but a person who installs it cannot get from the package to a signed login
without reading the source or the milestone records:

- **Fingerprint is all or nothing.** Signing with a finger already works, because polkit authenticates
  through PAM. But the only switch a distribution offers (`pam-auth-update --enable fprintd` on Ubuntu
  and Debian, `authselect enable-feature with-fingerprint` on Fedora, Omarchy's own script on Arch)
  turns it on for `sudo`, the login and everything else as well. A person who wants a finger for
  Custodio's dialogs, and only for polkit, has to hand-write a PAM file, and a wrong one can stop polkit
  from accepting the password.
- **Nothing tells the person what is missing.** Whether there is a reader, an enrolled finger,
  fingerprint for polkit, the module in Firefox, a journal that keeps the audit entries across a
  reboot, or an encrypted state directory: each needs a different tool and some knowledge of PAM, NSS
  and systemd.
- **The command line is not self-explanatory.** `--help` is not real help, `custodio list` is not
  laid out for people, errors do not say what to do next, and there are no shell completions.
- **Three defects of 0.8.0 confuse people.** An import reports a wrong password and an unreadable file
  as one error, so the person cannot tell whether to retype the password or export the file again.
  The storage classifier answers `unknown` and later `not-encrypted` for the same LVM volume on an
  unencrypted partition (device `252:0`), so the warning changes with no change on the machine.
  Firefox does not see an imported or deleted key until it restarts, and nothing says so.

It matters now because 0.8.0 is the first public release and the next one is the one people will
install. The acceptance is a person on Ubuntu 26.04 with a real reader following only the
documentation, from install to removal.

## Threat model

The threat model of M0–M6 holds (`docs/threat-model.md` and `docs/milestones/M6/SPEC.md`, "Threat
model"). M7 adds no operation on keys and no new entry point to the service. It adds a command that
writes one system PAM file as root, a read-only diagnostic command, and printing of certificate fields
on the terminal.

- **In scope (new):**
  - **The fingerprint command must not lock anyone out of polkit or change anything but polkit.** It
    writes only `/etc/pam.d/polkit-1`, only when the vendor file it includes exists, and only in the
    exact form the report proved on four distributions: a missing or wrong finger, a missing module,
    daemon, reader or enrolled finger all fall through to the password, and `sudo` and the login keep
    their own PAM files. It refuses rather than guess on any system that does not match.
  - **It must not destroy someone else's configuration.** It never overwrites, edits or removes a
    `/etc/pam.d/polkit-1` it did not write (an administrator's file, Omarchy's, a distribution's).
    `disable` removes only a file that is exactly Custodio's. A write is atomic: an interruption
    leaves no file or the whole file, never a partial PAM stack, and the file has the mode, owner and
    security label of any other file in `/etc/pam.d/`.
  - **The diagnostic command changes nothing.** `custodio doctor` writes no file, changes no setting,
    opens no polkit dialog and needs no root. (It may start `fprintd` by bus activation, as any client
    of `fprintd` does; it starts nothing else.)
  - **Certificate text is untrusted.** Subject, issuer and other fields printed by `custodio list` come
    from a certificate the person imported, possibly from a hostile issuer. They can never write
    control characters or terminal escape sequences to the terminal, and they never change how the
    rest of the output is read (no forged rows or lines).
  - **Shell completions** run `custodio` to get key ids. They ask nothing of polkit, write nothing and
    fail silently when the service is absent.
  - **Decrypted keys stay off the disk.** An `encrypted-tpm` or `encrypted-host` key decrypted in the
    service's memory never reaches swap, a stored core dump or a crash report, whatever the core
    handler and even with the unit's core limit overridden (Design 4).
- **Out of scope:** everything M0–M6 exclude (a hostile process of the same uid outside any sandbox,
  root controlling the running machine, a compromised kernel, tampering with the journal). Also out:
  the security of `fprintd`, `libfprint`, the reader's driver and its matching; an administrator who
  edits the PAM stack after `enable`; a compromised distribution package.
- **Not guaranteed (the documents must say each of these):**
  - **The override is for every polkit action, not only Custodio's.** After `enable`, any polkit
    dialog on the machine (`pkexec`, software installation, disk management, Custodio's sign, import,
    delete and replace) accepts the finger instead of the password, including the actions that ask
    for an administrator. Custodio cannot narrow PAM to its own actions: PAM is per service, and
    polkit is one service.
  - **A finger is a weaker secret than a password.** It can be lifted, and it can be taken from a
    person who is asleep or coerced. A person who needs the password barrier keeps the fingerprint off.
  - **A finger at the machine can approve a remote request.** On Ubuntu the polkit helper is socket
    activated, so a polkit authentication started from an ssh session also asks for the finger, and a
    touch on the local reader approves it (run, report). On Fedora, `pam_fprintd` skips remote sessions
    (observed; the reason is inferred).
  - **The login and lock screens are not Custodio's.** On Ubuntu (and on any GNOME whose
    `org.gnome.login-screen enable-fingerprint-authentication` keeps its default `true`), enrolling a
    finger is enough for the lock screen to accept it, through GDM's own PAM file, whether or not
    Custodio's override exists. Custodio neither causes nor changes this; the documents say how to turn
    it off. Fedora and Bazzite lock it off through authselect; Omarchy uses a separate file.
  - **If the vendor file disappears** after `enable` (a future polkit package that moves it), the
    password path of polkit fails while the finger still works; `sudo` is unaffected, so the system is
    recoverable. `doctor` detects it. Nothing watches for it between runs of `doctor`.
  - **Debian 13 and RHEL/Alma 10** were not run in a VM. On them the command proceeds only when the
    files match what was proven elsewhere (vendor file at `/usr/lib/pam.d/polkit-1`, no
    `/etc/pam.d/polkit-1`), and refuses otherwise.
  - **Hibernation writes all of memory to disk**, a decrypted key included, whatever the unit says.
    The encrypted kinds need an encrypted swap device and hibernation image.

## Goal

A person on Ubuntu 26.04 with a fingerprint reader and no Custodio installed can, following only the
documentation, install the package, find out what is missing, turn the fingerprint on for polkit only,
import a certificate exported from Firefox, sign in to a real site with a finger, and later remove
everything, leaving the system as it was. Every command they meet explains itself, and every behaviour
added for this works, or refuses safely, on every supported system.

## Design

The architecture stays: `custodiod` on the system bus and the Firefox snap socket, the documented API,
per-uid ownership, polkit on every sign, import, delete and replace with nothing cached, one journal
entry per authorized call, the PKCS#11 module and the CLI as clients of the documented API. M7 adds two
CLI commands, groups the setup commands under `custodio setup`, reworks the CLI's output, fixes four
defects, and writes the documents. It adds no client.

### 1. `custodio setup fingerprint enable` and `disable`

A subcommand of `custodio setup`, run as root (`sudo custodio setup fingerprint enable`). It changes
exactly one file, `/etc/pam.d/polkit-1`.

- **The file.** `enable` writes this content (from the report, "Override that worked on all four"; the
  idea fixes it):

  ```
  #%PAM-1.0
  auth     [success=done default=ignore] pam_fprintd.so max-tries=3 timeout=30
  auth     include /usr/lib/pam.d/polkit-1
  account  include /usr/lib/pam.d/polkit-1
  password include /usr/lib/pam.d/polkit-1
  session  include /usr/lib/pam.d/polkit-1
  ```

  Three tries in 30 s are `pam_fprintd`'s defaults. The report's file had one try in 10 s, which the
  manual run of F211 on a real reader found too strict: a finger placed slightly off fell straight to
  the password.

  It may add comment lines that say Custodio wrote the file and how to undo it; comments must not
  change what any reader of the file sees as `auth ... pam_fprintd.so` (Omarchy's polkit agent decides
  its fingerprint mode by reading that line). Mode `0644`, owner `root:root`, and the SELinux label the
  policy gives a new file in `/etc/pam.d/` where SELinux is enforcing (on Fedora that is `etc_t`, the
  same as `matchpathcon`; report, Fedora item 7).
- **Why it works.** Linux-PAM reads `/etc/pam.d/<service>` in preference to `/usr/lib/pam.d/<service>`
  (`pam(7)`, `pam.conf(5)`), and on every system tested the vendor file is
  `/usr/lib/pam.d/polkit-1`, owned by the polkit package and not a conffile. `pam-auth-update`,
  `authselect` and a new rpm-ostree deployment leave `/etc/pam.d/polkit-1` alone (run, report).
  `include` with an absolute path is accepted by Linux-PAM (run on all four).
- **Whose file it is.** A file is Custodio's only if its bytes are exactly what `enable` writes, or
  what 0.8.0 wrote (the same file with `max-tries=1 timeout=10`): `disable` removes either, and `enable`
  on the 0.8.0 file refuses and says to run `disable`, then `enable`. Anything else, including
  Custodio's file edited by hand, is someone else's.
- **`enable` refuses**, writes nothing and exits non-zero, saying why and what to do next, when:
  - it is not running as root;
  - `/etc/pam.d/polkit-1` exists and is not Custodio's (an administrator's file, Omarchy's
    `omarchy-setup-security-fingerprint`, a distribution that ships the polkit file in `/etc`), or is
    not a regular file;
  - `/usr/lib/pam.d/polkit-1` does not exist or is not a regular file (including on Debian 13 or
    RHEL/Alma 10 if their polkit puts it elsewhere);
  - `pam_fprintd.so` or `fprintd` is not installed (the message names the package for the system:
    `libpam-fprintd` and `fprintd`, `fprintd-pam` and `fprintd`, `fprintd`).
- **No reader is a warning, not a refusal.** When `fprintd` reports no device, `enable` writes the file
  and says that polkit will keep asking for the password until there is a reader and an enrolled
  finger, and names `custodio doctor`. The report shows that state is harmless (straight to the
  password). `enable` does not check whose fingers are enrolled: that is `doctor`'s, run as the person.
- **`enable` on a system that already has it.** If `/etc/pam.d/polkit-1` is already Custodio's, it
  changes nothing and succeeds. If fingerprint is already active globally (`pam_fprintd` in
  `common-auth` on the Debian family; `authselect` feature `with-fingerprint` on the Fedora family;
  `pam_fprintd` in `system-auth` or `sudo` on Arch), it says so, says that the override would be
  redundant (and might ask for the finger twice after a mismatch, untested), writes nothing and
  exits non-zero, with the next step (turn the global switch off, then run `enable` again).
- **`disable`** removes `/etc/pam.d/polkit-1` only if it is Custodio's. If there is no file, it says
  so and succeeds. If the file is someone else's, it refuses, changes nothing, and says who might own
  it and how to look. After `disable`, polkit reads the vendor file again, exactly as before `enable`.
- **What it prints.** On success, `enable` says what changed in plain words: every polkit dialog now
  accepts the finger, three wrong fingers or no touch within 30 seconds fall back to the password, `sudo`
  and the login are unchanged, and how to undo it. It also prints the lock-screen note (Threat model,
  "Not guaranteed") when it applies, without changing that setting.
- **The package does not touch PAM.** No package script creates, edits, renames or removes
  `/etc/pam.d/polkit-1`, on install, upgrade, removal or purge. The install notice says the
  fingerprint is off and names `sudo custodio setup fingerprint enable` and `custodio doctor`.
  Removing the package leaves an existing override in place, still working (it names only system
  files), and prints no warning about it; the documents say to run `disable` first.
- **Supported systems.** The same command and file on every supported system. Where the files differ
  from the proven layout, the refusals above apply.

Prior art worth copying: `pam-auth-update` profiles (a tool that owns only what it wrote, with a marker
and exact matching); `authselect`'s refusal to overwrite files it did not create; Omarchy's
`omarchy-setup-security-fingerprint` and `omarchy-remove-security-fingerprint` (what not to do: they
edit `sudo` and an existing `polkit-1` with `sed`).

### 2. `custodio doctor`

A read-only command, run by the person as themselves (it refuses to run as root, as `setup browsers`
does, because it checks the person's own profiles and fingers). It prints one line per check, each
with a state, and for every check that is not satisfied, the command or documented step that fixes
it. The checks:

1. **A reader.** `fprintd` reports at least one device. If `fprintd` is not installed, that is the
   missing piece, and the package to install is named.
2. **An enrolled finger** for the person. From a session where `fprintd` refuses to answer (an ssh
   session: "Not Authorized: net.reactivated.fprint.device.verify", report), the state is "could not
   check" with the reason, never "missing".
3. **Fingerprint active for polkit**, and how: through Custodio's override, through someone else's
   `/etc/pam.d/polkit-1` that has an `auth` line with `pam_fprintd.so`, or globally (the same
   detection as `enable`). For an override, whether its `include` still resolves (the vendor file
   exists); a broken include is reported as the most urgent problem, because it breaks the password
   path of polkit. When it is active globally, `doctor` says that `sudo` uses the finger too.
4. **The module registered in Firefox**, per profile, using the same discovery as `custodio setup
   browsers enable` and read-only: native profiles, the Firefox snap's profiles and copy (including
   a stale copy), and systems where Firefox sees the module through p11-kit (satisfied without
   registration). No profile at all is reported as such, not as a failure of Custodio.
5. **A persistent journal**, so that the audit entries of signatures survive a reboot. How journald's
   effective storage is read without root (its configuration and drop-ins, and the presence of the
   persistent directory) is for a finding; the fix names the documented steps.
6. **The storage of the state directory**, as the service reports it (`StateStorage`, `docs/api.md`):
   `encrypted`, `not-encrypted` (with the full-disk encryption advice) or `unknown` (with the reason
   when one is known, see Design 4). `not-encrypted` and `unknown` are a warning, not a failure:
   Custodio works on such a disk, and the risk (whoever takes the machine can use the keys) is the
   person's to accept. If the service cannot be reached, that is reported with its fix, and this check
   is "could not check".

- **Exit status.** The fingerprint is optional: checks 1 to 3 are printed with their fix but do not
  count, except a broken include of an override, which does. The exit status is 0 only when that and
  checks 4 to 6 are satisfied, a warning of check 6 counting as satisfied; non-zero otherwise ("could
  not check" included). The steps of the
  acceptance end with `custodio doctor` reporting nothing to fix.
- **Never a prompt.** No check opens a polkit dialog, a password prompt or a browser, and none needs
  root. A check that would need one reports "could not check" instead.
- **Every system.** Each check works or says "could not check" on every supported system; none assumes
  Ubuntu. The package names and global-fingerprint detection are per family (report, "Detection").

Prior art worth copying: `flutter doctor` and `brew doctor` (one line per check, the fix next to it);
`systemd-analyze security` (read-only, explains each item).

### 3. The command line

- **Arguments are parsed by hand**, as today. No `clap` or other argument-parsing crate, and no crate
  that generates completions.
- **Help.** `custodio --help`, `custodio -h`, and `custodio <command> --help` for every command
  (including `setup` and `doctor`) print real help on standard output and exit 0: what the command
  does, its arguments and options, and an example. Under `setup`, `--help` works at every level the
  person can type (`setup --help`, `setup browsers --help`, `setup browsers enable --help`) and
  prints that level's help. A usage error still goes to standard error with exit status 2, as today,
  and says how to get help. The man page covers the same commands and options; a test checks that
  every command and option in the help is in the man page and the other way round.
- **`custodio setup`** groups the commands that set the system up, apart from the daily ones in the
  help, each undone by its sibling action. `doctor` stays a top-level command.
  - `custodio setup browsers enable [--module <path>]` adds the module (the installed one, or
    `<path>`) to the person's browser profiles, native and the Firefox snap's through its copy;
    `disable` removes the entries of every Custodio module file and takes no `--module`; `refresh
    [--module <path>]` only updates the copy of the module that the Firefox snap loads, from
    `<path>` when given, if it differs. The systemd user unit `custodio-refresh.service` runs
    `custodio setup browsers refresh`.
  - `custodio setup fingerprint enable` and `disable` are those of Design 1.

  Each action does what `custodio register [--module <path>]`, `--remove`, `--refresh-only` and
  `custodio fingerprint enable`/`disable` do before this change: the same effects, refusals, output
  and exit statuses, with only the command names in them changed. `custodio setup` alone, or a topic
  with no action, is a usage error (standard error, exit status 2) whose message is that level's
  short help (the topics, or the topic's actions) ending with the next-step line.
- **No compatibility.** There is no stable release and no frozen command line: `custodio register`
  and `custodio fingerprint` are unknown commands after this change, with no alias. Every message,
  document, test and packaging file of this release uses the new names; the release notes of 0.9.0
  say that `register` became `setup browsers` and that `fingerprint` moved under `setup`.
- **`custodio list`** prints a table with one row per key: id, key type, storage kind, subject, and end
  of validity (the day, marked when the certificate has expired or expires within 30 days). On a
  terminal a header row comes first; a script gets the rows only. When any key has a weaker storage
  kind (`encrypted-tpm`, `encrypted-host`), one line at the foot explains what that means, instead of a
  note per key. `custodio list -v` (`--verbose`) prints every key in full, as `custodio list <id>` does. The existing
  state-directory warning (M6 Design 7) stays. With no keys it says so and how to import one.
- **`custodio list <id>`** prints that one key in full: everything in the row, plus at least the
  issuer, the serial number, the start of validity and a SHA-256 fingerprint of the certificate. An id
  the person does not have is an error with the next step (`custodio list` to see the ids). It uses
  `ListKeys` and selects on the client side: no API change.
- **Certificate text.** Fields from the certificate are decoded by a parser that tolerates any input
  (fuzzed), and printed with every control character and every byte that is not printable escaped, so
  that a hostile subject can neither drive the terminal nor look like another row. How a subject is
  shown (the common name, or the whole name in RFC 4514 form) is the builder's, documented in the help.
- **Colour** only when the stream it is written to is a terminal, and never when `NO_COLOR` is set
  to a non-empty value (no-color.org). Without colour, the output contains no escape sequence at all
  and says the same things (colour never carries meaning alone).
- **Errors.** Every error, from every command, is at least two lines on standard error: what went
  wrong, then the next step the person can take (a command, a documented section, or "report a bug"
  with where). This includes usage errors, the service being absent, polkit denial and unavailability,
  every error of `docs/api.md`, the new import errors (Design 4), the refusals of `setup browsers` and
  `setup fingerprint`. Messages never contain a password, key material or untrusted text unescaped.
- **Completions** for bash, zsh and fish, shipped by every package format in the place each shell and
  distribution loads them from without configuration. They complete commands (the topics and actions
  of `setup` included), options, and key ids (for `list`, `delete`, and any other command that takes
  one), the ids coming from the service through `custodio` itself. Key id completion asks no polkit,
  writes nothing, finishes promptly, and offers nothing (no error text) when the service is absent.
  Which directories each format uses is for a finding; any difference between formats is recorded as
  the parity rules of `docs/decisions/packaging.md` require.

Prior art worth copying: no-color.org; `git`'s and `rustc`'s "hint:"/"help:" second lines;
systemd's hand-written bash and zsh completions, which call the program for dynamic values;
`ls`'s escaping of control characters in file names (`--quoting-style`).

### 4. Defects of 0.8.0

- **Wrong password versus unreadable file.** Today `ImportP12` fails as `WrongPasswordOrBadP12` and the
  journal writes `wrong_password` for both. The service must tell apart, and the CLI and the journal
  must show differently: (a) a file whose integrity MAC is present and does not verify with the
  password, which is a wrong password, whatever the file holds (its contents are sealed by that
  password); (b) a file that cannot be read as PKCS#12 or holds no usable key and certificate (no
  private key, several, a key without a certificate), with the right password, and with any password
  when the defect shows without decrypting (bytes that are not PKCS#12, unencrypted bags without a
  MAC), which is an unreadable file; and (c) a file with no MAC that does not decrypt, where the library
  cannot tell (a) from (b), which keeps a combined message. Two new D-Bus errors, one for (a) and
  one for (b); `WrongPasswordOrBadP12` stays for (c) only. In the journal, (a) and (c) keep
  `wrong_password` and (b) gets one new outcome. All are added under the compatibility rules of
  `docs/api.md` and `docs/audit.md` (names and meanings are only added to, never changed) and checked
  by `just api-contract`. The CLI says,
  for (a), to retype the password; for (b), to export the file again (the README shows how from
  Firefox); for (c), both. The order of the method stays: the file is never opened before polkit
  approves. Whether a case is (a), (b) or (c) is decided from the file and the library's result, never
  from timing.
- **The storage classifier's two answers.** On a machine with an LVM volume (device `252:0`) on an
  unencrypted partition, the service answered `unknown` at one start and `not-encrypted` at a later
  one. First find the cause and record it in a finding with the evidence (a reproduction, the sysfs
  and mountinfo the service read, or the code path). Then either fix it so that the same storage gets
  the same answer at every start, or, if the `unknown` cannot be avoided (for example, the service
  starts before the chain is complete), keep `unknown` and have the service expose the reason so that
  `doctor` explains it and says what to do. Either way `unknown` is never turned into `encrypted`, and
  the classification rules of `docs/findings/F180.md` stay unless the finding shows one of them wrong.
  Any addition to the API for the reason is read-only, documented, bus only, and under the API's
  compatibility rule.
- **Firefox and key changes.** After a successful `custodio import` or `custodio delete`, the CLI says
  that Firefox (and any other running program that loaded the module) sees the change only after it
  restarts. Making Firefox see the change without a restart is not in this milestone.
- **Decrypted keys reaching swap and core dumps.** `encrypted-tpm` and `encrypted-host` keys are
  decrypted in `custodiod`'s memory to sign, and nothing keeps that memory off the disk: a page in an
  unencrypted swap file, a core that `systemd-coredump` stores under `/var/lib/systemd/coredump/`, or
  an apport report in `/var/crash/` with the process's memory in it outlives the process and a
  power-off. That breaks what `docs/api.md` ("Storage kinds") promises for both kinds, protection
  against a copy of the files. `custodiod` protects itself at start, as `ssh-agent` and KeePassXC do,
  so this does not depend on the unit or on the core handler: first thing, before it reads any key,
  it sets its core-size limit (`RLIMIT_CORE`) to 0, soft and hard, and then makes itself non-dumpable
  (`PR_SET_DUMPABLE` 0); it does not start if either fails. Non-dumpable is what keeps every handler
  away: the kernel produces no dump at all for such a process, so no pipe handler (apport, which
  ignores the core limit, or `systemd-coredump`) receives its memory, and no process of the same uid
  can attach to it or read its memory through `/proc`. The limit of 0 is the second layer, for the
  kernel's own core file and for `systemd-coredump`, which stores nothing for a process whose limit is
  0. `data/custodio.service`, the one unit every package format ships, keeps `LimitCORE=0` as a third
  and sets `MemorySwapMax=0`, the only protection against swap (no page of the service is swapped);
  the static unit check requires both. `MADV_DONTDUMP`, `mlock`, `memfd_secret` and
  `coredump_filter` are not used: the flag, the limit and the swap setting cover the whole process,
  the libraries' copies of the key included, which marking the service's own buffers would not.
  Hibernation writes all of memory to the swap device whatever the unit says:
  `docs/threat-model.md` and `docs/api.md` ("Storage kinds") say that the encrypted kinds need
  encrypted swap and an encrypted hibernation image. Root reading the running service's memory stays
  out of scope.

### 5. Documentation

All in English, in the repository, linked from the README. Commands they show are run by a test as
written, as M6 required; prose is checked by a person, never by a test that greps wording.

- **An end-to-end guide for Ubuntu 26.04** that a person follows without other help: install the
  `.deb`; run `custodio doctor` and act on it, including enrolling a finger with the desktop's
  tools; `sudo custodio setup fingerprint enable`; export a certificate from Firefox as a `.p12`
  (Firefox's certificate manager, "Your Certificates", backup) and import it; `custodio setup
  browsers enable`; restart Firefox and sign in to a site; `custodio list` and the completions; and
  the way back: `custodio delete`, `custodio setup browsers disable`, `sudo custodio setup
  fingerprint disable`, removing the package, and what removal and purge leave (as M2 decided for
  the state directory).
- **Fingerprint:** how to turn it on and off; exactly what it changes (one file, every polkit action,
  not `sudo`, not the login); the fallback to the password; the limits of the Threat model's "Not
  guaranteed"; what to do when `enable` refuses (Omarchy's own setup, an administrator's file, the
  global switches). The other supported systems are covered with their package names and what was and
  was not run.
- **The GNOME lock screen on Ubuntu:** that it accepts an enrolled finger through GDM's own PAM file
  and a GNOME setting, which Custodio does not manage; how to turn it off for the person (`gsettings set
  org.gnome.login-screen enable-fingerprint-authentication false`, run, report); and that the GDM login
  screen reads the `gdm` user's settings, which was not tested.
- **The Firefox restart** after an import or a delete.
- **`custodio doctor`:** every check, what each state means and its fix.
- **Updates** to `docs/install.md`, `docs/api.md`, `docs/audit.md`, `docs/threat-model.md`, the man
  page, `SECURITY.md` (scope: the fingerprint command writes a system PAM file), the changelog and the
  release notes of this release, which is 0.9.0.
- **Manual acceptance steps** for Acceptance 22 in `docs/manual-acceptance.md`, with a form to return.

## Language and harnesses

Rust for the product, as before. Every harness of M0–M6 stays and keeps blocking the merge at the same
thresholds: unit, integration and end-to-end tests (the container suite on every target, the VM suite
for the release); `cargo-mutants` with no surviving mutant; coverage and the CRAP gate; `cargo-fuzz`;
Miri and AddressSanitizer on the FFI layer; `rustfmt` and `clippy` with the service's restriction
lints; `cargo-machete` and `cargo-deny`; `taplo`, `typos`, `shellcheck`, `actionlint` and `zizmor`; the
systemd exposure score and the unit and bus-policy checks; the package gates (parity, lint, glibc
ceiling, snap-base fit); the API contract check; the documents' command tests; commitlint; and `just`
as the entry point.

The test pyramid holds: each requirement is proven at the lowest level that can prove it. M7 adds, all
blocking:

- **Unit tests** for every decision that does not need the system: whether a file is Custodio's, each
  refusal of `enable` and `disable` from an observed state, global-fingerprint detection from file
  contents, each `doctor` state and its fix, the help and argument parser, the table and the full view
  of `list`, escaping of certificate text, colour on and off, the two-line form of every error, and the
  three import cases.
- **Integration tests** of `setup fingerprint` against a fixture file system and of `doctor` against
  fixture homes and system files. Any seam that lets a test point them at a fixture never ships,
  with a check that the shipped binary has none (as the test-only label source and TCTI rules of
  `docs/decisions.md`). Import tests with real `.p12` files for (a), (b) and (c), against the real
  service, checking the D-Bus error and the journal outcome.
- **Fuzzing** of every new parser of untrusted input: the certificate fields `list` decodes, and the
  PAM and configuration files `setup fingerprint` and `doctor` read. The argument parser is fuzzed
  if it is not already.
- **Completions:** a test drives bash, zsh and fish (the real shells) to complete a command, an option
  and a key id against a running service, and checks that completion with the service absent prints
  nothing and returns promptly. The completion files pass `shellcheck` (bash) and their shell's syntax
  check (zsh, fish).
- **Package checks:** every format ships the three completion files in their loading locations and no
  PAM file; no package script mentions `/etc/pam.d`; the install notice names the fingerprint command
  and `doctor`.
- **End-to-end, container suite on every supported target**, as root on the real `/etc`: `enable`
  writes the exact file with the right mode, owner and (where SELinux is enforcing) label; a PAM client
  of service `polkit-1` with the override in place authenticates a test user by password through the
  include (there is no reader in a container, so `pam_fprintd` falls through); `enable` again changes
  nothing; each refusal (foreign file, missing vendor file, missing module) holds and changes nothing;
  `disable` restores the previous state byte for byte; where the distribution has them,
  `pam-auth-update` and `authselect` leave the override as it was. `doctor` runs on each target and
  reports, for that container, what is missing without error.
- **End-to-end, Ubuntu 26.04 VM**, a new group in the VM target's `full` mode with libfprint's virtual
  device as in `docs/findings/acceptance-6-fingerprint.md` and the report's method: after `enable`, a
  polkit authentication (`pkexec` or `pkcheck` with `pkttyagent`) is approved by the enrolled finger;
  an unenrolled finger and no touch fall back to the password, and a correct password approves; `sudo`
  asks for the password only (with any passwordless `sudo` rule of the harness out of the way); a
  Custodio signature is approved by the finger and leaves its journal entry; each fallback case
  (module, daemon, reader, finger missing) goes straight to the password; after `disable` the finger is
  no longer offered by polkit. A negative control (no touch, no password) stays unapproved. Like M5's
  and M6's VM cases, a release test and the last feature's `verify`; the feature that builds the group
  runs it alone once.
- **Supply chain:** no new crate without the existing `cargo-deny` policy; packages added inside the
  VM come from the distribution's signed archive and their versions are recorded in the run.

## Scope

- `custodio setup fingerprint enable` and `disable`, their refusals and messages, on every supported
  system.
- `custodio setup` grouping the setup commands; `custodio register` and `custodio fingerprint`
  removed.
- `custodio doctor` with the six checks.
- Help for every command, the `list` table and full view, colour rules, two-line errors, completions for
  bash, zsh and fish with key ids, shipped by every format.
- The import error split (service, API, audit, CLI), the storage-classifier finding and its fix or
  explanation, and the Firefox restart notice.
- The install notice; the documents of Design 5; the manual acceptance steps.
- The container cases on every target and the Ubuntu VM virtual-fingerprint group.
- Keeping decrypted `encrypted-*` keys out of swap and core dumps: `custodiod`'s own core limit of 0
  and non-dumpable flag, the two unit settings, and the documents on hibernation.
- The findings these need.

## Out of scope

- Any new client, and any new operation on keys or change to storage kinds, polkit actions or the
  never-cache rule.
- Making Firefox see key changes without a restart (Unassigned in `docs/milestones.md`).
- Changing `sudo`, the login, GDM, the lock screen or any PAM file other than `/etc/pam.d/polkit-1`;
  managing `org.gnome.login-screen` settings; enrolling fingers (the desktop's or `fprintd`'s tools do).
- Fingerprint for Custodio's actions only, or presence checks without polkit (Unassigned).
- Running the fingerprint VM group on any system other than Ubuntu 26.04; creating Debian 13 or
  RHEL/Alma 10 lab VMs (a person's task).
- Argument-parsing or completion-generating crates.
- Localisation of the CLI's messages.
- `MADV_DONTDUMP`, `mlock` or `memfd_secret` on key buffers; protecting a key from root reading the
  running service's memory; making hibernation keep keys off the disk (the documents require encrypted
  swap instead).

## Acceptance

Automated, on the host (unit, integration, fuzz and package checks):

1. `enable`, given a system with the vendor file, the module and `fprintd` and no
   `/etc/pam.d/polkit-1`, produces a file whose `auth`, `account`, `password` and `session` lines are
   exactly those of Design 1, mode `0644`, owner root; a second `enable` leaves it byte-identical and
   succeeds. With no reader it writes the same file, succeeds and prints the warning.
2. `enable` refuses, exits non-zero, prints a two-line error with the next step and changes nothing,
   for each of: not root; a foreign `/etc/pam.d/polkit-1` (an Omarchy-style file, an administrator's
   file, Custodio's file with one byte changed, a symlink); no vendor file; no `pam_fprintd.so`; no
   `fprintd`.
3. `enable` with fingerprint already active globally (each family's form) says so, writes nothing and
   exits non-zero with the next step.
4. `disable` removes Custodio's file and nothing else; with no file it succeeds and changes nothing;
   with a foreign file it refuses and the file is byte-identical afterwards.
5. No package format ships a file under `/etc/pam.d/` or `/usr/lib/pam.d/`, no package script refers
   to `/etc/pam.d`, and the install notice names `sudo custodio setup fingerprint enable` and
   `custodio doctor`.
6. `doctor` reports each of the six checks in each of its states on fixture systems and homes, names
   the fix for each unsatisfied one, reports a broken include of Custodio's override, says "could not
   check" (never "missing") when `fprintd` refuses to list fingers, exits 0 with checks 1 to 3
   unsatisfied and the rest satisfied, exits 0 when check 6 is only a warning, exits non-zero for a
   broken include or any other unsatisfied check among 4 to 6,
   refuses to run as root, and writes nothing (the fixture tree is byte-identical afterwards and no
   polkit request is made).
7. `custodio --help`, `custodio -h` and `custodio <command> --help` for every command print help on
   standard output and exit 0; a usage error exits 2 with the error on standard error; the help and
   the man page list the same commands and options.
8. `custodio list` prints one row per key with id, type, storage kind, subject and end of validity, and
   the weaker-storage note exactly once when any key has an encrypted kind and not at all otherwise;
   `custodio list <id>` prints that key with issuer, serial, start of validity and SHA-256 fingerprint;
   an unknown id is an error with the next step.
9. A certificate whose subject and issuer contain control characters, escape sequences and newlines is
   listed with all of them escaped: the output has no byte below 0x20 other than the line ends of the
   layout, no DEL, and the same number of rows as keys. The field parser has a fuzz target.
10. With standard output not a terminal, or with `NO_COLOR` non-empty, no command writes an escape
    sequence; on a terminal without `NO_COLOR`, colour appears.
11. Every error the CLI can print is at least two lines, the second a next step, and contains no
    password or key material (every error variant, including each D-Bus error of `docs/api.md`).
12. bash, zsh and fish complete the commands, options and the ids of the person's keys against a running
    service; with the service absent, completion prints nothing and finishes within a bound the
    contract sets. Every package format installs the three files where the shells load them.
13. Importing a `.p12` with a MAC and the wrong password gives the wrong-password D-Bus error, journal
    outcome and CLI message, whatever the file holds; an unreadable or unusable file gives the
    unreadable ones with the right password, and with any password when its defect shows without
    decrypting (see `SPEC_DEVIATIONS.md`, F195); a file without a MAC that does not decrypt gives the combined ones. None of these opens
    the file before polkit approves; `just api-contract` passes with the documented names.
14. The classifier finding names the cause of the `252:0` answers with evidence. Then either a test
    reproducing that cause gets the same answer at every start, or the service exposes the reason for
    the unavoidable `unknown`, `doctor` prints it with what to do, and `just api-contract` checks the
    addition. No test case turns an `unknown` into `encrypted`.
15. A successful `custodio import` and `custodio delete` print the note that Firefox and other running
    programs see the change after a restart.
16. Every command in the documents of Design 5 runs as written in a test.

Automated, end-to-end:

17. Container suite, every supported target, as root: `enable` writes the exact file with mode, owner
    and (Fedora, Alma) the default SELinux label; a PAM client of `polkit-1` authenticates a test user by
    password through the override; the refusals of acceptance 2 that a container can stage hold;
    `disable` restores `/etc/pam.d/` byte for byte; on Debian and Ubuntu `pam-auth-update --enable
    fprintd` and `--disable fprintd`, and on Fedora and Alma `authselect apply-changes`, leave the
    override byte-identical. `doctor` runs and exits as its checks dictate.
18. Ubuntu 26.04 VM, virtual sensor: with the override, the enrolled finger approves a polkit
    authentication and a Custodio signature (verified with `openssl`, journal entry present); an
    unenrolled finger and the 10-second timeout fall back to the password, which approves; the four
    fallback cases go straight to the password; `sudo` asks for the password and shows no fingerprint
    prompt; a negative control stays unapproved; after `disable`, polkit no longer offers the finger.
    The run records the polkit, fprintd, libfprint and `libpam-fprintd` versions.
19. If the VM group cannot stage the virtual sensor (no virtual driver in libfprint), it fails, not
    skips.

Manual (a person, following steps in `docs/manual-acceptance.md` and the user documents):

20. A person checks the fingerprint, lock-screen, Firefox-restart, `doctor` and end-to-end documents
    against Design 5 and the Threat model's "Not guaranteed": every item is present and agrees with
    `docs/api.md`, `docs/audit.md` and the report.
21. A person checks that `custodio --help` and each command's help, read alone, are enough to use the
    command.
22. On Ubuntu 26.04 with a real fingerprint reader and no Custodio installed, a person using only
    the documentation: installs the `.deb` and sees the install notice; runs `custodio doctor`,
    which names what is missing; runs `sudo custodio setup fingerprint enable`, after which `pkexec`
    takes the finger and `sudo` still asks for the password; imports a certificate exported from
    Firefox, approving with the finger; runs `custodio setup browsers enable`; signs in to a real
    site that requires a client certificate, approving with the finger; uses `custodio list` and the
    completions; sees `custodio doctor` report nothing to fix; then deletes the key, runs `custodio
    setup browsers disable` and `sudo custodio setup fingerprint disable`, removes the package, and
    records that `/etc/pam.d/polkit-1` is absent, the Firefox profiles hold no Custodio entry, no
    module copy is left, and nothing else Custodio wrote remains beyond what the documents say
    removal keeps. The form records the reader model, the package versions and every place the
    documents were not enough.

Automated, on the host, added with `custodio setup`:

23. `custodio setup browsers enable [--module <path>]`, `disable` and `refresh [--module <path>]`,
    and `custodio setup fingerprint enable` and `disable`, work as Design 3 specifies, proven by the
    existing tests of `register` and `fingerprint` run with the new arguments. `custodio register`
    and `custodio fingerprint` are unknown commands. `custodio setup` and `custodio setup <topic>`
    print that level's short help on standard error, ending with the next-step line, and exit 2;
    `--help` at every level prints that level's help on standard output and exits 0; the help and
    the man page list the same commands and options. bash, zsh and fish complete the topics after
    `setup` and the actions after each topic. The systemd user unit runs `custodio setup browsers
    refresh`.

Automated, end-to-end, added with the swap and core-dump settings:

24. The running service's unit has `MemorySwapMax=0` and `LimitCORE=0` (`systemctl show`), its
    process's own core-size limit reads 0 soft and hard (`/proc/<pid>/limits`) and it is not dumpable,
    and the static unit check fails a unit without either setting. In the Ubuntu 26.04 VM the
    service's cgroup has `memory.swap.max` 0, and a SIGSEGV of `custodiod` is not dumped (systemd
    records it killed by the signal, not dumped) and leaves no core and no crash report with memory
    where the handler writes, both with the shipped unit and with a drop-in that overrides its
    `LimitCORE=` to `infinity`. This holds under the core handler Ubuntu 26.04 ships by default
    (apport: no `/var/crash/*.crash` with a `CoreDump` field, nothing in `/var/lib/apport/coredump/`)
    and under `systemd-coredump` (nothing in `/var/lib/systemd/coredump/`). Under each handler a
    control process with `LimitCORE=infinity`, crashed the same way, is dumped and leaves its core
    there. If the VM cannot run either handler, the case fails, not skips.

## Open questions

- **The cause of `unknown` then `not-encrypted` on `252:0`.** Unknown until the finding (Design 4). If
  the cause is outside the service's view and no unit setting can wait for it without weakening the
  unit, the fallback is the explained `unknown`. If neither is possible, that is a `BLOCKED.md`
  question.
- **Debian 13 and RHEL/Alma 10.** Whether their polkit ships `/usr/lib/pam.d/polkit-1`, and whether the
  override behaves there as on the four systems run. The Debian sid file list shows
  `/usr/lib/pam.d/polkit-1` in `polkitd`; trixie's (126-2) was not confirmed. The container suite
  proves the password path and the file handling there; the finger itself needs a lab VM, which only a
  person may create. Settle by a person running the report's method on both; until then the command
  relies on its refusals.
- **Persistent journal detection** without root, across systemd 257 and later and each distribution's
  default (`Storage=auto` with or without `/var/log/journal`, drop-ins, volatile overrides), and the
  documented fix for each. Settle by a finding.
- **Completion locations** per format and distribution (bash-completion's directory; zsh's vendor
  directory differs between Debian and Fedora or Arch; fish's vendor directory), and how completion
  obtains key ids quickly without a polkit agent. Settle by a finding.
- **Double fingerprint prompt** when the global switch and an override are both on (untested). `enable`
  refuses to add the override then; whether `doctor` should flag an existing combination of both (for
  example Omarchy's file plus the global switch) depends on observing it. Settle by a VM run.
- **The GDM login screen.** Whether setting `enable-fingerprint-authentication` for the `gdm` user or
  in system dconf turns the fingerprint off at the login screen on Ubuntu 26.04 was not tested; the
  documents say so until a person tries it.