# Custodio — Milestone 2: Packaging and distributions

M2 builds on the code of M0 and M1 (`docs/milestones/M0/SPEC.md`, `docs/milestones/M1/SPEC.md`,
results in `docs/findings.md`). Everything those milestones established stays true unless this
document says otherwise. This milestone's features are numbered from F36. Nothing is published:
package repositories, signing keys for packages and public download pages wait for M5.

## Problem

Custodio installs only on Debian 13, as a `.deb` built by `cargo deb`, and the end-to-end suite runs
only on a Debian 13 container. But the people who sign with FNMT certificates use Ubuntu, Fedora,
RHEL-family and Arch systems as well, and rFirma (M3) will want to point them at a package for their
system. Custodio's security rests on the system bus exposing `ProcessFD`, so polkit can bind every
authorization to a pidfd instead of a reusable PID (`docs/findings.md`, section 3). That holds only
on some releases, so "installable" has to mean "installable only where it is safe".

The supported set is the releases whose bus has `ProcessFD` and that their distribution still
maintains: **Debian 13, Ubuntu 26.04, Fedora 44, RHEL/Alma 10 and Arch**. Ubuntu 24.04 is a special
case: its default `dbus-daemon` (1.14.10) lacks `ProcessFD`, but its `dbus-broker` (35) has it.

Three things are missing today:

- **Packages for the other families.** No `.rpm` or Arch package exists, and the `.deb` metadata
  lives in `cargo deb` configuration that cannot produce the other formats.
- **Evidence on those systems.** Nothing has run on Fedora, Alma or Arch. SELinux, rpm-ostree,
  other polkit agents and other bus daemons have not been tried.
- **A lifecycle.** The `.deb` has only a `postinst`. Nobody has decided or tested what an upgrade,
  a removal or a purge does. That matters more than usual, because keys cannot be exported: if the
  state directory is deleted, the keys are gone.

## Threat model

M0 and M1's threat model still holds. M2 changes it as follows.

- **In scope:**
  - **Installing where authorization is weak.** If the package installs on a system whose bus lacks
    `ProcessFD`, polkit quietly falls back to PID subjects, and those can be raced. The package must
    refuse such a system where the package manager allows it (on Arch it can only warn on the first
    installation; see design section 2), and the service must refuse to sign on one even if it got
    installed anyway.
  - **Losing the keys, or exposing them, through the package lifecycle.** An upgrade, reinstall,
    removal or purge must not delete, rewrite, re-own or loosen the permissions of the state
    directory or the key files. If it did, the store would reject the keys (`docs/decisions.md`,
    "Key store refuses instead of repairing"), or worse, accept keys anyone could read.
  - **Maintainer scripts run as root.** They must not read, copy, print or log key material. They
    must not widen the bus policy, the polkit action or the unit's hardening.
  - **Build supply chain.** The packaging tool and the container base images become part of what
    ships. The packaging tool is pinned like every other tool.
- **Out of scope:** everything M0 and M1 exclude (same-uid hostile processes, root, physical access,
  a compromised kernel, journal tampering by root). Also out of scope: a hostile package mirror, the
  integrity of package downloads (nothing is published or signed until M5), and an administrator who
  deliberately switches the system bus to an unsafe daemon after installing. The runtime check below
  limits the damage from that last case, but nothing stops an administrator from doing it.
- **Not guaranteed:**
  - **SELinux confinement.** Custodio ships no SELinux policy. On Fedora and Alma the service is
    expected to run in a generic unconfined service domain. M2 shows only that SELinux does not get
    in its way. SELinux adds no protection for Custodio.
  - **Erasure after removal.** Keys left behind after a removal or purge stay on disk, readable by
    root, until an administrator deletes them. Deleting a file is not secure erasure.
  - **In-flight requests during an upgrade.** A signature that is waiting for polkit while the
    service restarts may fail. It must never succeed without its journal entry.

## Goal

On each supported distribution, one command on the build host produces a package that the system's
own package manager installs, upgrades and removes. The full end-to-end suite passes on that system,
and the keys survive every lifecycle step except one that a person performs deliberately by hand.
The package refuses (on Arch: warns on the first installation and refuses upgrades and reinstalls),
and the service fails closed, on any system whose bus cannot give polkit a
pidfd.

## Design

The runtime architecture does not change: `custodiod` on the system bus as `com.rfirma.Custodio1`,
polkit asked for every signature, the thin PKCS#11 module registered through p11-kit, one journal
entry per signature. M2 changes how that ships and adds one runtime check.

### 1. One file list, three formats

- **Tool.** nfpm builds the `.deb`, the `.rpm` and the Arch `.pkg.tar.zst` from **one**
  configuration that lists every installed file once: its source, destination, mode and owner. This
  replaces `cargo deb`. The `cargo deb` metadata and the tool itself leave the repository and the
  development image. nfpm is pinned with the other tools (`mise.toml`).
- **Per-format differences** are limited to what the formats force: package metadata, dependency
  names (for example `polkitd` on Debian and Ubuntu, `polkit` on Fedora, Alma and Arch), and the
  lifecycle scripts. Each format gets its own scripts. The contents may differ only when a
  distribution's rules require it, and each such difference is listed in the repository with its
  reason (see Open questions, Arch and `/usr/libexec`). The goal is a single set of paths, so the
  unit, the D-Bus activation file and the p11-kit module file stay single files.
- **What ships** is the same set as M1's `.deb`: the service, the CLI, the PKCS#11 module, the
  systemd unit, the sysusers file, the D-Bus policy and activation files, the polkit action, the
  p11-kit module file and the journal catalog. Everything goes under `/usr`. The package installs
  nothing in `/etc` and nothing in `/var`. That keeps it compatible with image-based systems
  (rpm-ostree), and it means no format has configuration files to merge.
- **One package per format, not per release.** The same `.deb` serves Debian 13, Ubuntu 26.04 and
  Ubuntu 24.04. The same `.rpm` serves Fedora 44 and Alma 10. Every shipped binary must therefore run
  on the oldest C library among those targets, and a gate checks this (see Harnesses). How the build
  meets that ceiling is the builder's choice.
- **Dependencies.** Each package declares its runtime needs: systemd, the system bus, polkit and
  p11-kit. Where the format can express it, the package also declares the minimum polkit that
  accepts pidfd subjects (124, `docs/findings.md` section 3). Dependency declarations cannot prove
  which bus daemon is *running*, so the bus check below exists as well.
- **Architecture:** x86_64 only, as today.
- **Entry point.** `just package` builds all three on the host, into a known output directory.
  `just e2e` uses them.
- **Prior art:** nfpm's own examples for multi-format packages. Debian's `dh_installsystemd` and
  `dh_installsysusers` scripts, Fedora's `%systemd_post`/`%systemd_preun`/`%systemd_postun_with_restart`
  and sysusers handling, and systemd's pacman hooks on Arch are the reference for what each
  format's scripts should do. Copy their behaviour, not their text.

### 2. Lifecycle

The behaviours below are decisions. Each format implements them with its own conventions.

- **Install.**
  - Create the static `custodio` account from the sysusers file before the bus loads the policy
    that names it (`docs/decisions.md`, "Static `custodio` user").
  - Make systemd and the bus see the new unit and policy, and register the journal catalog.
  - Do not enable or start the unit at boot. D-Bus activation starts it, as today.
  - Do not touch the state directory. systemd creates it on first start.
- **Bus check before installing.** If a system bus is running, the package checks before it
  changes anything that the bus returns `ProcessFD` in its connection credentials. If it does not,
  the installation fails with a message that names the reason and points to the documentation (on
  Ubuntu 24.04: switch to `dbus-broker` and reboot). The check tests the capability. It does not
  check the daemon's name or the distribution: `dbus-daemon` 1.16 on Debian 13 passes, and
  `dbus-daemon` 1.14 on Ubuntu 24.04 fails. Open questions covers what happens when no bus is
  running (chroot, image build, rpm-ostree).
  On Arch, pacman installs the package even when `pre_install` fails, and a hook shipped in the
  package does not run on its own first installation. So on Arch `pre_install` and `pre_upgrade`
  print the same message and the first installation goes on, and a `PreTransaction` hook with
  `AbortOnFail` runs the check and refuses every later upgrade and reinstall. The runtime refusal of
  design section 3 is what keeps that first installation safe (`docs/findings.md`, F42).
- **The package never switches the system bus itself.** Switching affects the whole system and
  takes effect only after a reboot. The documentation describes how to switch on Ubuntu 24.04.
- **Upgrade.**
  - The state directory and the `custodio` account stay as they are: same uid, same owner, same
    modes, same files.
  - If the service was running, it is restarted once the new files are in place and the bus policy
    has been reloaded, so the service that answers afterwards is the new binary. If it was not
    running, D-Bus activation starts the new binary on the next call.
  - The person runs no manual step.
  - Upgrading from the last `.deb` built by `cargo deb` to the first one built by nfpm is an
    upgrade like any other.
- **Removal** (`apt remove`, `dnf remove`, `pacman -R`, `rpm-ostree uninstall`):
  - Stop the service and remove every packaged file.
  - **Keep the state directory and the `custodio` account.** The account is kept because system
    accounts are not removed by convention on any of these distributions, and because a reinstall
    must find the keys owned by the same uid. Otherwise the store rejects them.
  - Print a notice saying that the keys are still on disk, where they are, and that deleting them
    by hand destroys them for good.
- **Purge** (`apt purge`; the other formats have no purge): **the same as removal.** The state
  directory is never deleted by a package script. Debian's convention is that purge removes a
  package's data. Here that data is private keys that cannot be exported or recreated, so one
  mistyped command would destroy a person's signing identity. The documentation gives the manual
  command that destroys the keys. The person approving this spec may reverse this decision. If so,
  purge must at least ask for confirmation, as the MySQL and PostgreSQL packages do for their
  databases.
- **Reinstall after removal:** the kept keys are listed and sign again without a new import.
- **Downgrade** is not supported and not tested. It must still never delete the state directory.

### 3. The service refuses a bus without `ProcessFD`

- When `custodiod` reads the caller's connection credentials for a `Sign` call, it asks for
  `ProcessFD` as well as the uid and pid it reads today. If the bus does not return `ProcessFD`, the
  signature is refused before polkit is asked. The call leaves the M1 journal entry for
  "authorization not possible" (the outcome M1 already has for missing credentials). This catches a
  bus that was switched after installation, an installation without a running bus, and any path the
  install-time check misses.
- Where the information is available without loosening the unit, the service also checks that the
  pidfd and the reported pid name the same process, as `docs/findings.md` M1.2 recommends. A
  mismatch is treated the same way. The exposure gate keeps its threshold. If this cross-check
  cannot be done within the current hardening, the presence check alone is the requirement, and
  the builder records why.
- This changes no D-Bus interface and no audit field name. Whether the entry should say *why*
  authorization was not possible is for the builder to decide under the additive-change rule of
  `docs/audit.md`.

### 4. End-to-end on every target

- The existing suite runs in a systemd container of each supported target: Debian 13, Ubuntu 26.04,
  Fedora 44, Alma 10 (the RHEL 10 stand-in; Alma is covered only here) and Arch. Each container runs
  the distribution's real polkit and its default system bus daemon. Each run records which daemon
  and which polkit version it used.
- The package is installed with the target's own tool (`apt`/`dpkg`, `dnf`, `pacman -U`), never by
  copying files. As today, the image does not contain the package.
- `just e2e` runs one target or all of them. A target whose base image cannot provide a test tool
  (for example `pkcs11-provider` on Alma 10) may skip only the cases that need that tool. Those
  skips are listed in the repository, per target and with a reason, and the suite fails if any case
  is skipped that is not on the list.
- **Lifecycle cases** run in the containers as well: upgrade, removal, purge (Debian family),
  reinstall, and the refusal on a bus without `ProcessFD` (an Ubuntu 24.04 container on its default
  `dbus-daemon`).
- **Limits.** Containers do not run SELinux, rpm-ostree or a graphical polkit agent. Those are
  covered by the manual runs below and only there.
- **Prior art:** the current `e2e/` harness. The per-distribution container matrices of projects
  such as systemd's `mkosi` tests and Cockpit's test images show how to keep one test script across
  distributions.

### 5. Manual acceptance machines

These are repeated by hand, following written steps shipped in the repository, on:

- `fedora44`: Fedora 44 Workstation, SELinux enforcing, Fedora's packaged Firefox;
- `bazzite`: an atomic Fedora, with the `.rpm` layered through rpm-ostree;
- `omarchy`: Omarchy 4 on Arch, Firefox, with Omarchy's Quickshell polkit agent (part of
  `omarchy-shell`), not polkit-gnome;
- `ubuntu2404`: Ubuntu 24.04 with the system bus switched to `dbus-broker`.

### 6. Journal storage

M1 left open whether the package should require persistent journal storage. Decision: the package
does not change journald's configuration, because that belongs to the administrator and to other
packages. The administrator documentation explains how to check that storage is persistent and why
it matters for the audit trail. Whether the install scripts should warn about volatile storage
stays an open question.

## Language and harnesses

Rust for the code, as before. Packaging configuration and maintainer scripts use nfpm's format and
POSIX shell. Every M0 and M1 harness stays and keeps blocking the merge with the same thresholds
(tests, mutation testing, coverage report with the CRAP gate, fuzzing, Miri and ASan, lints,
`cargo-deny`, `cargo-machete`, `taplo`, `typos`, `shellcheck`, `actionlint`, `zizmor`, the systemd
exposure score, the unit and bus-policy checks, commitlint).

M2 adds:

- **Package build gate.** `just package` builds all three packages. The step fails if any package
  is missing or if any file in the list is missing from a package.
- **One-file-list parity.** A check lists the installed paths, modes and owners of the three
  packages. It fails if they differ, apart from the differences listed in the repository.
- **C library ceiling.** A check reads every ELF file in the packages. It fails if any of them needs
  a glibc symbol version newer than the oldest glibc among the targets the packages install on
  (including Ubuntu 24.04).
- **Package linters:** `lintian` for the `.deb`, `rpmlint` for the `.rpm`, `namcap` for the Arch
  package. If the host lacks a linter, it runs in a container of the target distribution. Any
  finding fails the check unless it is in a committed exception list where each entry has a reason.
- **Maintainer scripts** are covered by `shellcheck`, whatever their file names.
- **Runtime bus check:** integration tests show that a `Sign` call whose credentials lack
  `ProcessFD` is refused, does not ask polkit, and leaves exactly one journal entry with the
  "authorization not possible" outcome. The credential-reading code stays under mutation testing.
- **End-to-end matrix:** `just e2e` for every target, plus the lifecycle cases. These block a
  feature from passing. Whether CI also runs them is an open question, because they need privileged
  containers.
- **Supply chain:** nfpm is pinned by version in `mise.toml`, with a checksum where mise supports
  one. `cargo-deb` is removed from `mise.toml`, the development image and CI.

## Scope

- nfpm packaging from one file list: `.deb`, `.rpm` and `.pkg.tar.zst`, from `just package`.
- Lifecycle scripts for each format, with the install, upgrade, removal, purge and reinstall
  behaviour above.
- The bus check at install time, and the runtime refusal in `custodiod` when `ProcessFD` is
  missing.
- The end-to-end suite and the lifecycle cases in containers of Debian 13, Ubuntu 26.04, Fedora 44,
  Alma 10 and Arch, plus the refusal case on Ubuntu 24.04 with `dbus-daemon`.
- The new gates above.
- Documentation for administrators: installing on each target, switching Ubuntu 24.04 to
  `dbus-broker`, what removal and purge leave behind and how to destroy keys deliberately, and
  persistent journal storage.
- Manual acceptance on `fedora44`, `bazzite`, `omarchy` and `ubuntu2404`.

## Out of scope

- Publishing anything: repositories, package signing, AUR or COPR entries, download pages (M5).
- Releases outside the supported set: Debian 12, Ubuntu 22.04, Ubuntu 25.10, RHEL 9, Fedora 43 and
  earlier, every openSUSE release. Ubuntu 24.04 counts only with `dbus-broker`.
- An SELinux policy module for Custodio; AppArmor profiles.
- Snap, Flatpak and systemd-sysext packages; Firefox as a snap or Flatpak; Mozilla's own Firefox
  builds that ignore p11-kit (see `docs/milestones.md`, Unassigned).
- Architectures other than x86_64.
- Downgrades; migrating keys between machines; any change to key storage (M4).
- Changes to the PKCS#11 module, the D-Bus interface, the polkit action or the audit field names.
- rFirma integration (M3).

## Acceptance

Automated (`just package`, `just e2e`, or CI):

1. `just package` on the build host produces exactly one `.deb`, one `.rpm` and one `.pkg.tar.zst`
   from a single nfpm configuration. The repository no longer contains `cargo deb` metadata, and no
   recipe uses `cargo deb`.
2. The parity check shows that the three packages install the same paths with the same modes and
   owners, apart from the differences listed in the repository.
3. The C library ceiling check passes for every ELF file in every package.
4. `lintian`, `rpmlint` and `namcap` report nothing outside their committed, justified exception
   lists.
5. For each of Debian 13, Ubuntu 26.04, Fedora 44, Alma 10 and Arch, the package installs with the
   target's own package tool in a systemd container. Every check of the end-to-end suite that M1
   automated then passes there: composed and raw signing, polkit asked once per signature, denial,
   polkit unavailable, the NSS checks, and the journal checks. Only cases on that target's committed
   skip list may be skipped.
6. On each of those targets, after keys are imported with package version N, installing a version
   N+1 with the target's tool:
   - keeps the key files byte-identical, with the same owner and modes;
   - lists the same keys and signs with them, with polkit asked;
   - leaves the service, if it was running before, running the new binary afterwards;
   - needs no manual step.

   On Debian 13, the same holds for an upgrade from the last `.deb` built by `cargo deb` to the
   first `.deb` built by nfpm.
7. On each of those targets, after removal (and after `apt purge` on Debian 13 and Ubuntu 26.04):
   - the service is not running, and no packaged file remains;
   - the bus name `com.rfirma.Custodio1` cannot be activated;
   - the state directory and its key files are still present and unchanged, and the `custodio`
     account still exists;
   - the removal printed where the keys are.

   Reinstalling the package afterwards lists the same keys, and they sign without a new import.
8. In an Ubuntu 24.04 container running its default `dbus-daemon`, installing the `.deb` fails with
   a message that names the missing `ProcessFD` support. Afterwards no Custodio file is installed,
   the package is not configured, and nothing listens on `com.rfirma.Custodio1`.
9. An integration test shows that a `Sign` call whose bus credentials lack `ProcessFD` returns no
   signature, does not ask polkit, and leaves exactly one journal entry with the "authorization not
   possible" outcome.
10. On each target in step 5, a journal entry of `custodio.service` shows the explanation from
    Custodio's journal catalog (for example with `journalctl -x`).
11. Every gate of M0 and M1 still passes with its threshold unchanged.

Manual (a person, following written steps that the milestone ships in the repository; each run
records the OS release, kernel, bus daemon and version, polkit version, and the package file names):

12. **`fedora44`, SELinux enforcing.**
    - The `.rpm` installs with `dnf`, and a `.p12` imports.
    - Fedora's packaged Firefox lists the certificate without manual registration and uses it for
      TLS client authentication. Each signature shows the polkit dialog, and cancelling makes it
      fail.
    - The audit log shows no SELinux denial involving the service, polkit or the module during
      import, signing and denial.
    - The documented `journalctl` query shows one entry per signature and per cancellation.
13. **`bazzite`.**
    - The `.rpm` is layered with `rpm-ostree`, and after a reboot a `.p12` imports.
    - A signature through the module from the host shows the polkit dialog, and cancelling makes it
      fail.
    - After the layered package is replaced by a newer version and the machine reboots, the same
      keys still sign. They also still sign after an OS update and a reboot.
    - No SELinux denial involves the service.
14. **`omarchy`.**
    - The `.pkg.tar.zst` installs with `pacman -U`.
    - Omarchy's Quickshell polkit agent shows the dialog for each signature. A second signature
      asks again, and cancelling makes it fail.
    - Firefox lists the certificate and uses it for TLS client authentication. If it needs manual
      registration, the run records that and the open question below decides the outcome.
15. **`ubuntu2404`.**
    - Before the switch to `dbus-broker`, installing the `.deb` is refused as in step 8.
    - After following the documented switch and rebooting, the desktop session, logind, the polkit
      agent and NetworkManager work. The run records anything that broke.
    - The `.deb` then installs, imports a `.p12`, and signs with the polkit dialog on every
      signature. Cancelling makes the signature fail.

## Open questions

- **Arch and `/usr/libexec`.** Arch's packaging standards ask packages to put helper binaries in
  `/usr/lib/<pkg>/`, not `/usr/libexec`, where the service lives today. Options: (a) one path that
  every distribution accepts, such as `/usr/lib/custodio/custodiod`, for all three formats; (b) a
  listed Arch-only difference, which means a second unit and activation file; (c) ignore the rule,
  since nothing is published to Arch repositories. Proposed: (a), because it keeps one unit file.
  Settle by having the person approving the feature list confirm it, and by checking that
  `namcap` and `rpmlint` accept it.
- **Ubuntu 24.04: does switching the bus break something?** The milestone wants Ubuntu 24.04 with
  `dbus-broker`. If the switch breaks the desktop or system services (acceptance step 15), should
  the package refuse Ubuntu 24.04 altogether, even with `dbus-broker`? Settled by step 15 (F57,
  `docs/findings.md`): the switch broke nothing checked on Ubuntu 24.04.5, so Ubuntu 24.04 is
  accepted with `dbus-broker` and refused on `dbus-daemon`; the capability check decides.
- **polkit 124 and the bus pidfd.** `docs/findings.md` takes polkit 124 as the first release with
  pidfd support from its NEWS. It has not confirmed that polkit 124 (Ubuntu 24.04) reads
  `ProcessFD` from the bus rather than falling back to the PID. If it does not, Ubuntu 24.04 is
  unsafe even on `dbus-broker`. Settled (F41, `docs/findings.md` section 3a): polkit 124, and
  Ubuntu 24.04's `124-2ubuntu1.24.04.4`, takes the caller's pidfd from `ProcessFD`.
- **Installing without a running bus** (chroot, image build, rpm-ostree, whose scriptlets run
  offline with `/var` read-only). The install-time check cannot run there. Proposed: install
  anyway, print a notice, and rely on the runtime refusal of design section 3. The alternative,
  refusing, breaks rpm-ostree layering, which the milestone requires. Settle when the person
  approves this spec.
- **Purge.** This spec keeps the keys on purge. If the person approving the spec prefers Debian's
  usual behaviour, purge must ask for confirmation before deleting. Settle by approval.
- **Restart during a pending signature.** Restarting on upgrade fails a signature that is waiting
  for polkit. Should the upgrade wait for the service to go idle? Proposed: no; fail closed and
  document it. Settle if the manual runs show it in practice.
- **Firefox on Arch and Omarchy.** Fedora's NSS registers p11-kit's proxy module in new NSS
  databases, so Fedora's Firefox should see the module without registration. Whether Arch's Firefox
  does the same has not been checked. If it does not, options: document a manual registration; ship
  a registration mechanism (which belongs with the "Firefox without p11-kit" item in
  `docs/milestones.md`); or accept TLS client authentication on Omarchy through another NSS client
  for M2. Settled by acceptance step 14 and the person approving the milestone.
- **Test tools on Alma 10 and Arch.** It is not confirmed that `pkcs11-provider`, OpenSC, the NSS
  tools and the Python D-Bus bindings that the suite needs are available in Alma 10's base and
  AppStream repositories (or only with EPEL) and on Arch. Settle while building the Alma and Arch
  images. Each gap becomes an entry on that target's skip list, with a reason, or EPEL is used if
  the person approving accepts it.
- **End-to-end in CI.** The matrix needs privileged containers that can run systemd. Today `just
  e2e` runs only locally. Should CI run it on every merge, nightly, or not at all? Settle by trying
  it on the CI runners and measuring the time it takes.
- **Version and release numbers.** How the workspace version maps to the Debian revision, the RPM
  release and Arch's `pkgrel`, and how the upgrade test gets an "N+1" package. Proposed: derive all
  three from the workspace version, and have the test build N+1 from the same tree with only the
  version raised. Settle in the first packaging feature and record it in `docs/decisions.md`.
- **Volatile journal warning.** Should the install scripts warn when journald storage is volatile?
  Proposed: documentation only, since the Debian 13, Ubuntu, Fedora, Alma and Arch defaults
  persist. Settle by checking each target's default in its container.
- **Which bus daemon Arch runs by default.** `docs/findings.md` assumes `dbus-daemon`, but Arch may
  have moved to `dbus-broker`. This does not change the design, because the check tests a
  capability, but the findings should be corrected. Settle from the Arch container run, which
  records the daemon.
