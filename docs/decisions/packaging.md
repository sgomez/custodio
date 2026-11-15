# Decisions: packaging

Decisions about the package scripts and file layout, under the rules at the top of
`docs/decisions.md`. Read this file before touching `packaging/` or the package checks.

## 2026-10-30 — Package version scheme and the place of the service binary
- Decision: the version comes from the workspace: `X.Y.Z-pre` is `X.Y.Z~pre-1` (.deb), release `1`
  with `~pre` (.rpm), `X.Y.Z_pre` pkgrel 1 (Arch). The binary is at `/usr/libexec/custodio/custodiod`
  in the .deb and .rpm and `/usr/lib/custodio/custodiod` in Arch (`packaging/parity-exceptions.txt`);
  one `data/custodio.service`, with `ExecStart` derived per format by `scripts/derive-units.sh`.
  The D-Bus activation file keeps `Exec=/bin/false`.
- Why: from `/usr/lib/custodio` (`lib_t`) Fedora runs the service in `init_t` and its key files get
  `init_var_lib_t` (F54, F55); from `/usr/libexec` (`bin_t`) it is `unconfined_service_t`. Arch has
  no `/usr/libexec`. A real `Exec=` would start the service outside the unit's hardening.
- Rejected: `/usr/lib/custodio` everywhere; `/usr/libexec` on Arch; two unit files; an `Exec=` in
  the activation file; an SELinux policy module (out of scope).

## 2026-10-30 — The install-time ProcessFD check refuses when it has no tool to ask with
- Decision: `packaging/bus-check.sh` asks with `busctl`, else `dbus-send`. A bus socket with
  neither tool is refused with a message to install one; only an absent socket (or nothing
  listening) is "no bus" and installs with a notice.
- Why: installing silently would hide a bus without ProcessFD; the rpm and Arch scripts have no
  pre-dependency, so the deb's `Pre-Depends: systemd` is not relied on.
- Rejected: a missing tool as "no bus"; a tool of our own (nothing can be added for a script that
  runs before the package); pre-depending on dbus.

## 2026-10-30 — The deb pre-depends on systemd and creates the account in preinst
- Decision: `systemd` is in the deb's `Pre-Depends`, not `Depends`. `preinst` creates the account
  with `systemd-sysusers -` from the embedded sysusers text (`scripts/check-sysusers-sync.sh`), on
  `install` and `upgrade`; if that fails, nothing is unpacked.
- Why: dpkg unpacks the bus policy before `postinst` and `dbus-daemon` may load it at once; in one
  transaction `Depends` may not be unpacked when `preinst` runs. Debian policy 7.2 allows this case:
  do not drop it as lint hygiene.
- Rejected: a `useradd` fallback (a second account definition); the account in `postinst`; skipping
  it without the tool. Move `systemd` back to `Depends` only if `preinst` stops needing it.

## 2026-10-30 — Deb scripts: restart marker in /run, notice on stderr, purge as remove
- Decision: `preinst upgrade` creates `/run/custodio-restart-after-upgrade` if the service is
  active; `postinst configure OLD` restarts once only if it exists, and removes it. The removal
  notice goes to stderr on `remove` and `purge`. `postrm remove|purge` stops the service again if
  it is active after the reloads.
- Why: the marker is the only state from `preinst` to `postinst` and must not be under the state
  directory; maintainer stdout can carry debconf's protocol; the second stop covers a D-Bus
  activation between `prerm` and the removal of the files.
- Rejected: `try-restart` in `postinst` (restarts a service started after `preinst`); the marker
  under `/var/lib`; one notice per transaction (another marker).

## 2026-10-30 — Rpm scriptlets: account in %pre from stdin, restart by marker, no systemd macros
- Decision: `%pre` runs the F42 check, `systemd-sysusers -` with the embedded line, and on upgrade
  notes `is-active` in the `/run` marker; the new `%post` reloads, updates the catalog and restarts
  once if the marker exists. No `user()` provide, `%posttrans`, `Requires(pre)` (nfpm cannot write
  it) or `%systemd_*`/`%sysusers_*` macro (nfpm leaves them unexpanded). `%preun 0` stops; `%postun 0`
  reloads, stops again if active, and prints the notice on stderr.
- Why: the old package's `%preun`/`%postun` run after the new `%post`, so only the new package can
  decide; `%systemd_postun_with_restart` is a try-restart that does nothing in a chroot; a `user()`
  provide would create the account before the F42 check. `rpm-ostree uninstall` runs no scriptlet:
  a deviation (`docs/milestones/M2/SPEC_DEVIATIONS.md`, F44).
- Rejected: `%posttrans` (its `$1` cannot tell install from upgrade); `systemd-update-helper`
  (absent in a chroot, enables on install); a `useradd` fallback.

## 2026-10-30 — Arch: hooks do the reloads and the catalog, the account is made in pre_*, a hook restarts
- Decision: the scripts call no `daemon-reload`, bus reload or `journalctl --update-catalog` (the
  system hooks do). `pre_install`/`pre_upgrade` create the account after the F42 check. The restart
  on upgrade is the PostTransaction hook `zz-custodio-restart.hook` (`try-restart`); `pre_remove`
  stops the service.
- Why: a script runs before all PostTransaction hooks, so a reload there is a second call and a
  restart would precede the daemon reload (`docs/findings/F58.md`).
- Rejected: `enqueue-marked` with `Markers=needs-restart` (runs before `dbus-reload`); reloads in
  `post_*`; a marker file; a `useradd` fallback.

## 2026-11-13 — The Firefox snap socket on install and upgrade (F173)
- Decision: the scripts `start` `custodio-firefox.socket`, never `restart` it. For a running service on upgrade they stop it, start the
  socket, then start it again (deb and rpm `restart`; Arch `systemctl start` in `post_upgrade`, and `zz-custodio-restart.hook` restarts it
  once more after the reloads). Deb uses `deb-systemd-invoke` for starts and stops (except the final start of the static service after an upgrade, which it refuses, so that one is `systemctl restart` after postinst asks `policy-rc.d` itself: exit 0 or 104 or no `policy-rc.d` restarts, anything else does not), so `policy-rc.d` is honoured.
- Why: systemd refuses to start a socket while its service is active; a restart of the socket stops the service and leaves it down.

## 2026-11-15 — The zsh completion lives in a different directory in the .deb (F191)
- Decision: `_custodio` is in `/usr/share/zsh/vendor-completions/` in the .deb and in `/usr/share/zsh/site-functions/` in the .rpm and the
  Arch package; bash and fish paths are the same in all three. F205 adds two presence entries to `packaging/parity-exceptions.txt`
  (`…/vendor-completions/_custodio | deb`, `…/site-functions/_custodio | rpm,arch`).
- Why: the default zsh `fpath` of Debian and Ubuntu has `vendor-completions` and not `site-functions`, and Fedora, Alma and Arch the reverse
  (`docs/findings/F191.md`).
- Rejected: shipping both in every format (a dead copy everywhere and an unowned directory in the .rpm); `site-functions` everywhere (not
  loaded on Debian and Ubuntu).
