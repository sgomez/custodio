# Blocked: F42 — pacman does not abort an installation when `pre_install` fails

The contract (Scope, step 4) says: if pacman ignores a failing `pre_install`/`pre_upgrade` and no mechanism aborts the installation,
write `BLOCKED.md` and stop. That is the case; evidence in `docs/findings.md` ("F42 — Does pacman stop an installation ...").

With the real `pacman -U`, a `pre_install` that returns 1 only prints `error: command failed to execute correctly`; the package is
installed and the exit status is 0. Sending SIGINT to the parent does not stop it either. A hook shipped in the package cannot guard
its own first installation, because libalpm loads hooks before the package is unpacked.

SPEC.md and the F42 description say the installation fails on a bus without ProcessFD. For Arch that is not possible from inside the package.

## Options (a person decides; the choice changes the F42 contract and maybe SPEC.md / features.json)
1. Arch warns, does not refuse. `pre_install`/`pre_upgrade` run the same check and print the refusal message loudly, but the install
   goes on (the service refuses to sign at runtime anyway, so nothing is exposed). deb and rpm refuse. The contract's Arch cases would
   assert the message and the real pacman behaviour (installed, rc 0) instead of an abort. Needs SPEC.md/features.json wording to say
   "refuses on deb and rpm, warns on Arch".
2. Option 1 plus a `PreTransaction` hook with `AbortOnFail` shipped in the package: it makes every upgrade and reinstall refuse, but the
   first installation still goes through with the warning.
3. Express the requirement as a package dependency on Arch (a `dbus` version known to provide ProcessFD) instead of a script check.
   That ties the package to a version, not to the capability; whether it is acceptable is the SPEC's call. The first dbus release with
   ProcessFD was not researched here.
4. Drop Arch from F42 (Arch package stays without a pre-install check) and record it in SPEC.md.

Recommended: option 2 (conservative: refuses wherever the package manager can be made to refuse, and says so on the rest).

## State of the work
- `packaging/bus-check.sh` (the check, shellcheck-clean, not yet embedded or tested) is committed; deb `preinst` and rpm `%pre` use it unchanged
  whatever the answer. Nothing else of F42 is started: no tests, no gates, no `just test-scripts`.
- Query-tool choice made while building: `busctl` (systemd) first, `dbus-send` second, queried for `org.freedesktop.DBus`'s own
  credentials; a present socket with neither tool is refused. Both tools were tried against a private dbus-daemon 1.16 here.
- Contract note: it says the reply to "its own unique name" is parsed; one-shot tools cannot know their unique name, so the check asks
  for the bus's own credentials and reads `ProcessFD` only from a successful reply (an error text naming ProcessFD does not count).
  The contract may need a small amendment to say so.
