Milestone: M7

M7 stabilises 0.8.0 into a release that a person can install and use end to end on Ubuntu 26.04 with a
fingerprint reader, without reading the source; it adds no client. Everything it builds must work on every
supported system; Ubuntu is where it is accepted by hand.

Fingerprint. Signing with a finger already works, because polkit authenticates through PAM, but Ubuntu's
`pam-auth-update --enable fprintd` turns it on for `sudo` and everything else too. A new command,
`sudo custodio fingerprint enable` and `disable`, turns it on for polkit only: it writes `/etc/pam.d/polkit-1`
with one `pam_fprintd.so` line (`[success=done default=ignore]`, `max-tries=1 timeout=10`) and an `include` of
the vendor file `/usr/lib/pam.d/polkit-1` for each PAM type. This was run on Ubuntu 26.04, Fedora 44, Bazzite
and Arch: the override takes precedence, a wrong finger or no touch falls back to the password, `sudo` is
unchanged, a missing module, daemon, reader or finger goes straight to the password, and `pam-auth-update`,
`authselect` and a new rpm-ostree deployment leave the file alone. Debian 13 and Alma 10 were not run. The
command never overwrites a `/etc/pam.d/polkit-1` it did not write (Omarchy's own scripts write one) and
`disable` removes only its own. The package does not touch PAM: its install notice names the command. The
command is proven in a VM with libfprint's virtual device (`docs/findings/acceptance-6-fingerprint.md`), not
only by hand. The runs, the exact file, the refusals `enable` needs and the read-only checks for
`doctor` are in `docs/reports/polkit-fingerprint.md`.

`custodio doctor`. A read-only command that says what is missing and the command that fixes it: a reader, an
enrolled finger, fingerprint active for polkit (through the override or globally, and whether the override's
include still resolves), the module registered in Firefox, a persistent journal, and what the service found
about the storage of its state directory.

The command line. `custodio --help` and `custodio <command> --help` print real help on standard output with
status 0. `custodio list` prints one row per key (id, type, storage, subject, end of validity), with the note
about weaker storage once at the foot; `custodio list <id>` prints one key in full. Colour only on a terminal
and never with `NO_COLOR`. Every error says the next step on a second line. The package installs completions
for bash, zsh and fish, key ids included. Arguments stay parsed by hand; no `clap`.

Bugs of 0.8.0. The import reports a wrong password and an unreadable format as one error; the service gets a
new D-Bus error and a new audit outcome so that the CLI and the journal tell them apart (a file with no MAC
keeps a combined message, because the library cannot tell there). The storage classifier answers `unknown`
and, later, `not-encrypted` for the same LVM volume on an unencrypted partition (device 252:0): find the
cause first, then fix it, or have `doctor` explain an `unknown` that cannot be avoided. Firefox does not see a
key imported or deleted until it restarts: `import` and `delete` say so; making it see the change is not in
this milestone.

Documentation. How to turn the fingerprint on and what it changes; that Ubuntu accepts a finger on the GNOME
lock screen as soon as one is enrolled, through GDM's own PAM file and a GNOME setting, which Custodio does
not manage, and how to turn that off; the Firefox restart.

Done when a person, on Ubuntu 26.04 with a real reader and no Custodio installed, completes these steps using
only the documentation: install the `.deb`; `custodio doctor` names what is missing; `sudo custodio
fingerprint enable`, after which `pkexec` takes the finger and `sudo` still asks for the password; import a
certificate exported from Firefox, approving with the finger; `custodio register`; sign in to a real site
with the finger; `custodio list` and the completions work; `custodio doctor` reports nothing; then delete the
key, `custodio register --remove`, `sudo custodio fingerprint disable` and remove the package, leaving the
system as it was. The other systems are covered by the automated end-to-end suite and the virtual-device test.

Earlier milestones are archived in docs/milestones/; build on the code that already exists.
Number this milestone's features from F189.
