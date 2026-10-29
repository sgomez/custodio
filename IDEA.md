Milestone: M2

M2 makes Custodio installable on every supported distribution, not only Debian 13: the versions
whose bus has `ProcessFD` and that their distribution still maintains, which are Debian 13, Ubuntu
26.04, Fedora 44, RHEL/Alma 10 and Arch. `just package` builds the `.deb`, the `.rpm` and an Arch
`.pkg.tar.zst` with nfpm from one file list, replacing `cargo deb`, and the end-to-end suite runs
in a container for each of them. Upgrading the package keeps the keys and restarts the service with
them; removal and purge have a decided behaviour for the state directory, since keys cannot be
exported. Ubuntu 24.04 requires `dbus-broker`, or the package refuses to install if switching the
bus breaks something; it never installs on `dbus-daemon`. Acceptance is repeated by hand on the
`fedora44` VM (SELinux enforcing, Firefox), on `bazzite` with the `.rpm` layered through rpm-ostree,
on `omarchy` (Firefox, its Quickshell polkit agent) and on `ubuntu2404` with `dbus-broker`. Nothing
is published: repositories wait for M5.

Earlier milestones are archived in docs/milestones/; build on the code that already exists.
Number this milestone's features from F36.
