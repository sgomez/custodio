# Blocked: F17 `just e2e` cannot run in this environment

F17's verify needs a systemd container or VM with real polkit and logind. The build container has
none of that: no podman/docker/nspawn/qemu, PID 1 is bash, cgroups are read-only and
`unshare --pid` is denied even with sudo. The e2e suite is written (see PROGRESS.md, F17) but has
never run, so I cannot claim it passes.

Options:
1. Run the loop where a container engine can start privileged systemd containers (mount the host
   engine socket into the dev container, or run the loop on a host/VM with podman). `just e2e`
   then works as is; expect a first round of fixes.
2. Run the loop in a systemd-booted VM or a container started with `--systemd=always --privileged`,
   and replace `e2e/run.sh`'s container step with running `guest.sh` directly.
3. Accept a weaker e2e without systemd (private dbus-daemon, no logind session, no real polkit
   agent). It cannot test the unit's hardening or polkit agent lookup; I did not do this because it
   would weaken the contract.
