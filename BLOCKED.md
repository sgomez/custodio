# F168 blocked: the container end-to-end suite cannot boot systemd in this dev container

`just e2e` fails on all six targets with `systemd did not boot (state: )`. Probe (this session, 2026-11-10):
- `podman run --rm --privileged ... custodio-e2e-debian13 /bin/true` works; with the image's `/lib/systemd/systemd` as PID 1 the container exits 255 with no output (also with `--log-level=debug`).
- `/sys/fs/cgroup` is root-owned (`stat` root 755) and `mkdir /sys/fs/cgroup/xx` as `dev` fails (Permission denied); the session is in `0::/`. Rootless podman cannot give systemd a writable cgroup.
- The same suite passed on Nov 7 (M4 logs in `target/e2e`), so the dev container or host changed (cgroup delegation).

Question: restore a delegated, writable cgroup subtree for the `dev` user in the dev container (or tell me another way to boot systemd containers). Options: (a) fix the dev container's cgroup delegation; (b) run the container targets on another host.

Also pending after this: budget rows for `vm full` (measured 8m23) and `vm lacking` (7m10), which the loop's time check does not read (`budgets.tsv` has an `ubuntu2404` row left for a person to remove). Steps done: 1, 2, VM full+lacking, gap evidence, package-gates. Not run: `just coverage`, `just crap` (next session).
