# F45: the dev container must be rebuilt and restarted before the real run

The answer (option 1) is applied in commit 7145e19: `harness/run.sh` adds `--privileged` for podman, and `harness/Containerfile` sets
`/etc/subuid` to `dev:1:999` and `/etc/subgid` to `dev:1001:64535`. `just check` passes.

This session still runs in the old container (`/etc/subuid` is empty, not started with `--privileged`), so `just e2e debian13` fails
the same way as before (`chown ... Invalid argument`, dpkg error in the image build). A session cannot restart its own container.

Needed from a person: restart the loop with `harness/run.sh` (it rebuilds the image and starts the container privileged). The next
session then runs `just e2e debian13` and `just e2e` and records the results in PROGRESS.md.
