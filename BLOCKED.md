# F45 is blocked: the required real run needs a change to the dev container

Everything of F45 is built and `just check` passes (see PROGRESS.md), except the last step: the real `just e2e debian13` and `just e2e`.
`docs/findings.md` ("F45: a systemd container cannot boot in the dev container") has the commands and errors: the dev container maps a single
uid, so the image's packages cannot be installed with their owners, and the container cannot get its own PID namespace (`mount proc: Operation
not permitted`), so systemd cannot be PID 1.

Question: how should the real run be made?
1. Give the dev container a user namespace with subuid/subgid ranges and permission to mount `/proc` (rootless podman able to run `--privileged`
   systemd containers), then I run `just e2e debian13` and `just e2e` and paste the results.
2. Run `just e2e debian13` and `just e2e` on a host that can (a person), and put the output and the record file in PROGRESS.md.
3. Accept the stub test in place of the real run (the contract says it is not a substitute; this would need a contract change by a person).
