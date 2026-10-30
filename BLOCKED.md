# BLOCKED — F38

Steps 2 onward need the real linters, and the dev container cannot run them:
the session is uid 1000 without sudo, with neither podman nor docker. lintian does not run from extracted debs (missing Perl
modules), rpmlint 2.8.0 exists only on Fedora, namcap needs an Arch container (branch 2, see docs/findings.md). Without a runtime
there are no raw findings, no `/usr/lib/custodio/custodiod` result and no `reports/package-lint-container.txt`.

Step 1 (research) is done: `packaging/lint/pins.txt` and `docs/findings.md`.

Question: how should the loop get a container runtime?
1. Run the loop on a host with podman/docker (rootless podman in the dev image needs `--device /dev/fuse` or vfs storage and
   subuid/subgid), or mount the host socket.
2. Allow `sudo` and network at build time so the dev image installs lintian and a podman, and accept running rpmlint and namcap in
   containers only in CI (the contract's "real container" evidence then comes from a CI run, which the contract does not allow today).
3. Narrow the contract (a person edits it) so that rpmlint/namcap run only in CI.
