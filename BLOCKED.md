# BLOCKED — F159 needs a person: rebuild the dev container

F159 is built and committed; `verify` (stubs) does not need the rebuild. The checkpoint needs it so `lacking` can boot.

1. Rebuild the dev container (`harness/run.sh` rebuilds `custodio-dev` from `harness/Containerfile`). The last layer now downloads the four swtpm 0.10.2 / libtpms 0.10.2 `.deb` files,
   checks their sha256 (those of `docs/findings/F152.md`; a wrong one fails the build) and unpacks them into `/opt/swtpm` with `dpkg-deb -x`. swtpm 0.7.1 stays the system `swtpm`.
2. Then `just vm-host-check` must exit 0 (it has a new `swtpm-profile` line, MISSING on 0.7.1), and `/opt/swtpm/usr/bin/swtpm` must print `0.10.2` with
   `LD_LIBRARY_PATH=/opt/swtpm/usr/lib/x86_64-linux-gnu/swtpm:/opt/swtpm/usr/lib/x86_64-linux-gnu`.
