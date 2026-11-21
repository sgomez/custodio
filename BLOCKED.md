# F213 blocked: archive.archlinux.org is unreachable from the dev container

Step 1 (`CHECK_FORCE=1 just check`) fails on two scripts that build the Arch image:
`scripts/test-install-real.sh` and `scripts/test-arch-lifecycle-real.sh`. Both stop at
`pacman -Syyuu` against `https://archive.archlinux.org/repos/${ALA_DATE}/...`:
`failed retrieving file 'extra.db' ... Connection timed out after 10001 milliseconds`.

Checked: `curl -m 20 https://archive.archlinux.org/repos/` → `000` (timeout), three times over about
10 minutes; `https://geo.mirror.pkgbuild.com/` → 200. Rerun of the arch script alone fails the same way.
The `arch` e2e target, `just package-gates` and the Arch install cases need the same archive, so steps 2 and 3
cannot pass either. The skip switch `CUSTODIO_SKIP_ARCH_INSTALL=1` would skip a group, which the contract forbids.

Everything else in `just check` passed (84 scripts). `test-vm-gap-map.sh` failed once in the first full run
("noplain-no-key-file is not in the VM case list") and passed alone and in the second full run: flaky under
the parallel script run, cause not found yet.

Question / options:
1. Restore network access to archive.archlinux.org from the container (proxy/firewall), then rerun F213.
2. A person decides the Arch image may pin a reachable mirror (a change to the Arch Containerfile and its date pin).
