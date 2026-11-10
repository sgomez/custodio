# F168 — alma10 e2e time over budget (needs a person)

`budgets.tsv` has `e2e alma10 540`. Measured in the loop's verify: 812 s. My rerun alone (`E2E_TPM=swtpm just e2e alma10`) took
about 840 s. Earlier today, with the same code, the same target took 437 s (attempt 2: 692 s wall for all six).
The other five runs of the verify are within their rows (arch 340, debian13 645, fedora44 368, ubuntu2604 333, debian13 none 448).

Cause (measured, not a case): the AlmaLinux guest runs `dnf install` with the cache cleaned (`dnf clean all` in the Containerfile),
so one `dnf` call per run downloads the BaseOS metadata, 55 MB, from a mirror chosen at random by `mirrors.almalinux.org`.
A probe with `dnf -v makecache` in the image: BaseOS 55 MB at 825 kB/s = 68 s. In the slow runs the phase that fetched it was
`m3-install` 424 s (verify run) and `install` 599 s (my rerun); in the fast run it was 11 s. No test case is slow: the sum of all
other alma10 phases is about 340 s. The time is the speed of an external mirror, so it varies from run to run.

Options for a person:
1. Raise the `e2e alma10` row (about 1.3× the slow runs: ~1100 s), accepting mirror noise.
2. Allow a harness change: a host dnf metadata cache shared by the runs (a changed `e2e/run.sh` mount; it changes how the
   install is resolved, so it is a choice, not mine to make).

Also: `budgets.tsv` still has an `ubuntu2404` row (target gone, F156); left for the person. VM times (full 8m23, lacking 7m10 in
attempt 1) are not read by the loop.
