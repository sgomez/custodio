# F146 — budgets: a person must decide

The verify passed; only four time budgets were exceeded, in the parallel `just check` / `just e2e`:

| item | measured (loop) | budget | lone run |
|---|---|---|---|
| e2e alma10 (swtpm) | 478 s | 470 s | 357 s (estimate, one target alone) |
| e2e arch (swtpm) | 420 s | 410 s | 307 s (estimate) |
| e2e debian13 (swtpm) | 707 s | 700 s | 605 s (estimate) |
| `scripts/test-install-real.sh` | 88 s | 60 s (default) | 11 s measured now, alone |

Why they cannot be made faster here:
- The three e2e overages are 1.7 % to 2.4 %. The runs are seven containers at once on 12 cores;
  the spread between runs is larger than the overage. The cases and phases are already parallel
  inside a target (see F143/F144 entries in PROGRESS.md); removing cases would weaken the gate.
- `test-install-real.sh` takes 11 s alone (three container runs of pacman -U plus the deb/rpm
  checks). The 88 s appear only while `just check` runs all script tests at once, so its time is
  contention on podman/disk, not work the script does.

Request: raise alma10 to 520 s, arch to 460 s, debian13 to 760 s, and give
`scripts/test-install-real.sh` 120 s in `budgets.tsv` (or tell me to cut cases instead).
`budgets.tsv` is untouched.
