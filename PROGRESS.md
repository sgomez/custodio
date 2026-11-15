# Progress

Each session appends one entry at the bottom. Keep entries short: the next session reads them
with an empty context.

## Template

```
### <date> — <feature id> — <attempt n>
- Done:
- Decisions (also in docs/decisions.md if lasting):
- Not done / known issues:
- Next session should:
```

## Sessions

### 2026-11-15 — F189 — attempt 1
- Done: `docs/findings/F189.md` + index line. Cause not reproduced (**inferred**): kernel (`dm.c` `dm_setup_md_queue`) exposes
  `slaves` before `dm/uuid` but all before any mount, and systemd 257 adds `RequiresMountsFor=` for `StateDirectory`; the same
  LVM code is in 0.8.0 and HEAD. Fixture runs (scratch example, deleted) give `NotEncrypted` for a complete chain, `Unknown` for each gap.
  No dm device can be created here (checked as root via `sudo -n`, which works: no `/dev/mapper`, no `dmsetup`, no `/dev/loop-control`, `CapEff` lacks `CAP_MKNOD`). F180 rules stand. `just quick` green, `verify` passes, no product code changed.
- Decisions: route 2 (keep `unknown`, expose an enumerated reason, no unit setting).
- Next session: F196 builds route 2 under the `docs/api.md` compatibility rule.

### 2026-11-15 — F190 — attempt 1
- Done: `docs/findings/F190.md` + index line; all contract steps ticked. `podman` pulls and runs all five targets, so defaults are
  **verified** (package contents, real `systemd-journald` + `SIGUSR1` flush). Precedence, masking, last-wins, invalid/empty value
  ignored, case/section rules verified by journald runs (not `cat-config`). 259+ default `persistent` (NEWS, run on ubuntu/fedora/arch);
  Alma 10 (257) has no `/var/log/journal` after install. `/run/log/journal` is never used. `just quick` green, `verify` passes.
- Decisions: unset `Storage=` takes the `#Storage=<v>` line of the main file; invalid values and any non-ENOENT error are "could not check".
- Next session: F203 implements the `Decision: ` line.
