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

### 2026-11-12 — F170 — attempt 2
- Done: docs/findings/F170.md and its index line. Probes ran in the e2e VM (Ubuntu 26.04, systemd 259.9) and the ubuntu2604 container; polkit 123 to 127 sources read.
- Results: `PrivateUsers=yes` shows peers as 65534; `identity` keeps real uid below 65536 and score 0.7 (so no BLOCKED.md); `no` gives 0.8; p2p server `ANONYMOUS`; polkit 124+ accepts `{pidfd, uid}` from an owner caller, and does not check the claimed uid, so unmapped uid must be refused before polkit.
- Not done / known issues: identity under polkit not run (no polkit in VM, inferred); polkit 128 not read; systemd 257 behaviour inferred from its man page.
- Next session should: nothing for F170; the socket feature reads the Decision lines.
