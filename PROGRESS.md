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

### 2026-11-12 — F171 — attempt 1
- Done: docs/findings/F171.md and its index line, all five contract steps ticked. Probed in the e2e VM (image release-20261105).
- Results: image ships snapd 2.77.1 and AppArmor `Y`; Firefox 9181 / core26 / glibc 2.43 (ceiling 2.39), install 50 s, 1.22 GB; cache via `snap download` + `snap ack` + `snap install ./f` works offline (19 s) and tampering is rejected, but the decision is not to cache; label `snap.firefox.firefox (enforce)` via SO_PEERSEC, `/proc/self/attr/current` is denied in the snap; accept only that label; profiles in `~/snap/firefox/common/.mozilla/firefox/`.
- Not done / known issues: hook labels inferred from profile names (hooks cannot be started under `--shell`); second-boot payload copy inferred (host cannot fetch 1.2 GB through the guest; tested same-guest with the store blocked via proxy). BLOCKED.md skipped: the base is not older than the module supports.
- Next session should: nothing for F171; the VM snap feature reads the Decision lines.
