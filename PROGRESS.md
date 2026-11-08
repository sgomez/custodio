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

### 2026-11-08 — F150 — attempt 1
- Done: `docs/findings/F150.md` (+ index), `scripts/vm-host-check.sh`, `scripts/test-vm-host-check.sh` (in `test-scripts`), `just vm-host-check`,
  Containerfile VM packages (+gpgv), `run.sh` `--device /dev/kvm --group-add keep-groups` when the host has the device. `just quick` green; self-test passes.
- Decisions: host facts and runner are **inferred** (docs only); the "host change needed" step is `[-]`: no host change is known until the person pastes `ls -l /dev/kvm; id`.
  Unconfirmed: `-accel help` listing kvm, `gpgv` package name on trixie (the check will show).
- Not done: the rebuild (a person's); `just vm-host-check` passes only on the rebuilt container. BLOCKED.md written.
- Next session should: after the rebuild, run `just vm-host-check`; mark host facts **verified** from the pasted output; fix the finding if KVM is absent.

### 2026-11-08 — F150 — attempt 2
- Done: container rebuilt (crun); `just vm-host-check` exits 0 here (nine OK lines). Evaluator notes checked: the self-test already uses a regular-file KVM stub and exact `MISSING <label>:` matches; the finding now says its first evidence block is the pre-rebuild container.
- Not done: nothing; the loop runs the `verify`.

### 2026-11-08 — F151 — attempt 1
- Done: `docs/findings/F151.md` (+ index): image/checksum URLs, serial, retention (oldest listed serial 2026-04-23), verified download with negative controls, QEMU command line, serial-console channel with `cloud-localds` seed, guest facts, `has-tpm2` before/after, power cycle with control. All contract steps ticked; `verify` greps pass, `just quick` green.
- Decisions: channel = serial console on a unix socket (no `ssh` in the container); seed tool `cloud-localds`.
- Known: `libtss2-rc0t64` alone leaves `has-tpm2` `partial`; esys and mu are also needed (tpm2-tools pulls them). One idle `swtpm` (pid 32088, from my first failed start) cannot be killed from the tool sandbox (`Permission denied`); it ends with the container. No qemu left; the `/tmp` dir is removed.
- Next session should: nothing for F151; the loop runs the `verify`.
