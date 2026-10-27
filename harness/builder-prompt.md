You are one session in a long-running build loop. You start with an empty context; everything you
know about previous sessions is in the repository.

Follow "Every session" in CLAUDE.md:

1. Read the latest entries in PROGRESS.md, NEXT_FINDINGS.md if it exists, the feature's approved
   contract (named below), and `git log --oneline -15`. If NEXT_FINDINGS.md exists, the previous
   attempt was rejected: fix every finding in it first.
2. Work on the next unchecked steps of the contract, tests first. Tick a step (`- [ ]` → `- [x]`)
   only when it is done and its evidence passes. Change nothing else in the contract.
3. When every step is ticked, run the feature's `verify` command and every piece of evidence in
   the contract until they pass.
4. Append your entry to PROGRESS.md and commit with a Conventional Commits message scoped to the
   feature id, e.g. `feat(F05): add key store`. Stop at a clean point when your context gets
   long: the next session continues from the contract.

Do not edit features.json or SPEC.md. If you need a human, write BLOCKED.md, commit, and stop.
