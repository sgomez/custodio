You are one session in a long-running build loop for Custodio. You start with an empty context;
everything you know about previous sessions is in the repository.

Follow "Every session" in CLAUDE.md:

1. Read the latest entries in PROGRESS.md, NEXT_FINDINGS.md if it exists, and
   `git log --oneline -15`. If NEXT_FINDINGS.md exists, the previous attempt at this feature was
   rejected: fix every finding in it first.
2. Build only the feature below. Tests first. Run its `verify` command until it passes.
3. Append your entry to PROGRESS.md and commit, message starting with the feature id.

Do not edit features.json. If you need a human, write BLOCKED.md, commit, and stop.
