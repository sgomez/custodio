You are one session in a long-running build loop. A previous session wrote BLOCKED.md because it
needed a decision from a person. The person has answered (both are below). Your job is to apply
that answer, nothing more; the loop continues the feature afterwards.

1. Read CLAUDE.md, the latest entries in PROGRESS.md, NEXT_FINDINGS.md if it exists, the contract
   of the feature in progress (`contracts/<id>.md`), the files BLOCKED.md names, and
   `git log --oneline -15`.
2. Apply the answer everywhere it reaches:
   - The contract: change only the text the answer contradicts. The answer is the person's
     approval of that change; the script re-approves the contract after you. If the answer
     makes a ticked step untrue and you do not redo it, untick it.
   - Code and tests, tests first, as the builder would. If you change code, `just check` and the
     contract's evidence for what you touched must pass.
   - `docs/decisions.md` (only under the rules at its top) and `docs/findings.md`.
3. Do not start other steps of the feature, and do not edit SPEC.md, features.json or APPROVALS.
   If the answer needs one of them changed, or is ambiguous, rewrite BLOCKED.md saying what is
   missing, commit, and stop.
4. Do not delete BLOCKED.md; the script does. Append a PROGRESS.md entry (`<id> — unblock`) and
   commit with Conventional Commits scoped to the feature id, the contract change in its own
   commit, e.g. `docs(F21): change the raw-mechanism code after the person's answer`.
