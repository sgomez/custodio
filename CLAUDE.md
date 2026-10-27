# Custodio — agent guide

`SPEC.md` says what we are building. `features.json` is the contract: the list of features for
this milestone, in dependency order, each with a `verify` command. You build; a separate evaluator
and the loop decide whether a feature passes.

## Language

Everything in this repository is in English: code, comments, docs, commit messages, issues and PRs.

## Every session

1. **Get your bearings.** Read the latest entries in `PROGRESS.md`, `NEXT_FINDINGS.md` if it exists
   (the evaluator's or the loop's findings from the previous attempt; fix those first), and
   `git log --oneline -15`. Run `just check` once it exists; if the tree is red, fix that before
   anything else.
2. **Build one feature.** Only the feature you were given. Do not start the next one, even if you
   have context left.
3. **Tests first.** Write the failing test, then the code. Run the feature's `verify` command until
   it passes.
4. **Hand off.** Append an entry to `PROGRESS.md` (template in that file) and commit with a message
   that starts with the feature id, e.g. `F05: Add key store with 0700/0600 permissions`.

## Protect the context window

- Use subagents for reading outside material (siguldry-pkcs11, cryptoki-sys, zbus, polkit and
  PKCS#11 docs, crate sources) and for broad searches. Ask them for conclusions, not file dumps.
- Never print whole build or test logs. Use `tail`, `grep`, or `--quiet` flags.
- Anything the next session must know goes in `PROGRESS.md` or `docs/decisions.md`, not only in
  this conversation: the next session starts with an empty context.

## Rules

- Never edit `features.json`. Only the loop marks a feature as passing.
- Never weaken a gate to get green: no deleting or `#[ignore]`-ing tests, no lowering thresholds,
  no `#[allow(...)]` without a comment that justifies it, no turning a `just` recipe into a no-op.
- Key material and passwords live in `secrecy` / `zeroize` types and never reach `Debug`, logs or
  error messages.
- Every signature calls polkit. Never cache an authorization.
- When `SPEC.md` does not decide something, choose the more conservative option and record it in
  `docs/decisions.md` (date, decision, why, alternatives) in a few lines.
- If you cannot continue without a human (a decision the spec does not cover and that is hard to
  undo, missing credentials, a `verify` command that cannot work), write `BLOCKED.md` with the
  question and the options, commit your work so far, and stop.
