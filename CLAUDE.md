# Custodio — agent guide

`SPEC.md` says what we are building. `features.json` lists the features for this milestone, in
dependency order, each with a `verify` command. Before a feature is built, its contract in
`contracts/<id>.md` says how each requirement will be proven, and an evaluator approves it. You
build; a separate evaluator and the loop decide whether a feature passes. `harness/README.md`
explains the whole flow.

## Language

Everything in this repository is in English: code, comments, docs, commit messages, issues and PRs.

## Every session

1. **Get your bearings.** Read the latest entries in `PROGRESS.md`, `NEXT_FINDINGS.md` if it exists
   (the evaluator's or the loop's findings from the previous attempt; fix those first), and
   `git log --oneline -15`. Run `just quick`; if it is red, fix that before anything else.
2. **Build one feature, following its contract.** Only the feature you were given; do not start the
   next one, even if you have context left. Tick contract steps as they are done. Change the
   rest of the contract only by an amendment the evaluator approves (`harness/builder-prompt.md`).
   A feature may take several sessions.
3. **Tests first.** Write the failing test, then the code. Between steps run only that test and
   the tests of the code you touched (`cargo test -p <crate> <filter>`). When every step is ticked,
   run `just quick` once and the contract's evidence (and `just mutants-diff <id>` if the `verify`
   has it) until they pass; the loop runs the `verify`. Never run `just check`, `just e2e`
   or the package gates: they run at the checkpoint features and the release.
   Run every command in the foreground with `timeout`; background tasks and polling loops are
   blocked.
4. **Hand off.** Append an entry to `PROGRESS.md` (template in that file) and commit with a
   [Conventional Commits](https://www.conventionalcommits.org) message scoped to the feature id,
   e.g. `feat(F05): add key store with 0700/0600 permissions`. Types: `feat`, `fix`, `docs`,
   `test`, `refactor`, `perf`, `build`, `ci`, `chore`, `style`, `revert`. Lower-case description,
   header and body lines up to 100 characters. commitlint (`@commitlint/config-conventional`)
   enforces it in the commit-msg hook, the loop and CI; the changelog (`just changelog`, git-cliff)
   is generated from these messages.

## Protect the context window

- Use subagents for reading outside material (siguldry-pkcs11, cryptoki-sys, zbus, polkit and
  PKCS#11 docs, crate sources) and for broad searches. Ask them for conclusions, not file dumps.
- Never print whole build or test logs. Use `tail`, `grep`, or `--quiet` flags.
- Anything the next session must know goes in `PROGRESS.md` or `docs/decisions.md`, not only in
  this conversation: the next session starts with an empty context.

## Rules

- Never edit `SPEC.md`, `features.json` or `APPROVALS`. A person approves the spec and the feature
  list; only the loop marks a feature as passing.
- Never weaken a gate to get green: no deleting or `#[ignore]`-ing tests, no lowering thresholds,
  no `#[allow(...)]` without a comment that justifies it, no turning a `just` recipe into a no-op.
- Key material and passwords live in `secrecy` / `zeroize` types and never reach `Debug`, logs or
  error messages.
- Every signature calls polkit. Never cache an authorization.
- When `SPEC.md` does not decide something, choose the more conservative option. Record it in
  `docs/decisions.md` only if a later session could undo it without knowing why; follow the rules
  at the top of that file. What a feature builds and how goes in the commit and the code; fixes in
  the commit; research in `docs/findings.md`.
- If a `SPEC.md` requirement cannot be met by anything this project ships, and a finding in
  `docs/findings.md` proves it (a tool's source or a command you ran, not a guess), do not block:
  record a deviation in `SPEC_DEVIATIONS.md` (format at the top of that file), amend the contract
  to the narrowest replacement, and go on. The evaluator approves it with the amendment; a person
  reviews every deviation before the milestone closes. Never for the security rules above, nor
  for a requirement that is only hard or costly.
- If you cannot continue without a human (a decision the spec does not cover and that is hard to
  undo, missing credentials, a change to the dev container or the host, a contradiction with
  `SPEC.md` that is a choice rather than an impossibility, a `verify` command that cannot work),
  write `BLOCKED.md` with the question and the options, commit your work so far, and stop. A
  contract that cannot hold is amended instead.
