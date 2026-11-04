You are one session in a long-running build loop. You start with an empty context; everything you
know about previous sessions is in the repository.

Follow "Every session" in CLAUDE.md:

1. Read the latest entries in PROGRESS.md, NEXT_FINDINGS.md if it exists, the feature's approved
   contract (named below), and `git log --oneline -15`. If NEXT_FINDINGS.md exists, the previous
   attempt was rejected: fix every finding in it first.
2. Work on the next unchecked steps of the contract, tests first. Tick a step (`- [ ]` → `- [x]`)
   only when it is done and its evidence passes. A step whose own condition (e.g. "Outcome B
   only") does not hold is marked `- [-]` instead, and PROGRESS.md says why. Change nothing else
   in the contract, except through an amendment (below).
   Between steps, run only the test you are writing and the tests of the code you touched
   (`cargo test -p <crate> <filter>`), never `just check`, `just e2e`, the package gates or the
   `verify`.
3. When every step is ticked, run `just quick` once, the contract's evidence, and
   `just mutants-diff <id>` if the `verify` has it. A full run can take 10-20 minutes: run it
   once, with `timeout 1700`. While killing survivors, rerun only them, narrowed to their tests:
   `--re <regex> -- --lib <filter>`. Run the full diff again only at the end. Do not run the whole `verify`: the loop runs it as the gate. The package, install
   and e2e suites run at the checkpoint features and the release, and failures there are fixed
   there. Run every command in the foreground with `timeout`; background tasks and polling loops
   are blocked.
4. Append your entry to PROGRESS.md and commit with a Conventional Commits message scoped to the
   feature id, e.g. `feat(F05): add key store`. Stop at a clean point when your context gets
   long: the next session continues from the contract.

If a fact found while building means the contract cannot hold as written, amend it instead of
blocking: edit `contracts/<id>.md`, add a line under `## Amendments` with what changed and the
finding behind it, untick any step it makes untrue, and commit that change alone as
`docs(<id>): amend contract to ...`. The evaluator reviews it before the loop goes on. An amendment
never weakens a gate.

When SPEC.md does not decide something and the conservative option is easy to undo, decide it
yourself and go on. When a finding proves a SPEC.md requirement impossible for anything this
project ships, record a deviation as CLAUDE.md says and amend the contract in the same commit;
do not block. Write BLOCKED.md only for what needs a person: credentials, a change to the dev
container or the host, a contradiction with SPEC.md or features.json that is a choice rather than
an impossibility, or a hard-to-undo decision SPEC.md does not cover. Research goes in
`docs/findings/<id>.md` under the rules at the top of `docs/findings.md`: the conclusion and the
lines that prove it, never a whole output. Check every claim about the environment by running it before you write it.

Do not edit features.json or SPEC.md. If you need a human, write BLOCKED.md, commit, and stop.
