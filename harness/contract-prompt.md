You are one session in a long-running build loop. Before anyone writes code for the feature below,
you write its contract: what will be built and how each requirement will be proven. An
independent evaluator must approve it.

Read CLAUDE.md, the feature's entry in features.json, the parts of SPEC.md it touches, and the
code that already exists. Use subagents for outside material. Then write `contracts/<id>.md`
(for example `contracts/F09.md`) in this format:

```
# <id> — <title>

## Scope
What will be built, and what is explicitly left for other features.

## Steps
- [ ] One step per line, each small enough for one session, in the order you will build them.
- [ ] A conditional step starts with its condition ("Outcome B only: ..."); if it does not hold, the
      builder marks it `- [-]`.

## Evidence
- <requirement> → <test name or command> → <expected result>
```

Say what must be proven, not how to build it: flags, paths and tool choices belong to the builder
unless SPEC.md or `docs/decisions.md` fixes them. Do not forbid outright something nobody has
researched yet; if a step researches it, let that step decide within limits the contract states.

Every point in the feature description must appear under Evidence, with evidence that would fail
if the feature were wrong. Prove each behaviour once, at the cheapest level that would catch it
being wrong. If another feature's description or `verify` in features.json names the same check,
point to that feature under Scope instead of proving it here. A few negative controls show that a
test can fail; build no mutant sets beyond what `verify` runs. Package gates, the install and
lifecycle tests and `just e2e` run at the checkpoint features (F90, F100), not here: a
requirement that only they prove is listed under Scope as proven at the checkpoint. A feature
whose `verify` runs `just e2e-cases` proves its own cases with them. If the feature is too big for about five steps, say so under Scope and
propose a split; do not edit features.json.

If a requirement depends on the environment (a container engine, privileges, network, a device,
a tool not pinned in mise.toml), run the smallest command that shows the dev container can do it,
and put the command and its result under Scope. If it cannot, the contract says how the requirement
will be met instead (a deviation or a person's run) before anything is built.

Do not write code in this session. Commit the contract with a message like `docs(F09): add contract`.
