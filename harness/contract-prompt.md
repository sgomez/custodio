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

## Evidence
- <requirement> → <test name or command> → <expected result>
```

Every point in the feature description must appear under Evidence, with evidence that would fail
if the feature were wrong. If the feature is too big for about five steps, say so under Scope and
propose a split; do not edit features.json.

Do not write code in this session. Commit the contract with a message like `F09: Add contract`.
