# SPEC deviations

Requirements of SPEC.md that nothing this project ships can meet, and what is built instead. A
builder adds an entry with the contract amendment; the evaluator approves both; a person reviews
every entry before `just milestone close`: updates SPEC.md and sets `accepted`, or sets `rejected`
with what to build instead.

Format:

```
## <feature id> — <requirement, in a few words>
- SPEC: section and the sentence that cannot hold.
- Proof: the finding in docs/findings.md (source or command run).
- Instead: what is built, and its evidence in the contract.
- Status: <pending when added; accepted or rejected by a person>
```
