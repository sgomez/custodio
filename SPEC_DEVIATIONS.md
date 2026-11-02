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

## F89 — start `pkttyagent` only when no agent answers
- SPEC: section 6, "polkit without a graphical agent": "When stdin is a terminal and no agent answers for the session, the CLI starts `pkttyagent`".
- Proof: `docs/findings.md`, "F89: which agent answers": polkit has no call that tells whether an agent is registered; the only probes register an agent or start an authentication.
- Instead: on a terminal the CLI always starts `pkttyagent --fallback --process=PID,START_TIME` for its own process. polkitd uses a fallback agent only when the session has no other agent, so a graphical agent keeps answering. Evidence: the argument test (always `--fallback`, only the CLI's process), contract F89.
- Status: pending
