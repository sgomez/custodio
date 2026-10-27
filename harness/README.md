# Harness

How Custodio gets built by agents, from idea to milestone, following Anthropic's articles on
long-running agents: a planner writes the spec, an initializer splits it into features, and each
feature is built by fresh sessions and judged by a separate evaluator. People approve the spec and
the feature list; agents do the rest.

```
IDEA.md ──planner──▶ SPEC.md ──[you approve]──▶ initializer ──▶ features.json ──[you approve]──▶
  for each feature whose dependencies pass:
    builder writes contracts/<id>.md ──evaluator: APPROVED / REVISE──┐ (up to 3 rounds)
    builder sessions tick the contract's steps, one fresh context each ◀┘
    verify command (no LLM) ──▶ evaluator: PASS / NEEDS_WORK ──▶ loop marks it passing
```

## Run

From the repository root on your machine, with Docker or Podman:

```bash
export CLAUDE_CODE_OAUTH_TOKEN=...      # once: claude setup-token
harness/run.sh                          # runs harness/pipeline.sh in the dev container
```

Run it again after each stop: it picks up where it left off.

| Stops with | Meaning | What you do |
|---|---|---|
| `Stopped for review: read SPEC.md` | The planner wrote the spec | Read and edit it, then `harness/approve.sh spec` |
| `Stopped for review: read features.json` | The initializer split it | Read and edit it, then `harness/approve.sh features` |
| `BLOCKED.md found` | A session needs a decision | Answer in the code or spec, delete `BLOCKED.md`, commit |
| `rejected 3 times` / `contract not approved` | The agents disagree | Read `NEXT_FINDINGS.md` or `.harness/state/`, steer, rerun |
| `Reached MAX_SESSIONS` | Budget spent | Rerun when you want to spend more |

`AUTO_APPROVE=1 harness/run.sh` skips both reviews. Edit either file and its approval lapses
(`APPROVALS` holds the hashes).

## Knobs

| Variable | Default | Limits |
|---|---|---|
| `MAX_SESSIONS` | 40 | claude sessions in one run, all roles |
| `MAX_CONTRACT_ROUNDS` | 3 | contract drafts per feature |
| `MAX_FEATURE_SESSIONS` | 8 | builder sessions per feature |
| `MAX_ATTEMPTS` | 3 | rejected implementations per feature |

Stop at any time with `touch AGENT_STOP`. Logs are in `.harness/logs/`.

## Who commits

Agents commit on the current branch inside the container, as you: the planner's spec, the
initializer's feature list, each contract and each builder session. The loop commits
`chore(<id>): mark as passing` when a feature passes. Every message must be a Conventional Commit
(`harness/commit-msg.sh`): the loop sends a session back if its commits are not, and CI fails. Nothing is pushed and no PRs are opened.

## Files

| File | Written by |
|---|---|
| `IDEA.md` | you |
| `SPEC.md` | planner (`.claude/agents/planner.md`), then you |
| `features.json` | initializer (`.claude/agents/initializer.md`), then you; `passes` by the loop |
| `APPROVALS` | `harness/approve.sh` |
| `contracts/<id>.md` | builder, approved by the evaluator; builders only tick its steps |
| `PROGRESS.md`, `docs/decisions.md` | builders |
| `NEXT_FINDINGS.md` | the loop, from the verify output or the evaluator |
| `BLOCKED.md` | any session that needs a person |

`.claude/hooks/protect-contract.sh` stops each role from writing another role's files.
