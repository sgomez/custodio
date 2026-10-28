# Harness

Agents build Custodio one feature at a time. You write the idea, approve the plan, and check what
only a person can check.

**Lost? Run `just status`.** It says where things are and the next command to run.

## Once per machine

1. Install [mise](https://mise.jdx.dev), rustup and Docker or Podman, and activate mise in your shell.
2. `just setup`
3. `claude setup-token`, then put `export CLAUDE_CODE_OAUTH_TOKEN=<token>` in your shell profile.

## Commands

| Command | Does |
|---|---|
| `just status` | Where things are and what to run next |
| `just release` | Changelog, version tag and push |
| **Milestone** | |
| `just milestone list` | Milestones, closed and open |
| `just milestone open` / `close` | Start a milestone, finish it |
| `just milestone approve spec` / `approve features` | Approve what you reviewed |
| `just milestone pass <id>` | Mark a manual feature as checked |
| **Agents** | |
| `just harness run` | Run the agents, or continue after a stop |
| `just harness try` | Same, at most 3 Claude sessions |
| `just harness stop` / `resume` | Stop the agents, continue |
| `just harness unblock "<answer>"` | Answer `BLOCKED.md`: an agent applies it, then continue |
| `just harness unblock` | After applying the answer yourself: commit and continue |
| `just harness fix <id>` | Fix what stopped `<id>` in an interactive agent session, then continue |

## A milestone, start to end

1. `just milestone open`, then write the idea in `IDEA.md` (replace the `TODO` line).
2. `just harness run`. A planner writes `SPEC.md` and stops.
3. Read `SPEC.md`, fix what you don't like, `just milestone approve spec`.
4. `just harness run`. An initializer splits the spec into `features.json` and stops.
5. Read `features.json`: every feature there, in order, each with a `verify` that checks something
   real. `just milestone approve features`.
6. `just harness run`. The agents build feature after feature.
7. Check by hand the features marked `manual`, then `just milestone pass <id>` for each.
8. `just release` (runs `just check-slow` first, in the dev container), then `just milestone close`.

## When it stops

| It says | You do |
|---|---|
| `Stopped for review` | Steps 3 or 5 above |
| `BLOCKED.md found` | Read `BLOCKED.md`, then `just harness unblock "<answer>"`. If the answer changes `SPEC.md` or `features.json`, edit and approve them yourself, then `just harness unblock` |
| `rejected 3 times` | Read `NEXT_FINDINGS.md`. If the feature is badly defined, fix it in `features.json`, `just milestone approve features`, `just harness run` |
| `contract not approved` | `just harness fix <id>`: an agent fixes the contract with you, then the evaluator reviews it again |
| `used 8 builder sessions` | The feature is too big: split it in `features.json`, `just milestone approve features`, `just harness run` |
| `Reached MAX_SESSIONS` | Budget for this run spent: `just harness run` when you want to spend more |
| `Uncommitted changes` | Commit or `git stash`, then `just harness run` |

## Good to know

- The agents run in a container, commit on your current branch as you, and never push.
- Every Claude session starts with an empty memory; what carries over is in `PROGRESS.md`,
  `docs/decisions.md` and `contracts/`.
- A feature passes only when its `verify` command and a separate reviewer agent both say so.
- It spends your Claude subscription: each feature takes several sessions.
- Editing `SPEC.md` or `features.json` after approving them means approving them again.

## How it works

```
IDEA.md ──planner──▶ SPEC.md ──[you approve]──▶ initializer ──▶ features.json ──[you approve]──▶
  for each feature whose dependencies pass:
    builder writes contracts/<id>.md ──evaluator: APPROVED / REVISE──┐ (up to 3 rounds)
    builder sessions tick the contract's steps, one fresh context each ◀┘
    verify command (no LLM) ──▶ evaluator: PASS / NEEDS_WORK ──▶ loop marks it passing
```

The design follows Anthropic's articles on long-running agents. `harness/pipeline.sh` runs the
planning steps and `harness/loop.sh` the build; `AUTO_APPROVE=1 just harness run` skips both reviews.

| Limit | Default | Counts |
|---|---|---|
| `MAX_SESSIONS` | 40 | Claude sessions in one run, all roles |
| `MAX_CONTRACT_ROUNDS` | 3 | contract drafts per feature |
| `MAX_FEATURE_SESSIONS` | 8 | builder sessions per feature |
| `MAX_ATTEMPTS` | 3 | rejected implementations per feature |

| File | Written by |
|---|---|
| `IDEA.md` | you |
| `SPEC.md` | the planner, then you |
| `features.json` | the initializer, then you; `passes` by the loop |
| `APPROVALS` | `just milestone approve` |
| `contracts/<id>.md` | a builder, approved by the evaluator; builders only tick its steps; the unblocker applies your answer to it |
| `PROGRESS.md`, `docs/decisions.md` | builders |
| `NEXT_FINDINGS.md` | the loop, from the verify output or the evaluator |
| `BLOCKED.md` | any session that needs a person |

Commit messages follow Conventional Commits (commitlint checks them in the hook, the loop and CI),
and `just release` builds the changelog from them. Hooks in `.claude/hooks/` stop each agent role
from writing another role's files. Logs are in `.harness/logs/`.
