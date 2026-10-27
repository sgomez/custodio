# Decisions

Decisions that `SPEC.md` leaves open, newest last.

<!-- ### YYYY-MM-DD — Title
Decision. Why. Alternatives considered. -->

## 2026-10-27 — Lint config for custodiod
- Decision: `custodiod/Cargo.toml` declares its own `[lints.clippy]` (pedantic + unwrap/expect/panic/indexing) instead of `workspace = true`; edition 2024, toolchain pinned to 1.99.1.
- Why: Cargo forbids extending `workspace.lints` with per-crate additions.
- Alternatives: put all deny lints in the workspace (would also restrict the other crates; less flexible).

## 2026-10-27 — CI workflow shape (F03)
- Decision: `.github/workflows/ci.yml` runs `just check` and `just check-slow` as separate jobs plus an aggregate `ci` job. Actions are pinned by commit SHA with a version comment; the workflow has `permissions: {}` and each job gets only `contents: read`. Branch protection must require the `ci` status check (a repository setting, not expressible in the repo).
- Why: one stable required check name survives job renames; SHA pins resist tag hijacking.
- Alternatives: requiring each job individually (brittle); Dependabot-managed pins (not yet added).
