# Decisions

Decisions that `SPEC.md` leaves open, newest last.

<!-- ### YYYY-MM-DD — Title
Decision. Why. Alternatives considered. -->

## 2026-10-27 — Lint config for custodiod
- Decision: `custodiod/Cargo.toml` declares its own `[lints.clippy]` (pedantic + unwrap/expect/panic/indexing) instead of `workspace = true`; edition 2024, toolchain pinned to 1.99.1.
- Why: Cargo forbids extending `workspace.lints` with per-crate additions.
- Alternatives: put all deny lints in the workspace (would also restrict the other crates; less flexible).
