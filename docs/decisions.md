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

## 2026-10-27 — Supply chain policy (F04)

- Decision: `deny.toml` denies yanked crates, duplicate versions, wildcard requirements, unknown registries and any git source; licence allowlist is permissive licences plus MPL-2.0; `openssl`/`openssl-sys` are banned. `cargo deny check` and `cargo machete` run in `just lint`.
- Why: most conservative reading of SPEC. Duplicates are denied rather than warned; when a real duplicate appears, add a justified `skip` entry.
- Alternatives: warn on duplicates (weaker); allow GPL-family licences (EUPL compatibility is narrower).

## 2026-10-27 — Key store layout (F05)
- Decision: one file per key, named by id (`[A-Za-z0-9_-]{1,64}`), in the state dir. Written to a `.tmp-*` file (`create_new`, 0600, fsync), then `hard_link`ed into place so it is atomic and never overwrites; dir fsynced. An existing state dir or key file whose mode is not exactly 0700/0600 is rejected, not repaired.
- Why: conservative; a loosened mode may mean the key was already exposed, so a human should look. Systemd must create the dir with `StateDirectoryMode=0700`.
- Alternatives: `rename` (silently overwrites); auto-chmod (hides exposure).
