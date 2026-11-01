# F63 blocked: `just check` (the first part of the verify) is red on the tree before this feature

F63 itself is built and its real runs pass (see PROGRESS.md). The `verify` begins with `just check`, which cannot pass for reasons outside F63. I checked both on the
unmodified tree (git stash):

1. `scripts/test-docs-install.sh` fails with `docs/install.md: precondition: Ubuntu 24.04 is no longer in the supported set`. The test (line 104) requires the text
   "Ubuntu 24.04" in SPEC.md. The M3 SPEC.md (commit f92ef76) does not mention it, while `e2e/targets/ubuntu2404` and the docs section still exist. The `test-scripts`
   recipe stops at this script, so every script after it in the recipe is not run by `just check` either.
2. `shellcheck` (dev container version) reports SC2317 infos in `scripts/test-relabel.sh` (lines 20-24, 84-88); the file only disables SC2329. Looks like version drift.

Question: how should these be resolved? Options:
- (a) Ubuntu 24.04 is still supported in M3: change the precondition of the test to something that holds (for example the `e2e/targets/ubuntu2404` directory only), and add SC2317
  next to SC2329 in `test-relabel.sh` with a comment. Both touch gates, so I did not do it on my own.
- (b) Ubuntu 24.04 is dropped in M3: that is a larger change (target, docs, tests), and a feature of its own.
- (c) Pin or fix the shellcheck version of the dev container (host change).

F63 needs only one run of `just check` and the verify after that.
