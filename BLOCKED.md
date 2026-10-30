# BLOCKED — F38

The evaluator rejected the amendment that widened the person's decision on `usr/lib/custodio/custodiod` (72d43fa allowed exactly one
entry there and said any other finding on that path still fails). Widening it is a choice for a person, so this session does not touch
the contract's path rule, the lists or the matcher test. The lists currently hold entries for the findings below (as the proposal); the
contract text as approved forbids all but the first, so with the approved text the gate (and `scripts/test-package-lint-lists.sh`) would fail.

Every finding in the real run (`reports/package-lint-container.txt`) whose subject names the path:

| # | linter | tag | subject | fixable in packaging? |
|---|--------|-----|---------|-----------------------|
| 1 | lintian | `executable-in-usr-lib` | `usr/lib/custodio/custodiod` | no (Arch has no `/usr/libexec`); **already decided** by 72d43fa |
| 2 | lintian | `hardening-no-fortify-functions` | `usr/lib/custodio/custodiod` | no: Rust does not call glibc `_chk` functions; same for the other two ELF files |
| 3 | lintian | `spelling-error-in-binary` | `onthe on the [usr/lib/custodio/custodiod]` | no: string embedded by a dependency |
| 4 | namcap | `incorrect-owner` | `usr/lib/custodio/custodiod (0:0)` | not with nfpm: it writes numeric owner ids only into the Arch package (every file gets it) |
| 5 | namcap | `unused-sodepend` | `/usr/lib64/ld-linux-x86-64.so.2 usr/lib/custodio/custodiod` | no: the loader is a NEEDED entry of every Rust executable |
| 6 | namcap | `libdepends-missing-provides` (x2), `libdepends-detected-not-included`, `dependency-implicitly-satisfied`, `dependency-detected-satisfied` | subjects list the path inside a bracketed file list with `usr/bin/custodio` and the PKCS#11 library | no: information about dependencies; the packages depend on glibc and gcc-libs by name (F36) |

rpmlint draws no finding that names the path.

Options:
1. A person approves a contract amendment listing exactly these (linter, tag, literal subject) pairs (rows 2-5; row 6 as literal
   file-list subjects, since namcap's list order varies per run), and the matcher test is rewritten to take every finding in the real
   raw output whose subject contains the path and assert that only those pairs are covered. Recommendation.
2. Keep the original rule (only row 1) and have the person allow the other findings by a wildcard-free per-tag decision instead.
3. Change the packaging so the findings go away (for example a custom Arch package builder instead of nfpm for rows 4 and 6): large,
   reverses F36 decisions.
