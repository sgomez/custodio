# BLOCKED — F38

Progress: nested podman works in the dev container, the three linter images build at the pinned versions, and the raw findings on the real
packages are in `docs/findings.md` ("raw linter findings"). Everything the packaging can fix is fixable (strip, changelog, copyright and
license files, man page, short synopsis, namcap owner names); the rest is mechanical.

Question: lintian's experimental tag `X: executable-in-usr-lib [usr/lib/custodio/custodiod]` names exactly the path of the open question.
It cannot be fixed without the `/usr/libexec` path that SPEC and docs/decisions.md rejected for Arch (one file list). The contract forbids any
list entry that covers `usr/lib/custodio/custodiod`, and also mandates `--display-experimental`. Options:
1. Allow one lintian exception for that tag and path (reason: Arch has no `/usr/libexec`, SPEC "Arch and /usr/libexec"); a person edits the
   contract's matcher test to say so.
2. Drop `--display-experimental` (experimental tags are lintian's unreliable ones); a person edits the contract's flags list.
3. Install the service under `/usr/libexec` in the .deb and .rpm only (two lists, two units; reverses the decision in decisions.md).
Recommendation: option 1.
