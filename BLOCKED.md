# Blocked: F44 — the removal notice and stop for `rpm-ostree uninstall`

## What is built and passing
All four scriptlets (`%pre`, `%post`, `%preun`, `%postun`), their tests (`scripts/test-rpm-lifecycle.sh`, `-real.sh`, `test-rpm-scripts-static.sh`),
the gates and the lint lists. `dnf remove` / `rpm -e` stop the service, keep the state directory and the account, and print the notice.

## The question
SPEC section 2 lists `rpm-ostree uninstall` among the removals that must stop the service, keep state and account, and **print a notice**.
`docs/findings.md` (F44 research, from rpm-ostree's source) shows that rpm-ostree runs `%pre`, `%post`, `%posttrans` and file triggers of
packages it *adds*, and **no** scriptlet at all of a package it removes (`%preun`, `%postun` and removal triggers are not run). So nothing in the
package can print the notice at that moment. The stop is not needed (the service ends with the reboot into the deployment without the package),
but the notice has no mechanism. The contract forbids covering this with a stubbed `%postun 0` case or counting a notice shown at the next install.

## Options
1. **Accept and document**: the package cannot print it on rpm-ostree; `docs/install.md` (F51) and the post-install `%post` text say where the keys are and that
   removal keeps them. Needs a contract amendment (and probably a SPEC line: "on rpm-ostree the notice is documentation only").
2. **Also print the keys notice at install time** (`%post` 1, stderr), so a person layering the package has read it before removing it. Not the removal notice
   SPEC asks for, but the only place rpm-ostree gives a scriptlet a voice. Costs a new line in the output of every first install; SPEC amendment needed.
3. **Ship a file trigger / `%posttrans` of a *different* package**: rejected, not ours to ship.
4. Wait for rpm-ostree to run removal scriptlets ("not running *un scripts for removals yet" in its source).

## My recommendation
Option 1, with the sentence in the install documentation. Everything else in F44 is done; `PROGRESS.md` has the details. The loop must not mark F44
as passing until the contract item "rpm-ostree uninstall meets SPEC" is amended or decided.
