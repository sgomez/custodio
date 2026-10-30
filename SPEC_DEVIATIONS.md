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

## F44 — removal notice and stop on `rpm-ostree uninstall`
- SPEC: section 2, Removal: "Stop the service ... Print a notice saying that the keys are still on disk" for `rpm-ostree uninstall`.
- Proof: `docs/findings.md` (F44 research, rpm-ostree source): it runs no scriptlet of a package it removes (`%preun`, `%postun` and
  removal triggers are not run: "not running *un scripts for removals yet").
- Instead: on rpm-ostree the notice is documentation only. `docs/install.md` (F51) says where the keys are and that removal keeps them.
  The service stops with the reboot into the deployment without the package. `dnf remove` and `rpm -e` still stop, keep and print.
- Status: pending
