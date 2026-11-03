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

## F110 — encrypted-key fallback bound to the TPM and never to a PCR, on systemd 255 and 257
- SPEC: section 5, "It is bound to the TPM when there is one and to the host key otherwise, and **never to any PCR**, explicitly, whatever the default of the systemd version installed", with a service that is not root.
- Proof: `docs/findings.md`, `## F110`. debian13 and alma10 (systemd 257): the unprivileged call is only the Varlink daemon's `auto` key, whose PCR mask is the daemon's own command-line default, PCR 7 (creds.c v257:1032-1033, 1219-1224; read from source, *inferred* because no kernel TPM can be reached from a container), so with a usable TPM the credential is PCR-bound and the caller cannot change it. ubuntu2404 (255): no `--user`, no Varlink; as uid 992 `--with-key=host` fails `Failed to determine local credential host secret: Permission denied`, `--with-key=tpm2 --tpm2-pcrs=` works against swtpm (TPM alone, no uid binding).
- Instead: on debian13 and alma10 the service reads the stored PCR mask back from each new credential and refuses a nonzero one, so the fallback is unavailable on those machines when a TPM is present (host+uid-bound without a TPM); on ubuntu2404 the service runs `systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=` itself (TPM alone), and there is no encrypted fallback on a machine without a TPM. Evidence: the tests of the storage feature (F120) and the real-hardware run (F147), which reads the mask of a Varlink credential on a machine with a TPM and can drop the 257 part.
- Status: pending
