# Progress

Each session appends one entry at the bottom. Keep entries short: the next session reads them
with an empty context.

## Template

```
### <date> — <feature id> — <attempt n>
- Done:
- Decisions (also in docs/decisions.md if lasting):
- Not done / known issues:
- Next session should:
```

## Sessions

### 2026-10-28 — F19 — attempt 1
- Done: `custodio-pkcs11::composed` (`Composed` mapping, `DigestHasher` Clone, `digest_info`,
  `sign_input`), tests in `composed/tests.rs` incl. RFC 8017 prefixes, RSA/ECDSA cross-verification
  with `rsa`/`p256` and the openssl CLI (`cross_verify_openssl` ran, not skipped). Added
  `ecdsa_long_digest_standard_result` in `custodiod/tests/sign.rs`.
- Decisions: the service truncates SHA-384/512 for P-256; it already did, so `sign.rs` is
  unchanged. Recorded in `docs/decisions.md`.
- Not done / known issues: none; wiring into the FFI is for later features.
- Next session should: start the next feature; `composed` is ready to call.
