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

### 2026-10-28 — F20 — attempt 1
- Done: `Mechanism::Composed`, per-token lists and `mechanism_info` (moved with `Mechanism` to
  `module/mechanism.rs` to stay under the file-size gate), `Module::sign` hashing outside the state
  lock via `hash_message`, `C_SignInit` parameter check. Unit tests in `module/tests/composed.rs`
  and `ffi/tests/composed.rs`. Integration: the fixture now has a bus monitor that records the
  `Sign` calls the service receives; scenarios in `tests/cryptoki/composed*.rs` (lists, sign and
  verify, 64 MiB, refusals, retry via the raw function list, denied). RSA cert fixture
  `tests/rsa2048-cert.der` (from `rsa2048.p12`). New dev-dependency `libloading`.
- Decisions: none lasting. Two M0 assertions loosened because composed mechanisms are now listed:
  `basic` (`contains` ECDSA) and the list size in `ffi::tests::list_outputs_respect_the_callers_sizes`
  (4 entries).
- Not done / known issues: `just miri` not run (pinned nightly-2026-10-26 is not installed here).
  `scripts/check-files.sh` prints `file: command not found` in this environment (pre-existing).
- Next session should: start F21 (`C_SignUpdate`/`C_SignFinal` stay `unsupported::*` until then).
