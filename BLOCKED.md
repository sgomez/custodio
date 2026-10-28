# BLOCKED — F21: code for `C_SignUpdate` / `C_SignFinal` with a raw mechanism

`contracts/F21.md` says `C_SignUpdate` after `C_SignInit` with a raw mechanism returns
`CKR_FUNCTION_NOT_SUPPORTED`, and that if the SoftHSMv2 source contradicts this, the builder writes
this file instead of choosing another code.

It contradicts it (read in `src/lib/SoftHSM.cpp`, develop; details in `docs/findings.md`):

- `AsymSignInit` sets `bAllowMultiPartOp = false` for `CKM_RSA_PKCS` (and the other raw ones).
- `C_SignUpdate` → `AsymSignUpdate`: `resetOp()` (operation ended) and
  **`CKR_OPERATION_NOT_INITIALIZED`**.
- `C_SignFinal` with a raw mechanism: **`CKR_OPERATION_NOT_INITIALIZED`** from `C_SignFinal`
  itself, and the operation is NOT ended.

## Question
Which code do the raw-mechanism paths return?

1. Keep the contract: `CKR_FUNCTION_NOT_SUPPORTED` for both, operation ended (what the code does now).
2. Follow SoftHSMv2: `CKR_OPERATION_NOT_INITIALIZED` for both. `C_SignUpdate` ends the operation;
   `C_SignFinal` ends it too (the contract's conservative rule) or keeps it (SoftHSMv2).
3. Another combination.

## State
Everything else of F21 is built and green (`just check`, `just test-integration`, steps 1-5 ticked)
with option 1. Switching is a small edit in `module/signing.rs` (`begin_update`, `sign_final`) and the
assertions in `module/tests/multipart.rs` (`multipart_raw_mechanism_ends`),
`ffi/tests/multipart.rs` and `tests/cryptoki/multipart_child.rs` (`multipart_raw`). Step 6
(`docs/decisions.md` entries) waits for this answer; `docs/findings.md` is written.
