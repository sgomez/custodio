# SPEC deviations

Requirements of SPEC.md that nothing this project ships can meet, and what is built instead. A
builder adds an entry with the contract amendment; the evaluator approves both; a person reviews
every entry before `just milestone close`: updates SPEC.md and sets `accepted`, or sets `rejected`
with what to build instead.

Format:

```
## <feature id> — <requirement, in a few words>
- SPEC: section and the sentence that cannot hold.
- Proof: the finding in docs/findings/<id>.md (source or command run).
- Instead: what is built, and its evidence in the contract.
- Status: <pending when added; accepted or rejected by a person>
```

## F195 — import tells "not a usable PKCS#12" from "wrong password", with a wrong password
- SPEC: Design 4, a file with a MAC that is unusable (no private key, no certificate, several keys) is (b), "not readable PKCS#12 or no usable key and certificate", with any password.
- Proof: `docs/findings/F195.md`. `Pkcs12Archive::from_pkcs12` (p12-keystore 0.4.1) checks the MAC first (`archive.rs:73`) and fails with `MAC tag mismatch` before any bag is read, so with a wrong password a MAC-bearing file with no key, no certificate or two keys gives the same result as a good file. Without a MAC and with a shrouded key it gives `PKCS#5 decryption failed`, the same as a good file.
- Instead: the classification follows the library's result, not how the fixture was built. MAC present and it fails to verify: (a), whatever the contents. No MAC and decryption fails: (c). The library returns a structural error (no key, no certificate, two keys, key without a certificate, not PKCS#12): (b). With the right password every unusable file is (b); with a wrong password (b) happens only for files whose defect is visible without decrypting (plain bags without a MAC, bytes that are not PKCS#12). Evidence: the amended cells in `contracts/F195.md`, asserted by `crates/custodiod/tests/import_split.rs`.
- Status: pending
