//! `scripts/check-no-plaintext.sh` finds no plaintext key in the state directory after an import, under every storage
//! kind and both key types (F127), and it can fail: every encoding of the key it derives is found when planted.
//!
//! The six cells are those of `kinds_suite` (the lacking cell keeps its filter in front of the `swtpm`); the credential
//! double of the encrypted cells is `MemoryCreds`, so they prove the service writes no plaintext next to the credential,
//! and the real `systemd-creds` is the e2e cases' part. The test derives the encodings itself, with the `rsa` and `p256`
//! crates and `openssl`, so the script cannot agree with itself.

// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;
#[path = "no_plaintext/planted.rs"]
mod planted;
// Shared with `storage_choice`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "storage_choice/rig.rs"]
mod rig;
#[path = "no_plaintext/script.rs"]
mod script;
#[path = "no_plaintext/service.rs"]
mod service;
// Shared with `tpm_import`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "tpm_import/support.rs"]
mod support;
