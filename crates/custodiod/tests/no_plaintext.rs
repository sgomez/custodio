//! `scripts/check-no-plaintext.sh` finds no plaintext key in the state directory after an import, under every storage
//! kind and both key types (F127), and it can fail: every encoding of the key it derives is found when planted.
//!
//! The six cells are those of `kinds_suite` (the lacking cell keeps its filter in front of the `swtpm`); the credential
//! double of the encrypted cells is `MemoryCreds`, so they prove the service writes no plaintext next to the credential,
//! and the real `systemd-creds` is the e2e cases' part. The test derives the encodings itself, with the `rsa` and `p256`
//! crates and `openssl`, so the script cannot agree with itself.

use crate::bus;
use crate::common;
#[path = "no_plaintext/planted.rs"]
mod planted;
use crate::rig;
#[path = "no_plaintext/script.rs"]
mod script;
#[path = "no_plaintext/service.rs"]
mod service;
use crate::support;
