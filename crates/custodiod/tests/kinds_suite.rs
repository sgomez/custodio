//! The lifecycle of a key (import, list, sign, delete, replace certificate) under each storage kind (F126): the real
//! service on a private bus with fake polkit, once with the `swtpm` serving everything, once with an `swtpm` that lacks
//! a capability the key type needs (the filter stays in front of it for every call) and once with no TPM; both key
//! types in each. Every signature is verified with the key's certificate by `openssl`.
//!
//! The failure classes, the counters, polkit per signature, the journal, the API shape and the choice rules are owned by
//! `sign_kinds`, `kind_audit`, `api_kind` and `storage_choice`; this target adds the matrix of every mechanism and the
//! lifecycle on the lacking cell. The mechanism table is `oracle::rsa_rows` and `oracle::p256_rows`; the ECDSA rows hold
//! the digest lengths 1, 16, 32, 48 and 64 (a superset of the SHA-256, SHA-384 and SHA-512 lengths), and the
//! PKCS#11 front end's composed mechanisms are not here.

use crate::bus;
// The shared helpers are used in full by other tests; this file uses part of them.
#[path = "kinds_suite/cell.rs"]
mod cell;
use crate::common;
#[path = "kinds_suite/lifecycle.rs"]
mod lifecycle;
use crate::kit;
use crate::oracle;
use crate::rig;
#[path = "kinds_suite/signs.rs"]
mod signs;
use crate::support;
