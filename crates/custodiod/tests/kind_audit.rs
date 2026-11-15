//! The journal names the storage kind and the cause of a failure (F120): the real service on a private bus with fake
//! polkit, a software TPM, and a credential double, and the
//! in-memory sink. The entries are read as typed values, as the fields they produce, and as the datagram the
//! `JournalSink` sends.
//!
//! The rigs are those of `storage_choice` (the import failures) and `sign_kinds` (the signature failures).

use crate::bus;
use crate::case;
use crate::common;
#[path = "kind_audit/import.rs"]
mod import;
use crate::kit;
#[path = "kind_audit/queries.rs"]
mod queries;
use crate::rig;
use crate::scan;
#[path = "kind_audit/secrets.rs"]
mod secrets;
#[path = "kind_audit/sign.rs"]
mod sign;
