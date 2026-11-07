//! The journal names the storage kind and the cause of a failure (F120): the real service on a private bus with fake
//! polkit, a software TPM, the real `systemd-creds` where a row needs it and a credential double elsewhere, and the
//! in-memory sink. The entries are read as typed values, as the fields they produce, and as the datagram the
//! `JournalSink` sends.
//!
//! The rigs are those of `storage_choice` (the import failures) and `sign_kinds` (the signature failures).

// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
// Shared with `sign_kinds`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "sign_kinds/case.rs"]
mod case;
// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;
// Shared with `creds`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "creds/env.rs"]
mod env;
#[path = "kind_audit/import.rs"]
mod import;
// Shared with `sign_kinds`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "sign_kinds/kit.rs"]
mod kit;
// Shared with `tpm_sign`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "tpm_sign/oracle.rs"]
mod oracle;
#[path = "kind_audit/queries.rs"]
mod queries;
// Shared with `sign_kinds`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "sign_kinds/real.rs"]
mod real;
// Shared with `storage_choice`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "storage_choice/rig.rs"]
mod rig;
// Shared with `audit`: this target uses part of it.
#[allow(dead_code)]
#[path = "audit/scan.rs"]
mod scan;
#[path = "kind_audit/secrets.rs"]
mod secrets;
#[path = "kind_audit/sign.rs"]
mod sign;
// Shared with `tpm_import`: this target does not use every helper of it.
#[allow(dead_code, unused_imports)]
#[path = "tpm_import/support.rs"]
mod support;
