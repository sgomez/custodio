//! The storage kind chosen at import and the fail-closed rule (F117): the real import path on a private bus with fake
//! polkit, a software TPM (ready, lacking, faulty or absent) and a credential double.
//!
//! The TPM and the credential service are the two access points the service takes; every reason is injected through
//! them. The store, the journal and the TPM are read back afterwards.

// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;
#[path = "storage_choice/fails_closed.rs"]
mod fails_closed;
#[path = "storage_choice/kinds.rs"]
mod kinds;
#[path = "storage_choice/order.rs"]
mod order;
#[path = "storage_choice/rig.rs"]
mod rig;
#[path = "storage_choice/row.rs"]
mod row;
// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "tpm_import/support.rs"]
mod support;
