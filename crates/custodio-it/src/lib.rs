//! Integration tests (see `tests/`) and the helpers they share.
//!
//! The only helper so far is [`swtpm`], a software TPM per test. It uses the standard library only,
//! so the crate keeps no regular dependencies.

pub mod swtpm;
