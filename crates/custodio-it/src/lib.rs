//! Integration tests (see `tests/`) and the helpers they share.
//!
//! Helpers: [`swtpm`], a software TPM per test, [`tpm_filter`], a filter in front of it that makes it lack
//! an algorithm, and [`spawn`], children that inherit no descriptor. They use the standard library only, so the
//! crate keeps no regular dependencies.

pub mod spawn;
pub mod swtpm;
pub mod tpm_filter;
