//! Signing inside the TPM with every mechanism (F114), against `swtpm`. `openssl` verifies every signature with the
//! certificate of the key the test generated; the tools of `tpm2-tools` read what the TPM holds.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

#[path = "tpm_sign/blobs.rs"]
mod blobs;
#[path = "tpm_sign/every.rs"]
mod every;
#[path = "tpm_sign/oracle.rs"]
mod oracle;
#[path = "tpm_sign/refusals.rs"]
mod refusals;
// Shared with `tpm_import`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "tpm_import/support.rs"]
mod support;
