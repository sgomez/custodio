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
use crate::oracle;
#[path = "tpm_sign/refusals.rs"]
mod refusals;
use crate::support;
