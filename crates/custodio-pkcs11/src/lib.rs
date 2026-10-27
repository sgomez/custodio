//! Custodio PKCS#11 module.
//!
//! This is the only crate allowed to contain `unsafe` code, and only in the PKCS#11 FFI layer
//! (`ffi`, including its feature-gated fuzz harness `ffi::fuzzing`).
//! The module lists one token per key, finds the certificate and the private key object, and
//! forwards `C_Sign` to the `custodiod` service over D-Bus. Every other function returns
//! `CKR_FUNCTION_NOT_SUPPORTED`.

// The `fuzzing` feature swaps the service for a fake that signs without asking polkit. It must
// never reach a shipped module: only debug builds (clippy, tests) and cargo-fuzz (`--cfg fuzzing`)
// may enable it. See docs/decisions.md (FFI safety).
#[cfg(all(feature = "fuzzing", not(debug_assertions), not(fuzzing)))]
compile_error!(
    "feature `fuzzing` replaces polkit with a fake and must not be built outside fuzz or debug builds"
);

pub mod backend;
#[cfg(any(test, feature = "fuzzing"))]
mod fake;
mod ffi;

#[cfg(feature = "fuzzing")]
pub use ffi::fuzzing;
pub mod module;
pub mod token;
mod unsupported;

/// Name of the module, reported in the token info.
pub const MODULE_NAME: &str = "custodio-pkcs11";

#[cfg(test)]
mod tests;
