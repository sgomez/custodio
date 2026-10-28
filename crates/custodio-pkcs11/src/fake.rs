//! A fixed service for tests, Miri and the fuzz target: one P-256 key with a certificate, and a
//! constant 64-byte "signature".
#![forbid(unsafe_code)]

use crate::backend::{Backend, BackendError, SignParams};

pub const EC_CERT: &[u8] = include_bytes!("../tests/p256-cert.der");

/// The input of the last `sign`, for the tests of the `extern "C"` functions.
#[cfg(test)]
pub static LAST_INPUT: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

/// How many times `sign` was called, for the tests that count calls to the service. Read it as a
/// before/after difference under the serial lock of `ffi::tests`.
#[cfg(test)]
pub static SIGN_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub struct FakeBackend;

impl Backend for FakeBackend {
    fn list_certificates(&self) -> Result<Vec<(String, Vec<u8>)>, BackendError> {
        Ok(vec![("ec".into(), EC_CERT.to_vec())])
    }

    fn sign(&self, _: &str, _: SignParams, data: &[u8]) -> Result<Vec<u8>, BackendError> {
        #[cfg(not(test))]
        let _ = data;
        #[cfg(test)]
        {
            SIGN_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *LAST_INPUT
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = data.to_vec();
        }
        Ok(vec![7; 64])
    }
}

#[cfg(test)]
mod tests;
