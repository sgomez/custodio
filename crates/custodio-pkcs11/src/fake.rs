//! A fixed service for tests, Miri and the fuzz target: one P-256 key with a certificate, and a
//! constant 64-byte "signature".

use crate::backend::{Backend, BackendError, SignParams};

pub const EC_CERT: &[u8] = include_bytes!("../tests/p256-cert.der");

pub struct FakeBackend;

impl Backend for FakeBackend {
    fn list_certificates(&self) -> Result<Vec<(String, Vec<u8>)>, BackendError> {
        Ok(vec![("ec".into(), EC_CERT.to_vec())])
    }

    fn sign(&self, _: &str, _: SignParams, _: &[u8]) -> Result<Vec<u8>, BackendError> {
        Ok(vec![7; 64])
    }
}
