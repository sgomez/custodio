//! What the service checks of the TPM's answer before it returns a signature.
//!
//! The TPM does the raw RSA operation on a block the service built, so the service can verify the result with the public
//! key of the blob alone: `result^e mod n` must be the block and `result` must be below `n`. A TPM that returns anything
//! else is not trusted.

use rsa::hazmat::rsa_encrypt;
use rsa::{BoxedUint, RsaPublicKey};
use tss_esapi::structures::Public;

use super::TpmSignError;
use super::block::K;

/// The exponent of a key whose template says 0.
const DEFAULT_EXPONENT: u32 = 65537;

/// `bytes` with zeros on the left up to `len` bytes.
///
/// # Errors
/// [`TpmSignError::BadResult`] when `bytes` is longer than `len` (and does not start with zeros that could go).
pub fn left_pad(bytes: &[u8], len: usize) -> Result<Vec<u8>, TpmSignError> {
    let skip = bytes.len().saturating_sub(len);
    let (extra, rest) = bytes.split_at(skip);
    if extra.iter().any(|b| *b != 0) {
        return Err(TpmSignError::BadResult);
    }
    let mut out = vec![0u8; len - rest.len()];
    out.extend_from_slice(rest);
    Ok(out)
}

/// Checks the TPM's raw RSA result against the block it was given and returns it as `K` bytes.
///
/// # Errors
/// [`TpmSignError::BadResult`] when the result is not below the modulus or `result^e mod n` is not `block`;
/// [`TpmSignError::Internal`] when the public area is not an RSA 2048 key.
pub fn rsa_result(public: &Public, block: &[u8], raw: &[u8]) -> Result<Vec<u8>, TpmSignError> {
    let Public::Rsa {
        parameters, unique, ..
    } = public
    else {
        return Err(TpmSignError::Internal);
    };
    let modulus = left_pad(unique.as_bytes(), K).map_err(|_| TpmSignError::Internal)?;
    let exponent = match parameters.exponent().value() {
        0 => DEFAULT_EXPONENT,
        e => e,
    };
    let signature = left_pad(raw, K)?;
    if signature >= modulus {
        return Err(TpmSignError::BadResult);
    }
    let bits = u32::try_from(K * 8).map_err(|_| TpmSignError::Internal)?;
    let n = BoxedUint::from_be_slice(&modulus, bits).map_err(|_| TpmSignError::Internal)?;
    let key = RsaPublicKey::new(n, BoxedUint::from(u64::from(exponent)))
        .map_err(|_| TpmSignError::Internal)?;
    let s = BoxedUint::from_be_slice(&signature, bits).map_err(|_| TpmSignError::BadResult)?;
    let recovered = rsa_encrypt(&key, &s).map_err(|_| TpmSignError::BadResult)?;
    let recovered = left_pad(&recovered.to_be_bytes(), K)?;
    if recovered != block {
        return Err(TpmSignError::BadResult);
    }
    Ok(signature)
}
