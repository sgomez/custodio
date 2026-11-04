//! Signing inside the TPM (F114): the request, the errors, and the call.
//!
//! The service never holds the private key. For RSA it builds the padded block (`block`) and the TPM does the raw private
//! operation (`TPM2_RSA_Decrypt`, null scheme); for P-256 it truncates the digest as `crate::sign::sign` does and the TPM
//! runs `TPM2_Sign`. Everything is validated before the TPM is opened, with the bounds and errors of `crate::sign::sign`.
//! The payload of `CKM_RSA_PKCS` is opaque: only its length is looked at.

use std::fmt;

use super::blob::Imported;
use super::classify::{Fault, ResponseCode, TpmError};
use super::import::open_ready;
use super::list::Item;
use super::{OpenError, TpmAccess};
use crate::sign::{Mechanism, SignError};

pub mod block;
pub mod check;

/// What the caller asks for: the stored key (blob and the name of its parent), the mechanism and the data. No key material.
#[derive(Debug, Clone, Copy)]
pub struct SignRequest<'a> {
    pub imported: &'a Imported,
    pub mechanism: Mechanism,
    pub data: &'a [u8],
}

/// What the TPM is given once the request is validated.
#[derive(Clone, PartialEq, Eq)]
pub enum Prepared {
    /// The padded block for the raw RSA operation, as long as the modulus.
    Rsa(Vec<u8>),
    /// The digest, 32 bytes, for `TPM2_Sign` with ECDSA and SHA-256.
    Ecdsa(Vec<u8>),
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa(b) => write!(f, "Prepared::Rsa({} bytes)", b.len()),
            Self::Ecdsa(d) => write!(f, "Prepared::Ecdsa({} bytes)", d.len()),
        }
    }
}

/// Why a signature was not produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmSignError {
    /// The request is refused before the TPM is touched; the class is the one `crate::sign::sign` returns.
    Refused(SignError),
    /// No TPM is present.
    NoTpm,
    /// The TPM or the way to it failed.
    Tpm(TpmError),
    /// The TPM cannot serve the mechanism: this item is missing. Nothing else was tried.
    Lacks(Item),
    /// The blob was wrapped to another parent than the current one (cleared TPM, another TPM).
    ParentMismatch,
    /// The parent matches and `TPM2_Load` refused the blob (a damaged private area).
    LoadFailed(ResponseCode),
    /// The TPM's answer is not the signature of the block it was given; nothing is returned.
    BadResult,
    /// The blob or a value did not fit its structure; a bug, not a TPM answer.
    Internal,
}

impl fmt::Display for TpmSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(why) => write!(f, "request refused: {why}"),
            Self::NoTpm => f.write_str("no TPM"),
            Self::Tpm(e) => write!(f, "TPM error: {e}"),
            Self::Lacks(item) => write!(f, "TPM lacks: {}", item.name()),
            Self::ParentMismatch => f.write_str("the key was wrapped to another TPM parent"),
            Self::LoadFailed(rc) => {
                write!(f, "the TPM refused to load the key (response code {rc})")
            }
            Self::BadResult => {
                f.write_str("the TPM returned a result that is not a valid signature")
            }
            Self::Internal => f.write_str("internal error preparing the TPM signature"),
        }
    }
}

impl std::error::Error for TpmSignError {}

impl From<Fault> for TpmSignError {
    fn from(fault: Fault) -> Self {
        Self::Tpm(fault.into())
    }
}

impl From<OpenError> for TpmSignError {
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::NoDevice => Self::NoTpm,
            OpenError::Failed(e) => Self::Tpm(e),
        }
    }
}

impl From<super::import::ImportError> for TpmSignError {
    fn from(error: super::import::ImportError) -> Self {
        use super::import::ImportError as E;
        match error {
            E::Refused(_) | E::Internal => Self::Internal,
            E::NoTpm => Self::NoTpm,
            E::Tpm(e) => Self::Tpm(e),
            E::ParentMismatch => Self::ParentMismatch,
        }
    }
}

/// Signs inside the TPM. The signature has the format of `crate::sign::sign`: 256 bytes for RSA, `r || s` (64 bytes) for
/// P-256.
///
/// # Errors
/// [`TpmSignError`]; a request that `crate::sign::sign` would refuse is refused before the TPM is opened. Every object
/// the call created is flushed before it returns, whatever the outcome.
pub fn sign(access: &dyn TpmAccess, request: &SignRequest<'_>) -> Result<Vec<u8>, TpmSignError> {
    let SignRequest {
        imported,
        mechanism,
        data,
    } = *request;
    let prepared = block::prepare(&imported.blob, mechanism, data)?;
    let mut session = open_ready(access).map_err(TpmSignError::from)?;
    session.sign(imported, &prepared)
}
