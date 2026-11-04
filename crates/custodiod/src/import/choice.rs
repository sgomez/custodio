//! The choice of how an imported key is stored (SPEC section 2), as one pure function of what the TPM was found to be.
//!
//! Only two answers lead to a weaker kind than the TPM: the TPM lacks a capability the key type needs (the key is then
//! encrypted and bound to the TPM) and there is no TPM at all (encrypted, bound to the host). A TPM that cannot be
//! judged is a refusal, never a fallback.

use crate::import::KeyKind;
use crate::store::Kind;
use crate::tpm::{Classification, KeyType, TpmError};

/// The TPM key type that stands for an accepted key type.
#[must_use]
pub const fn tpm_key_type(kind: KeyKind) -> KeyType {
    match kind {
        KeyKind::Rsa2048 => KeyType::Rsa2048,
        KeyKind::EcdsaP256 => KeyType::EccP256,
    }
}

/// The storage kind to use for a classification, or why none may be used.
///
/// # Errors
/// The [`TpmError`] of a [`Classification::Error`]: the import fails and stores nothing.
pub const fn choose(classification: &Classification) -> Result<Kind, TpmError> {
    match classification {
        Classification::Ready => Ok(Kind::Tpm),
        Classification::Lacks(_) => Ok(Kind::EncryptedTpm),
        Classification::Absent => Ok(Kind::EncryptedHost),
        Classification::Error(e) => Err(*e),
    }
}

#[cfg(test)]
mod tests;
