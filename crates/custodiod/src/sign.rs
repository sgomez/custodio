//! Signing primitives for the PKCS#11 mechanisms consumers use: `CKM_RSA_PKCS`,
//! `CKM_RSA_PKCS_PSS` and `CKM_ECDSA`.
//!
//! Like PKCS#11, every mechanism signs caller-provided bytes that are already prepared:
//!
//! - `CKM_RSA_PKCS`: the data is signed as is with PKCS#1 v1.5 type 1 padding. The caller supplies
//!   the `DigestInfo` (or any other payload up to `k - 11` bytes).
//! - `CKM_RSA_PKCS_PSS`: the data is a digest of the message, and the hash of the parameters must
//!   match its length. The mask generation function is MGF1 with the same hash.
//! - `CKM_ECDSA`: the data is a digest; the signature is the raw `r || s`, 64 bytes for P-256.
//!
//! This module does not authorize anything; the caller must have asked polkit first.

use std::fmt;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, Pss, RsaPrivateKey};
use secrecy::{ExposeSecret, SecretSlice};
use sha2::{Sha256, Sha384, Sha512};

use crate::import::{KeyKind, classify};

/// Hash used by `CKM_RSA_PKCS_PSS` (`CKM_SHA256` and so on). SHA-1 is not offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PssHash {
    Sha256,
    Sha384,
    Sha512,
}

impl PssHash {
    /// Digest length in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Always false; present because `len` is.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        false
    }
}

/// A signing mechanism with its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// `CKM_RSA_PKCS`.
    RsaPkcs,
    /// `CKM_RSA_PKCS_PSS` with `CK_RSA_PKCS_PSS_PARAMS` (`hash`, MGF1 of the same hash, `salt_len`).
    RsaPkcsPss { hash: PssHash, salt_len: usize },
    /// `CKM_ECDSA`.
    Ecdsa,
}

/// Why a signature was not produced.
#[derive(Debug, PartialEq, Eq)]
pub enum SignError {
    /// The stored key is not a PKCS#8 RSA 2048 or P-256 key.
    BadKey,
    /// The mechanism does not fit the key type.
    MechanismMismatch,
    /// The data has the wrong length for the mechanism, or the salt length is too large.
    BadData,
    /// The cryptographic operation failed.
    Failed,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadKey => "stored key is not a supported private key",
            Self::MechanismMismatch => "mechanism does not match the key type",
            Self::BadData => "data length is not valid for the mechanism",
            Self::Failed => "signing failed",
        })
    }
}

impl std::error::Error for SignError {}

/// Sign `data` with the PKCS#8 DER `key` using `mechanism`.
///
/// # Errors
///
/// See [`SignError`].
pub fn sign(
    key: &SecretSlice<u8>,
    mechanism: Mechanism,
    data: &[u8],
) -> Result<Vec<u8>, SignError> {
    let der = key.expose_secret();
    let kind = classify(der).map_err(|_| SignError::BadKey)?;
    match (kind, mechanism) {
        (KeyKind::Rsa2048, Mechanism::RsaPkcs) => {
            let key = RsaPrivateKey::from_pkcs8_der(der).map_err(|_| SignError::BadKey)?;
            key.sign_with_rng(&mut rand::rng(), Pkcs1v15Sign::new_unprefixed(), data)
                .map_err(|_| SignError::BadData)
        }
        (KeyKind::Rsa2048, Mechanism::RsaPkcsPss { hash, salt_len }) => {
            if data.len() != hash.len() {
                return Err(SignError::BadData);
            }
            let key = RsaPrivateKey::from_pkcs8_der(der).map_err(|_| SignError::BadKey)?;
            let rng = &mut rand::rng();
            match hash {
                PssHash::Sha256 => {
                    key.sign_with_rng(rng, Pss::<Sha256>::new_with_salt(salt_len), data)
                }
                PssHash::Sha384 => {
                    key.sign_with_rng(rng, Pss::<Sha384>::new_with_salt(salt_len), data)
                }
                PssHash::Sha512 => {
                    key.sign_with_rng(rng, Pss::<Sha512>::new_with_salt(salt_len), data)
                }
            }
            .map_err(|_| SignError::BadData)
        }
        (KeyKind::EcdsaP256, Mechanism::Ecdsa) => {
            // The nonce derivation panics on empty input.
            if data.is_empty() {
                return Err(SignError::BadData);
            }
            let key = SigningKey::from_pkcs8_der(der).map_err(|_| SignError::BadKey)?;
            let sig: p256::ecdsa::Signature =
                key.sign_prehash(data).map_err(|_| SignError::BadData)?;
            Ok(sig.to_bytes().to_vec())
        }
        _ => Err(SignError::MechanismMismatch),
    }
}
