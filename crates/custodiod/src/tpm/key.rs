//! The private key handed to the TPM import: RSA 2048 or P-256, nothing else.
//!
//! Only what `TPM2_Import` needs is kept: for RSA the public modulus and one prime (the TPM derives the other and checks
//! the product), for P-256 the scalar and the public point derived from it. The secret parts live in `secrecy` types
//! and are zeroed on drop; nothing here prints them.

use std::fmt;

use p256::SecretKey;
use p256::elliptic_curve::sec1::ToSec1Point;
use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use secrecy::{ExposeSecret, SecretSlice};
use zeroize::Zeroizing;

use crate::import::{KeyKind, classify};

/// Bytes of an RSA 2048 modulus, and of the prime the TPM is given (half the modulus).
pub const RSA_MODULUS_LEN: usize = 256;
pub const RSA_PRIME_LEN: usize = RSA_MODULUS_LEN / 2;
/// Bytes of a P-256 coordinate or scalar.
pub const P256_LEN: usize = 32;

/// Why a key is not imported into the TPM. No TPM call has happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefusal {
    /// Not a PKCS#8 key, or not one of the two accepted types and sizes (RSA 2048, P-256).
    Unsupported,
    /// RSA 2048 with a public exponent other than 65537, the only one a TPM template carries as the default.
    RsaExponent,
    /// The key does not parse or is not a valid key (for example a prime that does not divide the modulus).
    Malformed,
}

impl fmt::Display for KeyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => {
                "key type or size not supported by the TPM (only RSA 2048 and P-256)"
            }
            Self::RsaExponent => "RSA public exponent is not 65537",
            Self::Malformed => "key is malformed",
        })
    }
}

impl std::error::Error for KeyRefusal {}

/// The public and secret parts the import uses.
pub(super) enum Material {
    Rsa {
        modulus: Vec<u8>,
        prime: SecretSlice<u8>,
    },
    P256 {
        scalar: SecretSlice<u8>,
        x: [u8; P256_LEN],
        y: [u8; P256_LEN],
    },
}

/// A private key accepted for the TPM. `Debug` shows the type only.
pub struct ImportKey {
    pub(super) material: Material,
}

impl fmt::Debug for ImportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.material {
            Material::Rsa { .. } => "ImportKey(RSA 2048)",
            Material::P256 { .. } => "ImportKey(P-256)",
        })
    }
}

/// `bytes` left-padded with zeros to `len`, or `None` if it is longer after stripping zeros.
fn padded(bytes: &[u8], len: usize) -> Option<Vec<u8>> {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let significant = bytes.get(start..)?;
    let pad = len.checked_sub(significant.len())?;
    let mut out = vec![0u8; pad];
    out.extend_from_slice(significant);
    Some(out)
}

impl ImportKey {
    /// Accepts a PKCS#8 DER private key of RSA 2048 or P-256 and refuses everything else.
    ///
    /// # Errors
    /// [`KeyRefusal`] naming the reason; the bytes of the key are never part of it.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, KeyRefusal> {
        let kind = classify(der).map_err(|_| KeyRefusal::Unsupported)?;
        let material = match kind {
            KeyKind::Rsa2048 => {
                let key = RsaPrivateKey::from_pkcs8_der(der).map_err(|_| KeyRefusal::Malformed)?;
                if padded(key.e().to_be_bytes().as_ref(), 4) != Some(vec![0, 1, 0, 1]) {
                    return Err(KeyRefusal::RsaExponent);
                }
                let modulus = padded(key.n().as_ref().to_be_bytes().as_ref(), RSA_MODULUS_LEN)
                    .ok_or(KeyRefusal::Malformed)?;
                let prime = key.primes().first().ok_or(KeyRefusal::Malformed)?;
                let raw = Zeroizing::new(prime.to_be_bytes());
                let prime = Zeroizing::new(
                    padded(raw.as_ref(), RSA_PRIME_LEN).ok_or(KeyRefusal::Malformed)?,
                );
                Material::Rsa {
                    modulus,
                    prime: SecretSlice::from(prime.to_vec()),
                }
            }
            KeyKind::EcdsaP256 => {
                let key = SecretKey::from_pkcs8_der(der).map_err(|_| KeyRefusal::Malformed)?;
                let point = key.public_key().to_sec1_point(false);
                let x = point
                    .x()
                    .and_then(|x| <[u8; P256_LEN]>::try_from(x.as_slice()).ok())
                    .ok_or(KeyRefusal::Malformed)?;
                let y = point
                    .y()
                    .and_then(|y| <[u8; P256_LEN]>::try_from(y.as_slice()).ok())
                    .ok_or(KeyRefusal::Malformed)?;
                let raw = Zeroizing::new(key.to_bytes());
                let scalar = Zeroizing::new(raw.to_vec());
                Material::P256 {
                    scalar: SecretSlice::from(scalar.to_vec()),
                    x,
                    y,
                }
            }
        };
        Ok(Self { material })
    }

    /// The secret bytes the TPM keeps: the RSA prime or the P-256 scalar.
    pub(super) fn secret(&self) -> &[u8] {
        match &self.material {
            Material::Rsa { prime, .. } => prime.expose_secret(),
            Material::P256 { scalar, .. } => scalar.expose_secret(),
        }
    }
}

// The secret parts are `SecretSlice`s, zeroed on drop, and everything else is public.
impl zeroize::ZeroizeOnDrop for ImportKey {}
