//! The composed mechanisms (`CKM_SHA256_RSA_PKCS` and the like): which hash and raw service
//! mechanism each one maps to, the incremental hash and the `DigestInfo` of RFC 8017 section 9.2.
//!
//! Pure code: no FFI, no bus, no session state. The module hashes in the client's process and the
//! service only ever receives a digest or a `DigestInfo` that holds one.
//!
//! SHA-384 and SHA-512 digests on P-256 are passed whole; the service truncates them to the
//! leftmost 32 bytes (see `docs/decisions.md`).
#![forbid(unsafe_code)]

use std::fmt;

use cryptoki_sys::{
    CK_MECHANISM_TYPE, CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512,
    CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Hash of a composed mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
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

    /// The `DigestInfo` DER up to the digest (RFC 8017 section 9.2, note 1).
    const fn prefix(self) -> &'static [u8] {
        match self {
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/// The key type a mechanism needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    EcP256,
}

/// A composed mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Composed {
    Sha256RsaPkcs,
    Sha384RsaPkcs,
    Sha512RsaPkcs,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
}

impl Composed {
    /// The composed mechanism with this `CKM_*` value; `None` for raw and unknown ones.
    #[must_use]
    pub fn from_ckm(ckm: CK_MECHANISM_TYPE) -> Option<Self> {
        Some(match ckm {
            CKM_SHA256_RSA_PKCS => Self::Sha256RsaPkcs,
            CKM_SHA384_RSA_PKCS => Self::Sha384RsaPkcs,
            CKM_SHA512_RSA_PKCS => Self::Sha512RsaPkcs,
            CKM_ECDSA_SHA256 => Self::EcdsaSha256,
            CKM_ECDSA_SHA384 => Self::EcdsaSha384,
            CKM_ECDSA_SHA512 => Self::EcdsaSha512,
            _ => return None,
        })
    }

    /// The `CKM_*` value.
    #[must_use]
    pub const fn ckm(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Sha256RsaPkcs => CKM_SHA256_RSA_PKCS,
            Self::Sha384RsaPkcs => CKM_SHA384_RSA_PKCS,
            Self::Sha512RsaPkcs => CKM_SHA512_RSA_PKCS,
            Self::EcdsaSha256 => CKM_ECDSA_SHA256,
            Self::EcdsaSha384 => CKM_ECDSA_SHA384,
            Self::EcdsaSha512 => CKM_ECDSA_SHA512,
        }
    }

    /// The hash applied to the data.
    #[must_use]
    pub const fn hash(self) -> Hash {
        match self {
            Self::Sha256RsaPkcs | Self::EcdsaSha256 => Hash::Sha256,
            Self::Sha384RsaPkcs | Self::EcdsaSha384 => Hash::Sha384,
            Self::Sha512RsaPkcs | Self::EcdsaSha512 => Hash::Sha512,
        }
    }

    /// The key type the mechanism needs.
    #[must_use]
    pub const fn key_type(self) -> KeyType {
        match self {
            Self::Sha256RsaPkcs | Self::Sha384RsaPkcs | Self::Sha512RsaPkcs => KeyType::Rsa,
            Self::EcdsaSha256 | Self::EcdsaSha384 | Self::EcdsaSha512 => KeyType::EcP256,
        }
    }

    /// The raw mechanism the service is asked for.
    #[must_use]
    pub const fn raw(self) -> CK_MECHANISM_TYPE {
        match self.key_type() {
            KeyType::Rsa => CKM_RSA_PKCS,
            KeyType::EcP256 => CKM_ECDSA,
        }
    }
}

#[derive(Clone)]
enum State {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

/// Incremental hash. Clone it to finalize a copy and keep the original.
#[derive(Clone)]
pub struct DigestHasher {
    state: State,
}

// Manual: the state holds a function of the signed data.
impl fmt::Debug for DigestHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestHasher")
            .field("hash", &self.hash())
            .finish_non_exhaustive()
    }
}

impl DigestHasher {
    #[must_use]
    pub fn new(hash: Hash) -> Self {
        Self {
            state: match hash {
                Hash::Sha256 => State::Sha256(Sha256::new()),
                Hash::Sha384 => State::Sha384(Sha384::new()),
                Hash::Sha512 => State::Sha512(Sha512::new()),
            },
        }
    }

    #[must_use]
    pub const fn hash(&self) -> Hash {
        match self.state {
            State::Sha256(_) => Hash::Sha256,
            State::Sha384(_) => Hash::Sha384,
            State::Sha512(_) => Hash::Sha512,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match &mut self.state {
            State::Sha256(h) => h.update(data),
            State::Sha384(h) => h.update(data),
            State::Sha512(h) => h.update(data),
        }
    }

    /// The digest of everything fed so far.
    #[must_use]
    pub fn finalize(self) -> Vec<u8> {
        match self.state {
            State::Sha256(h) => h.finalize().to_vec(),
            State::Sha384(h) => h.finalize().to_vec(),
            State::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// The digest does not have the length of the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadDigestLength;

impl fmt::Display for BadDigestLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("digest length does not match the hash")
    }
}

impl std::error::Error for BadDigestLength {}

/// The `DigestInfo` of RFC 8017 section 9.2 for `digest`.
///
/// # Errors
/// If `digest` is not as long as the output of `hash`.
pub fn digest_info(hash: Hash, digest: &[u8]) -> Result<Vec<u8>, BadDigestLength> {
    if digest.len() != hash.len() {
        return Err(BadDigestLength);
    }
    let prefix = hash.prefix();
    let mut out = Vec::with_capacity(prefix.len() + digest.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(digest);
    Ok(out)
}

/// The bytes the service signs for `mechanism` after `hasher` has seen the data: the `DigestInfo`
/// for RSA, the bare digest for ECDSA. Finalizes a clone, so `hasher` stays usable.
///
/// The `DigestInfo` follows the hasher's own hash, whose digest always has the right length.
#[must_use]
pub fn sign_input(mechanism: Composed, hasher: &DigestHasher) -> Vec<u8> {
    let digest = hasher.clone().finalize();
    match mechanism.key_type() {
        KeyType::EcP256 => digest,
        KeyType::Rsa => digest_info(hasher.hash(), &digest).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests;
