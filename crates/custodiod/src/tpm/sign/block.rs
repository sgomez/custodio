//! The front end of a TPM signature: what the request is checked against and the blocks the TPM is given.
//!
//! The bounds are those of `crate::sign::sign`, in the same order: the mechanism must fit the key type, then the lengths.
//! Nothing here calls the TPM, and the only thing looked at in the caller's data is its length.

use rand::Rng as _;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::Public;

use super::{Prepared, TpmSignError};
use crate::sign::{Mechanism, PssHash, SignError};
use crate::tpm::blob::Blob;

/// The modulus length of an RSA 2048 key, in bytes.
pub const K: usize = 256;
/// The digest `TPM2_Sign` is given (SHA-256, the scheme of the key).
pub const DIGEST: usize = 32;
/// The last byte of an EMSA-PSS block.
const TRAILER: u8 = 0xbc;

/// The key type of a blob, from its public area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Rsa2048,
    P256,
}

/// The key type of the stored public area. Anything but RSA 2048 and ECC P-256 is a bug, not a request error.
///
/// # Errors
/// [`TpmSignError::Internal`].
pub fn kind_of(blob: &Blob) -> Result<Kind, TpmSignError> {
    match blob.public_area().map_err(|_| TpmSignError::Internal)? {
        Public::Rsa { parameters, .. } if parameters.key_bits() == RsaKeyBits::Rsa2048 => {
            Ok(Kind::Rsa2048)
        }
        Public::Ecc { parameters, .. } if parameters.ecc_curve() == EccCurve::NistP256 => {
            Ok(Kind::P256)
        }
        _ => Err(TpmSignError::Internal),
    }
}

const fn refused(why: SignError) -> TpmSignError {
    TpmSignError::Refused(why)
}

/// Validates the request as `crate::sign::sign` does and builds what the TPM is given.
///
/// # Errors
/// [`TpmSignError::Refused`] with the class `crate::sign::sign` returns for the same input; [`TpmSignError::Internal`] for
/// a blob that is not a supported key.
pub fn prepare(blob: &Blob, mechanism: Mechanism, data: &[u8]) -> Result<Prepared, TpmSignError> {
    prepare_with(kind_of(blob)?, mechanism, data, &mut |salt| {
        rand::rng().fill_bytes(salt);
    })
}

/// [`prepare`] for a known key type, with the source of the PSS salt given (tests fix it).
///
/// # Errors
/// As [`prepare`].
pub fn prepare_with(
    kind: Kind,
    mechanism: Mechanism,
    data: &[u8],
    fill_salt: &mut dyn FnMut(&mut [u8]),
) -> Result<Prepared, TpmSignError> {
    match (kind, mechanism) {
        (Kind::Rsa2048, Mechanism::RsaPkcs) => pkcs1_block(data)
            .map(Prepared::Rsa)
            .ok_or(refused(SignError::BadData)),
        (Kind::Rsa2048, Mechanism::RsaPkcsPss { hash, salt_len }) => {
            // Both bounds are checked before the salt is allocated.
            if data.len() != hash.len() || salt_len > K - hash.len() - 2 {
                return Err(refused(SignError::BadData));
            }
            let mut salt = vec![0u8; salt_len];
            fill_salt(&mut salt);
            Ok(Prepared::Rsa(pss_block(hash, data, &salt)))
        }
        (Kind::P256, Mechanism::Ecdsa) => ecdsa_digest(data)
            .map(Prepared::Ecdsa)
            .ok_or(refused(SignError::BadData)),
        _ => Err(refused(SignError::MechanismMismatch)),
    }
}

/// `00 01 FF..FF 00 payload`, `K` bytes. `None` when the payload is longer than `K - 11`.
#[must_use]
pub fn pkcs1_block(payload: &[u8]) -> Option<Vec<u8>> {
    let padding = K.checked_sub(payload.len())?.checked_sub(3)?;
    if padding < 8 {
        return None;
    }
    let mut block = vec![0x00, 0x01];
    block.resize(2 + padding, 0xff);
    block.push(0x00);
    block.extend_from_slice(payload);
    Some(block)
}

/// The digest the TPM signs: the leftmost 32 bytes of a longer one, a shorter one with zeros on the left, as the integer
/// it is (`crate::sign::sign` does the same). `None` for the empty digest, the only one it refuses.
#[must_use]
pub fn ecdsa_digest(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let mut digest = vec![0u8; DIGEST.saturating_sub(data.len())];
    digest.extend(data.iter().take(DIGEST));
    Some(digest)
}

/// EMSA-PSS-ENCODE of the digest `mhash` with MGF1 of the same hash and this salt, `K` bytes with the top bit clear.
/// `mhash` is `hash.len()` bytes and `salt.len() <= K - hash.len() - 2` (the caller checked).
#[must_use]
pub fn pss_block(hash: PssHash, mhash: &[u8], salt: &[u8]) -> Vec<u8> {
    match hash {
        PssHash::Sha256 => emsa_pss::<Sha256>(mhash, salt),
        PssHash::Sha384 => emsa_pss::<Sha384>(mhash, salt),
        PssHash::Sha512 => emsa_pss::<Sha512>(mhash, salt),
    }
}

fn emsa_pss<D: Digest>(mhash: &[u8], salt: &[u8]) -> Vec<u8> {
    // H = Hash(00*8 || mHash || salt)
    let mut hasher = D::new();
    hasher.update([0u8; 8]);
    hasher.update(mhash);
    hasher.update(salt);
    let h = hasher.finalize();
    // DB = 00..00 || 01 || salt, masked with MGF1(H)
    let db_len = K - <D as Digest>::output_size() - 1;
    let mut db = vec![0u8; db_len.saturating_sub(salt.len() + 1)];
    db.push(0x01);
    db.extend_from_slice(salt);
    for (byte, mask) in db.iter_mut().zip(mgf1::<D>(&h, db_len)) {
        *byte ^= mask;
    }
    // 8 * K - 2047 = 1 bit of the leftmost byte is cleared.
    if let Some(first) = db.first_mut() {
        *first &= 0x7f;
    }
    db.extend_from_slice(&h);
    db.push(TRAILER);
    db
}

fn mgf1<D: Digest>(seed: &[u8], len: usize) -> Vec<u8> {
    let blocks = u32::try_from(len.div_ceil(<D as Digest>::output_size())).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(len + <D as Digest>::output_size());
    for counter in 0..blocks {
        let mut hasher = D::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
    }
    out.truncate(len);
    out
}
