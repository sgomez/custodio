//! The outer wrap of `TPM2_Import`: the key never crosses the TCTI in the clear (TCG TPM 2.0 Part 1, "Duplication").
//!
//! The parent is an ECC P-256 storage key, so the seed is shared by ECDH with a fresh ephemeral key: the TPM receives the
//! ephemeral public point (`inSymSeed`) and derives the same seed. From the seed: `symKey = KDFa("STORAGE", name)` and
//! `hmacKey = KDFa("INTEGRITY")`. The sensitive area (`TPM2B_SENSITIVE`) is encrypted with AES-128-CFB under a zero IV and
//! the private buffer is `TPM2B_DIGEST(HMAC(hmacKey, encrypted || name)) || encrypted`. The seed, both derived keys and
//! the sensitive area are `Zeroizing` and gone when [`wrap`] returns; only the ephemeral public point leaves.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use p256::SecretKey;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest as _, Sha256};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{
    Digest, EccParameter, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public,
    PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
    RsaExponent, RsaScheme,
};
use zeroize::Zeroizing;

use super::import::ImportError;
use super::key::{ImportKey, Material};

/// `TPM_ALG_SHA256`, the name algorithm of the parent and of the imported key.
pub const ALG_SHA256: u16 = 0x000b;
const ALG_RSA: u16 = 0x0001;
const ALG_ECC: u16 = 0x0023;
const SYM_BITS: usize = 128;
const HASH_BITS: usize = 256;

type HmacSha256 = Hmac<Sha256>;

/// What `TPM2_Import` is given besides the parent.
pub struct Wrapped {
    pub public: Public,
    /// The `TPM2B_PRIVATE` buffer: integrity then encrypted sensitive area.
    pub duplicate: Vec<u8>,
    /// The marshalled `TPMS_ECC_POINT` of the ephemeral key (`inSymSeed`).
    pub seed_point: Vec<u8>,
}

/// A `TPM2B`: two-byte big-endian size, then the bytes.
fn sized(bytes: &[u8]) -> Result<Vec<u8>, ImportError> {
    let len = u16::try_from(bytes.len()).map_err(|_| ImportError::Internal)?;
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

/// `KDFa` of SP 800-108 in counter mode with HMAC-SHA-256 (TCG TPM 2.0 Part 1, B.10.2). `bits` is a multiple of 8.
///
/// # Errors
/// [`ImportError::Internal`] when the request does not fit the counter or the key is refused.
pub fn kdfa(
    key: &[u8],
    label: &str,
    context_u: &[u8],
    context_v: &[u8],
    bits: usize,
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let bits32 = u32::try_from(bits).map_err(|_| ImportError::Internal)?;
    let mut out = Zeroizing::new(Vec::with_capacity(bits.div_ceil(8) + 32));
    for counter in 1..=u32::try_from(bits.div_ceil(HASH_BITS)).map_err(|_| ImportError::Internal)? {
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key)
            .map_err(|_| ImportError::Internal)?;
        mac.update(&counter.to_be_bytes());
        mac.update(label.as_bytes());
        mac.update(&[0]);
        mac.update(context_u);
        mac.update(context_v);
        mac.update(&bits32.to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
    }
    out.truncate(bits.div_ceil(8));
    Ok(out)
}

/// `KDFe` of SP 800-56A with SHA-256 (TCG TPM 2.0 Part 1, B.10.3).
#[must_use]
pub fn kdfe(
    z: &[u8],
    label: &str,
    party_u: &[u8],
    party_v: &[u8],
    bits: usize,
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    for counter in 1..=u32::try_from(bits.div_ceil(HASH_BITS)).unwrap_or(0) {
        let mut hash = Sha256::new();
        hash.update(counter.to_be_bytes());
        hash.update(z);
        hash.update(label.as_bytes());
        hash.update([0]);
        hash.update(party_u);
        hash.update(party_v);
        out.extend_from_slice(&hash.finalize());
    }
    out.truncate(bits.div_ceil(8));
    out
}

/// AES-128 in CFB mode (full-block feedback) with a zero IV, in place.
///
/// # Errors
/// [`ImportError::Internal`] when `key` is not 16 bytes.
pub fn cfb_encrypt(key: &[u8], data: &mut [u8]) -> Result<(), ImportError> {
    let cipher = Aes128::new_from_slice(key).map_err(|_| ImportError::Internal)?;
    let mut feedback = Array::from([0u8; 16]);
    for chunk in data.chunks_mut(16) {
        cipher.encrypt_block(&mut feedback);
        for (byte, mask) in chunk.iter_mut().zip(feedback.iter()) {
            *byte ^= mask;
        }
        // The next block is encrypted from this ciphertext; a short last chunk has no next block.
        if let Ok(next) = <[u8; 16]>::try_from(&*chunk) {
            feedback = Array::from(next);
        }
    }
    Ok(())
}

/// The name of a public area: `nameAlg || H(TPMT_PUBLIC)`.
#[must_use]
pub fn name_of(marshalled_public: &[u8]) -> Vec<u8> {
    let mut name = ALG_SHA256.to_be_bytes().to_vec();
    name.extend_from_slice(&Sha256::digest(marshalled_public));
    name
}

/// The public area of the imported key: usages and flags per `docs/decisions.md` ("the service pads").
///
/// `fixedTPM` and `fixedParent` are clear (`TPM2_Import` requires it), `sensitiveDataOrigin` is clear (the TPM did not
/// generate the key), `userWithAuth` is set with an empty `authValue`, and `adminWithPolicy` is set with an empty
/// `authPolicy`: no policy digest is empty, so the admin role (which includes `TPM2_Duplicate`) is unusable.
///
/// # Errors
/// [`ImportError::Internal`] when a value does not fit its field.
pub fn template(key: &ImportKey) -> Result<Public, ImportError> {
    let is_rsa = matches!(key.material, Material::Rsa { .. });
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(false)
        .with_fixed_parent(false)
        .with_sensitive_data_origin(false)
        .with_user_with_auth(true)
        .with_admin_with_policy(true)
        .with_restricted(false)
        .with_decrypt(is_rsa)
        .with_sign_encrypt(true)
        .build()
        .map_err(|_| ImportError::Internal)?;
    let builder = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_auth_policy(Digest::default());
    let built = match &key.material {
        Material::Rsa { modulus, .. } => builder
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_scheme(RsaScheme::Null)
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(RsaExponent::default())
                    .with_is_signing_key(true)
                    .with_is_decryption_key(true)
                    .with_restricted(false)
                    .build()
                    .map_err(|_| ImportError::Internal)?,
            )
            .with_rsa_unique_identifier(
                PublicKeyRsa::try_from(modulus.clone()).map_err(|_| ImportError::Internal)?,
            ),
        Material::P256 { x, y, .. } => builder
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                    .with_curve(EccCurve::NistP256)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .with_is_signing_key(true)
                    .with_is_decryption_key(false)
                    .with_restricted(false)
                    .build()
                    .map_err(|_| ImportError::Internal)?,
            )
            .with_ecc_unique_identifier(EccPoint::new(
                EccParameter::try_from(x.to_vec()).map_err(|_| ImportError::Internal)?,
                EccParameter::try_from(y.to_vec()).map_err(|_| ImportError::Internal)?,
            )),
    };
    built.build().map_err(|_| ImportError::Internal)
}

/// `TPM2B_SENSITIVE` of the key: type, empty `authValue`, empty `seedValue`, the secret.
pub(super) fn sensitive(key: &ImportKey) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let kind = match key.material {
        Material::Rsa { .. } => ALG_RSA,
        Material::P256 { .. } => ALG_ECC,
    };
    let mut inner = Zeroizing::new(kind.to_be_bytes().to_vec());
    inner.extend_from_slice(&[0, 0, 0, 0]);
    inner.extend_from_slice(&sized(key.secret())?);
    Ok(Zeroizing::new(sized(&inner)?))
}

/// Wraps `key` to the parent whose public point is `parent_x`, `parent_y`, with `ephemeral` as the sender's key.
///
/// # Errors
/// [`ImportError::Internal`] when a value does not fit its field or the parent point is not on the curve.
pub fn wrap(
    key: &ImportKey,
    parent_x: &[u8],
    parent_y: &[u8],
    ephemeral: &SecretKey,
) -> Result<Wrapped, ImportError> {
    let public = template(key)?;
    let marshalled = {
        use tss_esapi::traits::Marshall;
        public.marshall().map_err(|_| ImportError::Internal)?
    };
    let name = name_of(&marshalled);

    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(parent_x);
    sec1.extend_from_slice(parent_y);
    let parent = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| ImportError::Internal)?;
    let shared = (parent.to_projective() * *ephemeral.to_nonzero_scalar()).to_affine();
    let z = Zeroizing::new(shared.x().to_vec());
    let eph = ephemeral.public_key().to_sec1_point(false);
    let (ex, ey) = match (eph.x(), eph.y()) {
        (Some(x), Some(y)) => (x.to_vec(), y.to_vec()),
        _ => return Err(ImportError::Internal),
    };

    let seed = kdfe(&z, "DUPLICATE", &ex, parent_x, HASH_BITS);
    let sym_key = kdfa(&seed, "STORAGE", &name, &[], SYM_BITS)?;
    let hmac_key = kdfa(&seed, "INTEGRITY", &[], &[], HASH_BITS)?;

    let mut encrypted = sensitive(key)?;
    cfb_encrypt(&sym_key, &mut encrypted)?;
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(&hmac_key)
        .map_err(|_| ImportError::Internal)?;
    mac.update(&encrypted);
    mac.update(&name);
    let integrity = mac.finalize().into_bytes();

    let mut duplicate = sized(&integrity)?;
    duplicate.extend_from_slice(&encrypted);
    let mut seed_point = sized(&ex)?;
    seed_point.extend_from_slice(&sized(&ey)?);
    Ok(Wrapped {
        public,
        duplicate,
        seed_point,
    })
}
