//! `.p12` import: parse a PKCS#12 file with its password, accept only RSA 2048 and ECDSA P-256
//! keys that come with a certificate, and hand the result to the key store.
//!
//! The private key is stored as PKCS#8 DER under `<id>`, the leaf certificate as DER under
//! `<id>-cert`.

use std::fmt;

use p12_keystore::{KeyStore as P12KeyStore, Pkcs12ImportPolicy};
use pkcs8::PrivateKeyInfoRef;
use pkcs8::der::{
    Decode, Reader, SliceReader, asn1::AnyRef, asn1::ObjectIdentifier, asn1::UintRef,
};
use secrecy::{ExposeSecret, SecretSlice, SecretString};

use crate::store::{KeyStore, StoreError};

/// `rsaEncryption` (RFC 8017).
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// `id-ecPublicKey` (RFC 5480).
const OID_EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `prime256v1` / secp256r1 (RFC 5480).
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// Modulus size accepted for RSA keys, in bits.
const RSA_BITS: usize = 2048;

/// Largest `.p12` accepted. Real files are a few kilobytes.
pub const MAX_P12_LEN: usize = 1024 * 1024;

/// Key types Custodio accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Rsa2048,
    EcdsaP256,
}

/// Why an import failed.
#[derive(Debug)]
pub enum ImportError {
    /// The file is too large to be a `.p12` we accept.
    TooLarge,
    /// Not a valid PKCS#12 file, or the password is wrong.
    Parse(String),
    /// The file holds no private key.
    NoPrivateKey,
    /// The file holds more than one private key; import one at a time.
    MultipleKeys,
    /// The private key has no certificate.
    NoCertificate,
    /// The key is neither RSA 2048 nor ECDSA P-256.
    UnsupportedKey(String),
    /// The key store refused the key or certificate.
    Store(StoreError),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "the .p12 file is larger than {MAX_P12_LEN} bytes"),
            Self::Parse(why) => write!(
                f,
                "cannot read the .p12 file (corrupt, unsupported, or wrong password): {why}"
            ),
            Self::NoPrivateKey => write!(f, "the .p12 file contains no private key"),
            Self::MultipleKeys => write!(f, "the .p12 file contains more than one private key"),
            Self::NoCertificate => write!(f, "the private key has no certificate in the .p12 file"),
            Self::UnsupportedKey(why) => write!(
                f,
                "unsupported key: {why}; only RSA 2048 and ECDSA P-256 are accepted"
            ),
            Self::Store(e) => write!(f, "cannot store the key: {e}"),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<StoreError> for ImportError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// A validated key and its certificate, ready to store.
pub struct ParsedP12 {
    pub kind: KeyKind,
    /// PKCS#8 DER of the private key.
    pub key: SecretSlice<u8>,
    /// DER of the leaf certificate.
    pub certificate: Vec<u8>,
}

impl fmt::Debug for ParsedP12 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedP12")
            .field("kind", &self.kind)
            .field("key", &"[REDACTED]")
            .field("certificate_len", &self.certificate.len())
            .finish()
    }
}

/// Parse a `.p12` and check that it holds exactly one RSA 2048 or ECDSA P-256 key with a
/// certificate.
///
/// # Errors
/// See [`ImportError`].
pub fn parse_p12(data: &[u8], password: &SecretString) -> Result<ParsedP12, ImportError> {
    if data.len() > MAX_P12_LEN {
        return Err(ImportError::TooLarge);
    }
    let ks = P12KeyStore::from_pkcs12(data, password.expose_secret(), Pkcs12ImportPolicy::Relaxed)
        .map_err(|e| ImportError::Parse(e.to_string()))?;
    let mut chains = ks.entries().filter_map(|(_, entry)| match entry {
        p12_keystore::KeyStoreEntry::PrivateKeyChain(chain) => Some(chain),
        _ => None,
    });
    let chain = chains.next().ok_or(ImportError::NoPrivateKey)?;
    if chains.next().is_some() {
        return Err(ImportError::MultipleKeys);
    }
    let kind = classify(chain.key().as_der())?;
    let leaf = chain.certs().first().ok_or(ImportError::NoCertificate)?;
    Ok(ParsedP12 {
        kind,
        key: SecretSlice::from(chain.key().as_der().to_vec()),
        certificate: leaf.as_der().to_vec(),
    })
}

/// Parse a `.p12` and store its key as `id` and its certificate as `<id>-cert`.
///
/// The certificate is written first: it is public, so a failure between the two writes leaves
/// nothing sensitive behind.
///
/// # Errors
/// See [`ImportError`].
pub fn import_p12(
    store: &KeyStore,
    id: &str,
    data: &[u8],
    password: &SecretString,
) -> Result<KeyKind, ImportError> {
    let parsed = parse_p12(data, password)?;
    store.put(&cert_id(id), &SecretSlice::from(parsed.certificate))?;
    store.put(id, &parsed.key)?;
    Ok(parsed.kind)
}

/// Key store id of the certificate belonging to key `id`.
#[must_use]
pub fn cert_id(id: &str) -> String {
    format!("{id}-cert")
}

fn unsupported(why: &str) -> ImportError {
    ImportError::UnsupportedKey(why.to_owned())
}

/// Decide whether a PKCS#8 DER key is RSA 2048 or ECDSA P-256.
fn classify(pkcs8_der: &[u8]) -> Result<KeyKind, ImportError> {
    let info =
        PrivateKeyInfoRef::from_der(pkcs8_der).map_err(|_| unsupported("malformed PKCS#8 key"))?;
    let oid = info.algorithm.oid;
    if oid == OID_RSA {
        let bits = rsa_modulus_bits(info.private_key.as_bytes())
            .ok_or_else(|| unsupported("malformed RSA key"))?;
        if bits == RSA_BITS {
            Ok(KeyKind::Rsa2048)
        } else {
            Err(unsupported(&format!("RSA {bits}")))
        }
    } else if oid == OID_EC {
        let curve = info
            .algorithm
            .parameters
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        if curve == Some(OID_P256) {
            Ok(KeyKind::EcdsaP256)
        } else {
            Err(unsupported("elliptic curve other than P-256"))
        }
    } else {
        Err(unsupported(&format!("algorithm {oid}")))
    }
}

/// Bit length of the modulus in a PKCS#1 `RSAPrivateKey`.
fn rsa_modulus_bits(pkcs1: &[u8]) -> Option<usize> {
    let mut reader = SliceReader::new(pkcs1).ok()?;
    let modulus = reader
        .sequence(|r| -> Result<&[u8], pkcs8::der::Error> {
            let _version = UintRef::decode(r)?;
            let modulus = UintRef::decode(r)?;
            // Skip the remaining fields; the modulus is all we need.
            while !r.is_finished() {
                let _ = AnyRef::decode(r)?;
            }
            Ok(modulus.as_bytes())
        })
        .ok()?;
    let top = usize::try_from(modulus.first()?.leading_zeros()).ok()?;
    (modulus.len() * 8).checked_sub(top)
}
