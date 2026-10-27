//! `.p12` import: parse a PKCS#12 file with its password, accept only RSA 2048 and ECDSA P-256
//! keys that come with a certificate, and hand the result to the key store.
//!
//! The private key is stored as PKCS#8 DER under `<id>`, the leaf certificate as DER under
//! `<id>-cert`.

use std::fmt;

use p12_keystore::Pkcs12Archive;
use p256::elliptic_curve::sec1::ToSec1Point;
use pkcs8::PrivateKeyInfoRef;
use pkcs8::der::{
    Decode, Reader, SliceReader, asn1::AnyRef, asn1::ObjectIdentifier, asn1::UintRef,
};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use x509_cert::Certificate as X509;

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
    /// None of the certificates in the file carries the public key of the private key.
    CertificateMismatch,
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
            Self::CertificateMismatch => {
                write!(f, "no certificate in the .p12 file matches the private key")
            }
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
    // The archive API keeps key bags that have no `localKeyId`; `KeyStore` would drop them.
    let archive = Pkcs12Archive::from_pkcs12(data, password.expose_secret())
        .map_err(|e| ImportError::Parse(e.to_string()))?;
    check_archive(&archive)
}

/// The checks of [`parse_p12`] on an already decoded archive.
///
/// # Errors
/// See [`ImportError`].
pub fn check_archive(archive: &Pkcs12Archive) -> Result<ParsedP12, ImportError> {
    let mut keys = archive.keys.iter();
    let bag = keys.next().ok_or(ImportError::NoPrivateKey)?;
    if keys.next().is_some() {
        return Err(ImportError::MultipleKeys);
    }
    let der = bag.key.as_der();
    let kind = classify(der)?;
    if archive.certs.is_empty() {
        return Err(ImportError::NoCertificate);
    }
    // `localKeyId` is attacker-controlled, so pair the key with a certificate by public key.
    let wanted = public_key_of(kind, der).ok_or_else(|| unsupported("malformed private key"))?;
    let leaf = archive
        .certs
        .iter()
        .find(|c| cert_public_key(kind, c.cert.as_der()).is_some_and(|pk| pk == wanted))
        .ok_or(ImportError::CertificateMismatch)?;
    Ok(ParsedP12 {
        kind,
        key: SecretSlice::from(der.to_vec()),
        certificate: leaf.cert.as_der().to_vec(),
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
    // Check up front so a refused key write cannot leave a certificate without a key behind.
    let ids = store.list()?;
    if ids.iter().any(|i| i == id || *i == cert_id(id)) {
        return Err(StoreError::AlreadyExists.into());
    }
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

/// Strip leading zero bytes of a DER unsigned integer.
fn trim(bytes: &[u8]) -> &[u8] {
    let n = bytes.iter().take_while(|b| **b == 0).count();
    bytes.get(n..).unwrap_or_default()
}

/// Canonical public key of a PKCS#8 private key: `n || e` (each length-prefixed) for RSA, the
/// uncompressed SEC1 point for P-256. The point is computed from the private scalar, never taken
/// from the file.
fn public_key_of(kind: KeyKind, pkcs8_der: &[u8]) -> Option<Vec<u8>> {
    let info = PrivateKeyInfoRef::from_der(pkcs8_der).ok()?;
    match kind {
        KeyKind::Rsa2048 => {
            let mut reader = SliceReader::new(info.private_key.as_bytes()).ok()?;
            reader
                .sequence(|r| -> Result<Vec<u8>, pkcs8::der::Error> {
                    let _version = UintRef::decode(r)?;
                    let n = UintRef::decode(r)?;
                    let e = UintRef::decode(r)?;
                    while !r.is_finished() {
                        let _ = AnyRef::decode(r)?;
                    }
                    Ok(rsa_canonical(n.as_bytes(), e.as_bytes()))
                })
                .ok()
        }
        KeyKind::EcdsaP256 => {
            let ec = sec1::EcPrivateKey::from_der(info.private_key.as_bytes()).ok()?;
            let secret = p256::SecretKey::from_slice(ec.private_key).ok()?;
            Some(secret.public_key().to_sec1_point(false).as_bytes().to_vec())
        }
    }
}

fn rsa_canonical(n: &[u8], e: &[u8]) -> Vec<u8> {
    let (n, e) = (trim(n), trim(e));
    let mut out = Vec::with_capacity(n.len() + e.len() + 8);
    out.extend_from_slice(&n.len().to_be_bytes());
    out.extend_from_slice(n);
    out.extend_from_slice(e);
    out
}

/// Public key of a certificate in the same form as [`public_key_of`]; `None` if the certificate
/// does not parse or holds a key of another type.
fn cert_public_key(kind: KeyKind, cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = X509::from_der(cert_der).ok()?;
    let spki = cert.tbs_certificate().subject_public_key_info();
    let oid = spki.algorithm.oid;
    let bits = spki.subject_public_key.as_bytes()?;
    match kind {
        KeyKind::Rsa2048 if oid == OID_RSA => {
            let mut reader = SliceReader::new(bits).ok()?;
            reader
                .sequence(|r| -> Result<Vec<u8>, pkcs8::der::Error> {
                    let n = UintRef::decode(r)?;
                    let e = UintRef::decode(r)?;
                    Ok(rsa_canonical(n.as_bytes(), e.as_bytes()))
                })
                .ok()
        }
        KeyKind::EcdsaP256 if oid == OID_EC => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
            (curve == Some(OID_P256)).then(|| bits.to_vec())
        }
        _ => None,
    }
}
