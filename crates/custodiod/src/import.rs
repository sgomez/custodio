//! `.p12` import: parse a PKCS#12 file with its password, accept only RSA 2048 and ECDSA P-256
//! keys that come with a certificate, and hand the result to the key store.
//!
//! The key is protected in the form [`choice`] names (TPM, encrypted TPM-bound or encrypted host-bound) by
//! [`protect`] and stored with the leaf certificate in one record under `<id>`; the PKCS#8 DER never reaches the store.

use std::fmt;

use p12_keystore::Pkcs12Archive;
use p256::elliptic_curve::sec1::ToSec1Point;
use pkcs8::PrivateKeyInfoRef;
use pkcs8::der::{
    Decode, Reader, SliceReader, asn1::AnyRef, asn1::ObjectIdentifier, asn1::UintRef,
};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use x509_cert::Certificate as X509;

use crate::creds::{Credentials, CredsError};
use crate::store::{KeyStore, Kind, Record, StoreError};
use crate::tpm::TpmAccess;
use crate::tpm::import::ImportError as TpmImportError;

pub mod choice;
pub mod protect;

/// `rsaEncryption` (RFC 8017).
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// `id-ecPublicKey` (RFC 5480).
const OID_EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `prime256v1` / secp256r1 (RFC 5480).
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// Modulus size accepted for RSA keys, in bits.
const RSA_BITS: usize = 2048;

pub use custodio_client::MAX_P12_LEN;

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
    /// The key could not be encrypted, or the credential was refused.
    Protect(CredsError),
    /// The TPM cannot be judged, or its import failed. Nothing is stored in a weaker form.
    Tpm(TpmImportError),
    /// The credential is bound to something else than the storage kind chosen.
    BindingMismatch,
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
            Self::Protect(e) => write!(f, "cannot protect the key: {e}"),
            Self::Tpm(e) => write!(f, "cannot import the key into the TPM: {e}"),
            Self::BindingMismatch => {
                f.write_str("the credential is bound to something else than the storage chosen")
            }
            Self::Store(e) => write!(f, "cannot store the key: {e}"),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<TpmImportError> for ImportError {
    fn from(e: TpmImportError) -> Self {
        Self::Tpm(e)
    }
}

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

/// Decodes a `.p12`. The service holds one; tests replace it to prove when it runs.
pub trait P12Decoder: Send + Sync {
    /// # Errors
    /// See [`ImportError`].
    fn decode(&self, data: &[u8], password: &SecretString) -> Result<ParsedP12, ImportError>;
}

/// The real decoder: [`parse_p12`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RealDecoder;

impl P12Decoder for RealDecoder {
    fn decode(&self, data: &[u8], password: &SecretString) -> Result<ParsedP12, ImportError> {
        parse_p12(data, password)
    }
}

/// Whether `owner` already has a key `id`.
///
/// # Errors
/// [`StoreError`] if the owner's area cannot be listed.
pub fn id_taken(store: &KeyStore, owner: u32, id: &str) -> Result<bool, StoreError> {
    let ids = store.list(owner)?;
    Ok(ids.iter().any(|i| i == id))
}

/// The name a key's credential is made under: it binds the credential to its owner and id.
#[must_use]
pub fn credential_name(owner: u32, id: &str) -> String {
    format!("custodio-{owner}-{id}")
}

/// Choose the storage kind (see [`choice`]), protect the key of `parsed` in it and store, for `owner`, one record
/// under `id` with the protected key and the certificate; returns the key type and the storage kind chosen. The plaintext key goes to the TPM or to the credential
/// service and nowhere else; it is dropped before the record is written. Every failure stores nothing.
///
/// # Errors
/// See [`ImportError`].
pub fn store_parsed(
    store: &KeyStore,
    creds: &dyn Credentials,
    tpm: &dyn TpmAccess,
    owner: u32,
    id: &str,
    parsed: ParsedP12,
) -> Result<(KeyKind, Kind), ImportError> {
    // Check up front so a taken id costs no encryption.
    if id_taken(store, owner, id)? {
        return Err(StoreError::AlreadyExists.into());
    }
    let protection = protect::protect(tpm, creds, &credential_name(owner, id), parsed)?;
    let record = Record::new(
        owner,
        id,
        protection.kind,
        &protection.certificate,
        protection.protected,
    )
    .map_err(StoreError::Record)?;
    store.put(&record)?;
    Ok((protection.key_type, protection.kind))
}

/// Undo [`store_parsed`] for `id`: remove the record.
///
/// # Errors
/// The [`StoreError`] of the removal.
pub fn rollback_import(store: &KeyStore, owner: u32, id: &str) -> Result<(), StoreError> {
    store.remove(owner, id)
}

/// Parse a `.p12` and store it for `owner`: [`parse_p12`], then [`store_parsed`].
///
/// # Errors
/// See [`ImportError`].
pub fn import_p12(
    store: &KeyStore,
    creds: &dyn Credentials,
    tpm: &dyn TpmAccess,
    owner: u32,
    id: &str,
    data: &[u8],
    password: &SecretString,
) -> Result<KeyKind, ImportError> {
    store_parsed(store, creds, tpm, owner, id, parse_p12(data, password)?)
        .map(|(key_type, _)| key_type)
}

fn unsupported(why: &str) -> ImportError {
    ImportError::UnsupportedKey(why.to_owned())
}

/// Decide whether a PKCS#8 DER key is RSA 2048 or ECDSA P-256.
pub(crate) fn classify(pkcs8_der: &[u8]) -> Result<KeyKind, ImportError> {
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
pub(crate) fn public_key_of(kind: KeyKind, pkcs8_der: &[u8]) -> Option<Vec<u8>> {
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
pub(crate) fn cert_public_key(kind: KeyKind, cert_der: &[u8]) -> Option<Vec<u8>> {
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

/// The key type and canonical public key (the form of [`public_key_of`]) of the public area of a TPM
/// blob; `None` for a key of another type.
pub(crate) fn blob_public_key(blob: &crate::tpm::blob::Blob) -> Option<(KeyKind, Vec<u8>)> {
    use tss_esapi::structures::Public;
    match blob.public_area().ok()? {
        Public::Rsa {
            parameters, unique, ..
        } => {
            // An exponent of 0 means the default, 65537.
            let e = match parameters.exponent().value() {
                0 => 65_537_u32,
                e => e,
            };
            Some((
                KeyKind::Rsa2048,
                rsa_canonical(unique.as_slice(), &e.to_be_bytes()),
            ))
        }
        Public::Ecc { unique, .. } => {
            let pad = |v: &[u8]| -> Option<Vec<u8>> {
                let fill = 32_usize.checked_sub(v.len())?;
                let mut out = vec![0_u8; fill];
                out.extend_from_slice(v);
                Some(out)
            };
            let mut point = vec![4_u8];
            point.extend(pad(unique.x().as_slice())?);
            point.extend(pad(unique.y().as_slice())?);
            Some((KeyKind::EcdsaP256, point))
        }
        _ => None,
    }
}

/// The key type of the public key in a certificate, if it is one of the two we accept.
pub(crate) fn certificate_kind(cert_der: &[u8]) -> Option<KeyKind> {
    [KeyKind::Rsa2048, KeyKind::EcdsaP256]
        .into_iter()
        .find(|k| cert_public_key(*k, cert_der).is_some())
}

#[cfg(test)]
mod tests;
