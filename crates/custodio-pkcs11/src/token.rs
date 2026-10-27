//! One token per key: what the module shows to PKCS#11 consumers, built from the certificate.

use cryptoki_sys::{
    CK_ATTRIBUTE_TYPE, CK_BBOOL, CK_OBJECT_HANDLE, CK_ULONG, CKA_ALWAYS_AUTHENTICATE,
    CKA_ALWAYS_SENSITIVE, CKA_CERTIFICATE_TYPE, CKA_CLASS, CKA_DECRYPT, CKA_DERIVE, CKA_EC_PARAMS,
    CKA_EXTRACTABLE, CKA_ID, CKA_ISSUER, CKA_KEY_TYPE, CKA_LABEL, CKA_LOCAL, CKA_MODIFIABLE,
    CKA_MODULUS, CKA_NEVER_EXTRACTABLE, CKA_PRIVATE, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE,
    CKA_SERIAL_NUMBER, CKA_SIGN, CKA_SIGN_RECOVER, CKA_SUBJECT, CKA_TOKEN, CKA_UNWRAP, CKA_VALUE,
    CKC_X_509, CKK_EC, CKK_RSA, CKO_CERTIFICATE, CKO_PRIVATE_KEY,
};
use pkcs1::RsaPublicKey;
use pkcs1::der::asn1::UintRef;
use pkcs1::der::{Decode, Encode};
use x509_cert::Certificate;
use x509_cert::der::asn1::ObjectIdentifier;

/// Handle of the certificate object of every token.
pub const CERT_HANDLE: CK_OBJECT_HANDLE = 1;
/// Handle of the private key object of every token.
pub const KEY_HANDLE: CK_OBJECT_HANDLE = 2;

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// DER of the `prime256v1` OID, the value of `CKA_EC_PARAMS`.
const P256_PARAMS: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// Length of a raw `r || s` P-256 signature.
const P256_SIGNATURE_LEN: usize = 64;

/// An attribute as `(type, value bytes)`.
pub type Attribute = (CK_ATTRIBUTE_TYPE, Vec<u8>);

/// Type and public parameters of the key behind a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyKind {
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    EcP256,
}

/// A key and its certificate, as seen through PKCS#11.
#[derive(Debug, Clone)]
pub struct Token {
    pub id: String,
    pub certificate: Vec<u8>,
    pub kind: KeyKind,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    serial: Vec<u8>,
}

fn boolean(v: bool) -> Vec<u8> {
    vec![CK_BBOOL::from(v)]
}

fn ulong(v: CK_ULONG) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

impl Token {
    /// Builds a token from the key id and its DER certificate. `None` if the certificate does not
    /// parse or holds a key type other than RSA or P-256, so such keys are not offered.
    #[must_use]
    pub fn parse(id: &str, certificate: &[u8]) -> Option<Self> {
        let cert = Certificate::from_der(certificate).ok()?;
        let tbs = cert.tbs_certificate();
        let spki = tbs.subject_public_key_info();
        let algorithm = spki.algorithm.oid;
        let kind = if algorithm == RSA_ENCRYPTION {
            let key =
                RsaPublicKey::<UintRef<'_>>::from_der(spki.subject_public_key.as_bytes()?).ok()?;
            KeyKind::Rsa {
                modulus: key.modulus.as_bytes().to_vec(),
                exponent: key.public_exponent.as_bytes().to_vec(),
            }
        } else if algorithm == EC_PUBLIC_KEY {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()?
                .decode_as::<ObjectIdentifier>()
                .ok()?;
            if curve != PRIME256V1 {
                return None;
            }
            KeyKind::EcP256
        } else {
            return None;
        };
        Some(Self {
            id: id.to_owned(),
            certificate: certificate.to_vec(),
            kind,
            subject: tbs.subject().to_der().ok()?,
            issuer: tbs.issuer().to_der().ok()?,
            serial: tbs.serial_number().to_der().ok()?,
        })
    }

    /// Length of the signature this key produces, so `C_Sign` can answer a length query and check
    /// the caller's buffer before it asks the user to authorize anything.
    #[must_use]
    pub fn signature_len(&self) -> usize {
        match &self.kind {
            KeyKind::Rsa { modulus, .. } => modulus.len(),
            KeyKind::EcP256 => P256_SIGNATURE_LEN,
        }
    }

    /// All attributes of an object, or `None` if the handle is not one of this token's objects.
    #[must_use]
    pub fn attributes(&self, handle: CK_OBJECT_HANDLE) -> Option<Vec<Attribute>> {
        let label = self.id.as_bytes().to_vec();
        match handle {
            CERT_HANDLE => Some(vec![
                (CKA_CLASS, ulong(CKO_CERTIFICATE)),
                (CKA_TOKEN, boolean(true)),
                (CKA_PRIVATE, boolean(false)),
                (CKA_MODIFIABLE, boolean(false)),
                (CKA_LABEL, label.clone()),
                (CKA_ID, label),
                (CKA_CERTIFICATE_TYPE, ulong(CKC_X_509)),
                (CKA_SUBJECT, self.subject.clone()),
                (CKA_ISSUER, self.issuer.clone()),
                (CKA_SERIAL_NUMBER, self.serial.clone()),
                (CKA_VALUE, self.certificate.clone()),
            ]),
            KEY_HANDLE => {
                let mut attrs = vec![
                    (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
                    (CKA_TOKEN, boolean(true)),
                    (CKA_PRIVATE, boolean(true)),
                    (CKA_MODIFIABLE, boolean(false)),
                    (CKA_LABEL, label.clone()),
                    (CKA_ID, label),
                    (CKA_SUBJECT, self.subject.clone()),
                    (CKA_SENSITIVE, boolean(true)),
                    (CKA_EXTRACTABLE, boolean(false)),
                    (CKA_NEVER_EXTRACTABLE, boolean(true)),
                    (CKA_ALWAYS_SENSITIVE, boolean(true)),
                    (CKA_LOCAL, boolean(false)),
                    (CKA_SIGN, boolean(true)),
                    (CKA_SIGN_RECOVER, boolean(false)),
                    (CKA_DECRYPT, boolean(false)),
                    (CKA_UNWRAP, boolean(false)),
                    (CKA_DERIVE, boolean(false)),
                    // Authorization is polkit's, asked on every signature by the service.
                    (CKA_ALWAYS_AUTHENTICATE, boolean(false)),
                ];
                match &self.kind {
                    KeyKind::Rsa { modulus, exponent } => {
                        attrs.push((CKA_KEY_TYPE, ulong(CKK_RSA)));
                        attrs.push((CKA_MODULUS, modulus.clone()));
                        attrs.push((CKA_PUBLIC_EXPONENT, exponent.clone()));
                    }
                    KeyKind::EcP256 => {
                        attrs.push((CKA_KEY_TYPE, ulong(CKK_EC)));
                        attrs.push((CKA_EC_PARAMS, P256_PARAMS.to_vec()));
                    }
                }
                Some(attrs)
            }
            _ => None,
        }
    }

    /// Whether an object matches every `(type, value)` of a search template.
    #[must_use]
    pub fn matches(&self, handle: CK_OBJECT_HANDLE, template: &[Attribute]) -> bool {
        let Some(attrs) = self.attributes(handle) else {
            return false;
        };
        template
            .iter()
            .all(|(t, v)| attrs.iter().any(|(at, av)| at == t && av == v))
    }
}

/// Attributes of the private key that exist but are never given out.
#[must_use]
pub fn is_sensitive(attribute: CK_ATTRIBUTE_TYPE) -> bool {
    use cryptoki_sys::{
        CKA_COEFFICIENT, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_PRIME_1, CKA_PRIME_2,
        CKA_PRIVATE_EXPONENT,
    };
    [
        CKA_VALUE,
        CKA_PRIVATE_EXPONENT,
        CKA_PRIME_1,
        CKA_PRIME_2,
        CKA_EXPONENT_1,
        CKA_EXPONENT_2,
        CKA_COEFFICIENT,
    ]
    .contains(&attribute)
}
