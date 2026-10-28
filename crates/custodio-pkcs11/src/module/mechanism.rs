//! The mechanisms a token offers, what `C_SignInit` accepts, and what the service is sent.

use cryptoki_sys::{
    CK_FLAGS, CK_MECHANISM_TYPE, CK_ULONG, CKF_EC_F_P, CKF_EC_NAMEDCURVE, CKF_SIGN,
    CKG_MGF1_SHA256, CKG_MGF1_SHA384, CKG_MGF1_SHA512, CKM_ECDSA, CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384, CKM_ECDSA_SHA512, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_SHA256,
    CKM_SHA256_RSA_PKCS, CKM_SHA384, CKM_SHA384_RSA_PKCS, CKM_SHA512, CKM_SHA512_RSA_PKCS,
    CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID,
};

use super::Rv;
use crate::backend::SignParams;
use crate::composed::{Composed, DigestHasher, sign_input};
use crate::token::{KeyKind, Token};

/// The message is fed to the hash in pieces of this size.
const HASH_CHUNK: usize = 1 << 20;

/// A mechanism the caller asked for, already checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    RsaPkcs,
    RsaPkcsPss {
        hash: CK_MECHANISM_TYPE,
        salt_len: CK_ULONG,
    },
    Ecdsa,
    /// Hashed in the module; the service gets the digest or its `DigestInfo`.
    Composed(Composed),
}

impl Mechanism {
    /// Checks a mechanism type and the `CK_RSA_PKCS_PSS_PARAMS` that came with it, if any. A
    /// mechanism that takes no parameter is also refused when the caller sent one (`pss` is `Some`).
    ///
    /// # Errors
    /// `CKR_MECHANISM_INVALID` or `CKR_MECHANISM_PARAM_INVALID`.
    pub fn new(
        mechanism: CK_MECHANISM_TYPE,
        pss: Option<(CK_MECHANISM_TYPE, CK_ULONG, CK_ULONG)>,
    ) -> Rv<Self> {
        if let Some(composed) = Composed::from_ckm(mechanism) {
            return match pss {
                None => Ok(Self::Composed(composed)),
                Some(_) => Err(CKR_MECHANISM_PARAM_INVALID),
            };
        }
        match (mechanism, pss) {
            (CKM_RSA_PKCS, None) => Ok(Self::RsaPkcs),
            (CKM_ECDSA, None) => Ok(Self::Ecdsa),
            (CKM_RSA_PKCS_PSS, Some((hash, mgf, salt_len))) => {
                let expected_mgf = match hash {
                    CKM_SHA256 => CKG_MGF1_SHA256,
                    CKM_SHA384 => CKG_MGF1_SHA384,
                    CKM_SHA512 => CKG_MGF1_SHA512,
                    _ => return Err(CKR_MECHANISM_PARAM_INVALID),
                };
                if mgf != expected_mgf || u32::try_from(salt_len).is_err() {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                Ok(Self::RsaPkcsPss { hash, salt_len })
            }
            (CKM_RSA_PKCS | CKM_ECDSA | CKM_RSA_PKCS_PSS, _) => Err(CKR_MECHANISM_PARAM_INVALID),
            _ => Err(CKR_MECHANISM_INVALID),
        }
    }

    pub(super) fn fits(self, kind: &KeyKind) -> bool {
        matches!(
            (self, kind),
            (Self::RsaPkcs | Self::RsaPkcsPss { .. }, KeyKind::Rsa { .. })
                | (Self::Ecdsa, KeyKind::EcP256)
        ) || matches!(self, Self::Composed(c) if composed_fits(c, kind))
    }

    /// What the service is told to do; a composed mechanism is its raw counterpart.
    pub(super) fn params(self) -> Rv<SignParams> {
        let (mechanism, hash, salt_len) = match self {
            Self::RsaPkcs => (CKM_RSA_PKCS, 0, 0),
            Self::Ecdsa => (CKM_ECDSA, 0, 0),
            Self::Composed(c) => (c.raw(), 0, 0),
            Self::RsaPkcsPss { hash, salt_len } => (
                CKM_RSA_PKCS_PSS,
                u32::try_from(hash).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?,
                u32::try_from(salt_len).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?,
            ),
        };
        Ok(SignParams {
            mechanism: u32::try_from(mechanism).map_err(|_| CKR_MECHANISM_INVALID)?,
            hash,
            salt_len,
        })
    }
}

const fn composed_fits(composed: Composed, kind: &KeyKind) -> bool {
    use crate::composed::KeyType;
    matches!(
        (composed.key_type(), kind),
        (KeyType::Rsa, KeyKind::Rsa { .. }) | (KeyType::EcP256, KeyKind::EcP256)
    )
}

/// Hashes the whole message in the module and returns what the service signs. A free function with
/// no access to the module, so it cannot run under the state lock.
pub(super) fn hash_message(composed: Composed, data: &[u8]) -> Vec<u8> {
    let mut hasher = DigestHasher::new(composed.hash());
    for chunk in data.chunks(HASH_CHUNK) {
        hasher.update(chunk);
    }
    sign_input(composed, &hasher)
}

const RSA_COMPOSED: [CK_MECHANISM_TYPE; 3] = [
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
];
const EC_COMPOSED: [CK_MECHANISM_TYPE; 3] = [CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512];

/// Mechanisms a token offers.
#[must_use]
pub fn mechanisms(token: &Token) -> Vec<CK_MECHANISM_TYPE> {
    let (raw, composed): (&[CK_MECHANISM_TYPE], _) = match token.kind {
        KeyKind::Rsa { .. } => (&[CKM_RSA_PKCS, CKM_RSA_PKCS_PSS], RSA_COMPOSED),
        KeyKind::EcP256 => (&[CKM_ECDSA], EC_COMPOSED),
    };
    raw.iter().copied().chain(composed).collect()
}

/// Key size bounds (in bits) and flags of a mechanism on a token, or `None` if the token does not
/// offer it.
#[must_use]
pub fn mechanism_info(token: &Token, mechanism: CK_MECHANISM_TYPE) -> Option<(CK_ULONG, CK_FLAGS)> {
    if !mechanisms(token).contains(&mechanism) {
        return None;
    }
    Some(match token.kind {
        KeyKind::EcP256 => (256, CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE),
        KeyKind::Rsa { .. } => (2048, CKF_SIGN),
    })
}
