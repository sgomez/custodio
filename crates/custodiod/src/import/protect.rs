//! Protecting a decoded key in the form [`choose`] names, failing closed.
//!
//! The plaintext key is taken by value and dropped before the protected form is returned, so no later step can reach
//! it. Every error after the choice ends the import: nothing is retried under another kind, and the binding the
//! credential names must agree with the chosen kind.

use secrecy::ExposeSecret;

use super::choice::{choose, tpm_key_type};
use super::{ImportError, KeyKind, ParsedP12};
use crate::creds::{Binding, Credentials, seal};
use crate::store::{Kind, Protected, StoreError};
use crate::tpm::import::{ImportError as TpmImportError, import_pkcs8};
use crate::tpm::{TpmAccess, assess};

/// A key in its protected form, with the certificate to store next to it.
pub struct Protection {
    pub kind: Kind,
    pub protected: Protected,
    pub certificate: Vec<u8>,
    pub key_type: KeyKind,
}

/// The binding a credential must name for `kind`; `None` for a kind that is not a credential.
const fn required_binding(kind: Kind) -> Option<Binding> {
    match kind {
        Kind::Tpm => None,
        Kind::EncryptedTpm => Some(Binding::Tpm),
        Kind::EncryptedHost => Some(Binding::Host),
    }
}

/// Chooses the storage kind for `parsed` and protects the key in it. `name` is the credential name.
///
/// # Errors
/// [`ImportError::Tpm`] if the TPM cannot be judged or its import fails, [`ImportError::Protect`] if the credential
/// service fails, [`ImportError::BindingMismatch`] if the credential is bound to something else than the kind chosen.
pub fn protect(
    tpm: &dyn TpmAccess,
    creds: &dyn Credentials,
    name: &str,
    parsed: ParsedP12,
) -> Result<Protection, ImportError> {
    let ParsedP12 {
        kind: key_type,
        key,
        certificate,
    } = parsed;
    let classification = assess(tpm, tpm_key_type(key_type));
    let kind = choose(&classification).map_err(|e| ImportError::Tpm(TpmImportError::Tpm(e)))?;
    let protected = match required_binding(kind) {
        None => {
            let imported = import_pkcs8(tpm, key.expose_secret())?;
            Protected::from_imported(&imported).map_err(StoreError::Record)?
        }
        Some(binding) => {
            let sealed = seal(creds, name, &key).map_err(ImportError::Protect)?;
            if sealed.binding() != binding {
                return Err(ImportError::BindingMismatch);
            }
            Protected::from_sealed(&sealed)
        }
    };
    // The plaintext key is not needed any more.
    drop(key);
    Ok(Protection {
        kind,
        protected,
        certificate,
        key_type,
    })
}
