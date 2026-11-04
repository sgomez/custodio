//! Importing a private key into the TPM under the approved parent, and checking a blob's parent before use (F113).
//!
//! Both calls open the TPM, refuse an owner hierarchy that cannot be used (as the capability query does), and leave
//! nothing loaded in the TPM when they return.

use std::fmt;

use super::blob::{Imported, same_name};
use super::classify::{Fault, TpmError};
use super::key::{ImportKey, KeyRefusal};
use super::{OpenError, Session, TpmAccess};

/// Why an import or a parent check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    /// The key is not one the TPM import takes. No TPM call was made.
    Refused(KeyRefusal),
    /// No TPM is present.
    NoTpm,
    /// The TPM or the way to it failed.
    Tpm(TpmError),
    /// The blob was wrapped to another parent than the current one (the TPM was cleared, or it is another TPM).
    ParentMismatch,
    /// A value did not fit its TPM structure; a bug, not a TPM answer.
    Internal,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(why) => write!(f, "key refused: {why}"),
            Self::NoTpm => f.write_str("no TPM"),
            Self::Tpm(e) => write!(f, "TPM error: {e}"),
            Self::ParentMismatch => f.write_str("the key was wrapped to another TPM parent"),
            Self::Internal => f.write_str("internal error preparing the TPM key"),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<Fault> for ImportError {
    fn from(fault: Fault) -> Self {
        Self::Tpm(fault.into())
    }
}

impl From<OpenError> for ImportError {
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::NoDevice => Self::NoTpm,
            OpenError::Failed(e) => Self::Tpm(e),
        }
    }
}

/// Opens the TPM and refuses an owner hierarchy the service cannot use.
fn open_ready(access: &dyn TpmAccess) -> Result<Box<dyn Session>, ImportError> {
    let mut session = access.open()?;
    let owner = session.owner()?;
    if owner.auth_set {
        return Err(ImportError::Tpm(TpmError::OwnerAuthSet));
    }
    if !owner.enabled {
        return Err(ImportError::Tpm(TpmError::OwnerDisabled));
    }
    Ok(session)
}

/// Imports a PKCS#8 private key (RSA 2048 or P-256). Any other key is refused before the TPM is opened.
///
/// # Errors
/// [`ImportError`]; none of its texts holds key bytes.
pub fn import_pkcs8(access: &dyn TpmAccess, pkcs8_der: &[u8]) -> Result<Imported, ImportError> {
    let key = ImportKey::from_pkcs8(pkcs8_der).map_err(ImportError::Refused)?;
    import(access, &key)
}

/// Imports `key` under the current parent.
///
/// # Errors
/// [`ImportError`].
pub fn import(access: &dyn TpmAccess, key: &ImportKey) -> Result<Imported, ImportError> {
    open_ready(access)?.import_key(key)
}

/// Checks that `recorded` is the name of the parent the TPM gives now. Nothing is loaded.
///
/// # Errors
/// [`ImportError::ParentMismatch`] when the names differ; a TPM error otherwise.
pub fn check_parent(access: &dyn TpmAccess, recorded: &[u8]) -> Result<(), ImportError> {
    let current = open_ready(access)?.parent_name()?;
    if same_name(recorded, &current) {
        Ok(())
    } else {
        Err(ImportError::ParentMismatch)
    }
}
