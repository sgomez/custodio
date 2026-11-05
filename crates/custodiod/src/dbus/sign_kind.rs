//! The signature of one stored key, by the kind the record holds (F118).
//!
//! A TPM record signs inside the TPM through the service's [`TpmAccess`]; the private key is not in the service. An
//! encrypted record is decrypted through the credential service for this one signature and dropped. Nothing else
//! chooses the path: a failure of one is never retried through the other, and nothing is deleted, marked or migrated.
//!
//! The failures are told apart in two classes, so a person can tell "this key can no longer be used" from "try again
//! later": [`ServiceError::KeyLost`] and [`ServiceError::TemporarilyUnavailable`]. The mappings are exhaustive
//! matches: a new variant of either source error does not build until it has a class.

use crate::creds::CredsError;
use crate::dbus::Custodio;
use crate::error::ServiceError;
use crate::import::credential_name;
use crate::sign::{Mechanism, sign};
use crate::store::Record;
use crate::tpm::blob::Imported;
use crate::tpm::sign::{self as tpm_sign, SignRequest, TpmSignError};

impl From<&TpmSignError> for ServiceError {
    fn from(e: &TpmSignError) -> Self {
        match e {
            TpmSignError::Refused(why) => Self::from(why),
            // The blob will not load: it was wrapped to another parent, or it is damaged.
            TpmSignError::ParentMismatch | TpmSignError::LoadFailed(_) => Self::KeyLost,
            // The record is intact and signs again once the TPM is back or serves the mechanism.
            TpmSignError::NoTpm
            | TpmSignError::Tpm(_)
            | TpmSignError::Lacks(_)
            | TpmSignError::BadResult => Self::TemporarilyUnavailable,
            TpmSignError::Internal => Self::Internal,
        }
    }
}

impl From<&CredsError> for ServiceError {
    fn from(e: &CredsError) -> Self {
        match e {
            CredsError::CannotDecrypt => Self::KeyLost,
            CredsError::Unavailable => Self::TemporarilyUnavailable,
            CredsError::Refused(_) | CredsError::BadRequest => Self::Internal,
        }
    }
}

impl<A, C> Custodio<A, C> {
    /// Signs with the key of `record`, by its kind.
    pub(super) fn sign_record(
        &self,
        record: &Record,
        mechanism: Mechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, ServiceError> {
        if let Some((blob, parent_name)) = record.protected().blob() {
            let imported = Imported {
                blob: blob.clone(),
                parent_name: parent_name.to_vec(),
            };
            let request = SignRequest {
                imported: &imported,
                mechanism,
                data,
            };
            return tpm_sign::sign(self.tpm.as_ref(), &request).map_err(|e| ServiceError::from(&e));
        }
        let (Some(creds), Some(credential)) =
            (self.key_creds.as_deref(), record.protected().credential())
        else {
            return Err(ServiceError::Internal);
        };
        let name = credential_name(record.owner(), record.id());
        let key = creds
            .decrypt(&name, credential)
            .map_err(|e| ServiceError::from(&e))?;
        sign(&key, mechanism, data).map_err(|e| ServiceError::from(&e))
    }
}

#[cfg(test)]
mod tests;
