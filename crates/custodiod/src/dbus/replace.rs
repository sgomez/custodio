//! The `ReplaceCertificate` call: the certificate stored for one of the caller's keys is replaced
//! by another for the same public key, after polkit approves.

use secrecy::ExposeSecret;
use x509_cert::Certificate;
use x509_cert::der::Decode;

use super::{Custodio, check_id};
use crate::audit::{KeyId, OperationEntry, ReplaceOutcome};
use crate::credentials::CallerCredentials;
use crate::error::ServiceError;
use crate::import::{KeyKind, cert_id, cert_public_key, classify, public_key_of};
use crate::polkit::{AuthError, Authorizer, REPLACE_ACTION_ID};
use crate::store::StoreError;

pub use custodio_client::MAX_CERT_LEN;

/// Whether `der` is exactly one DER X.509 certificate within [`MAX_CERT_LEN`] bytes. Nothing else is
/// looked at: no chain, revocation, date, key usage or subject.
pub(super) fn is_certificate(der: &[u8]) -> bool {
    // `from_der` refuses trailing bytes.
    within_bound(der.len()) && Certificate::from_der(der).is_ok()
}

/// The size check alone: `MAX_CERT_LEN` bytes pass, one more does not.
pub(super) const fn within_bound(len: usize) -> bool {
    len <= MAX_CERT_LEN
}

/// Whether `cert_der` carries the public key of the PKCS#8 private key `key_der`. `None` if the
/// private key is not one of the supported types.
pub(super) fn certificate_matches_key(key_der: &[u8], cert_der: &[u8]) -> Option<bool> {
    let kind: KeyKind = classify(key_der).ok()?;
    let wanted = public_key_of(kind, key_der)?;
    Some(cert_public_key(kind, cert_der).is_some_and(|pk| pk == wanted))
}

/// What the part after the approval gives: the outcome to record, the reply, and the old certificate
/// if the new one was stored.
type Stored = (
    ReplaceOutcome,
    Result<(), ServiceError>,
    Option<secrecy::SecretSlice<u8>>,
);

impl<A: Authorizer + Sync, C: CallerCredentials + Sync> Custodio<A, C> {
    /// `ReplaceCertificate` after the bus handed over the sender: the id and the certificate against
    /// their bounds, the caller, the caller's own key (a missing id and another uid's id both fail
    /// `NoSuchKey`, before polkit), polkit once under the replace action, the comparison of the
    /// certificate's public key with the key's, and the atomic store. It runs under the lock
    /// `DeleteKey` takes for the same owner and id, so the two never interleave. Nothing is cached.
    ///
    /// Once the arguments are valid, every call that gets past the credentials and the own-key
    /// lookup leaves exactly one `replace_certificate` entry, submitted after the store and before
    /// the reply, still under the lock. If the entry cannot be submitted the certificate read before
    /// the store is put back (atomically, like the replace) and the call fails, also when that
    /// restore fails. `InvalidArgs` and `NoSuchKey` leave no entry.
    ///
    /// # Errors
    /// A D-Bus error for bad arguments, an unknown caller, a missing key, a refusal of polkit, a
    /// certificate for another key or a store failure; [`ServiceError::AuditUnavailable`] if the
    /// entry could not be submitted.
    pub async fn replace_call(
        &self,
        sender: Option<&str>,
        id: &str,
        certificate: &[u8],
    ) -> Result<(), ServiceError> {
        check_id(id).map_err(|e| ServiceError::from(&e))?;
        if !is_certificate(certificate) {
            return Err(ServiceError::InvalidArgs);
        }
        let key_id = KeyId::new(id).map_err(|_| ServiceError::AuditUnavailable)?;
        let known = self.known_caller(sender).await;
        let Some((sender, caller, pidfd)) = known else {
            let entry = OperationEntry::replace_certificate(
                ReplaceOutcome::AuthorizationUnavailable,
                None,
                key_id,
            );
            self.submit(entry).await?;
            return Err(ServiceError::AuthorizationUnavailable);
        };
        let owner = caller.uid;
        if self.deletes.is_unusable(owner, id) {
            return Err(ServiceError::NoSuchKey);
        }
        let _one_at_a_time = self.deletes.lock_key(owner, id).await;
        if self.deletes.is_unusable(owner, id) {
            return Err(ServiceError::NoSuchKey);
        }
        self.key_of(owner, id)?;
        let app_id = self.app_id_of(pidfd.as_ref(), owner).await;
        let (outcome, reply, old) = match self.authorizer.authorize(sender, REPLACE_ACTION_ID).await
        {
            Ok(()) => self.store_certificate(owner, id, certificate),
            Err(AuthError::Denied) => (
                ReplaceOutcome::Denied,
                Err(ServiceError::PolkitDenied),
                None,
            ),
            Err(AuthError::BadSender | AuthError::Unavailable(_)) => (
                ReplaceOutcome::AuthorizationUnavailable,
                Err(ServiceError::AuthorizationUnavailable),
                None,
            ),
        };
        let entry =
            OperationEntry::replace_certificate(outcome, Some(caller), key_id).with_app_id(app_id);
        if let Err(e) = self.submit(entry).await {
            if let Some(old) = old {
                // Nothing more can be done if this fails: the reply is the same error either way.
                let _ = self
                    .store
                    .replace_existing(owner, &cert_id(id), old.expose_secret());
            }
            return Err(e);
        }
        reply
    }

    /// The part after the approval: the key read again (it is not held across the wait for
    /// polkit), the comparison, and the atomic store. Gives the outcome to record, the reply and,
    /// if the new certificate was stored, the old one for the restore.
    fn store_certificate(&self, owner: u32, id: &str, certificate: &[u8]) -> Stored {
        let failed = |e| (ReplaceOutcome::StorageFailure, Err(e), None);
        let key = match self.key_of(owner, id) {
            Ok(key) => key,
            Err(e) => return failed(e),
        };
        match certificate_matches_key(key.expose_secret(), certificate) {
            None => return failed(ServiceError::Internal),
            Some(false) => {
                return (
                    ReplaceOutcome::CertificateMismatch,
                    Err(ServiceError::CertificateMismatch),
                    None,
                );
            }
            Some(true) => {}
        }
        let name = cert_id(id);
        let Ok(old) = self.store.get(owner, &name) else {
            return failed(ServiceError::Internal);
        };
        match self.store.replace_existing(owner, &name, certificate) {
            Ok(()) => (ReplaceOutcome::Replaced, Ok(()), Some(old)),
            Err(_) => failed(ServiceError::Internal),
        }
    }

    /// The caller's key `id`: `NoSuchKey` if there is none, `Internal` if it cannot be read.
    fn key_of(&self, owner: u32, id: &str) -> Result<secrecy::SecretSlice<u8>, ServiceError> {
        self.store.get(owner, id).map_err(|e| match e {
            StoreError::NotFound => ServiceError::NoSuchKey,
            _ => ServiceError::Internal,
        })
    }
}

#[cfg(test)]
mod tests;
