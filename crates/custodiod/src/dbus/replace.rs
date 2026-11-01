//! The `ReplaceCertificate` call: the certificate stored for one of the caller's keys is replaced
//! by another for the same public key, after polkit approves.

use secrecy::ExposeSecret;
use x509_cert::Certificate;
use x509_cert::der::Decode;

use super::{Custodio, check_id};
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

impl<A: Authorizer + Sync, C: CallerCredentials + Sync> Custodio<A, C> {
    /// `ReplaceCertificate` after the bus handed over the sender: the id and the certificate against
    /// their bounds, the caller, the caller's own key (a missing id and another uid's id both fail
    /// `NoSuchKey`, before polkit), polkit once under the replace action, the comparison of the
    /// certificate's public key with the key's, and the atomic store. It runs under the lock
    /// `DeleteKey` takes for the same owner and id, so the two never interleave. Nothing is cached,
    /// and no journal entry is written.
    ///
    /// # Errors
    /// A D-Bus error for bad arguments, an unknown caller, a missing key, a refusal of polkit, a
    /// certificate for another key or a store failure.
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
        let sender = sender.ok_or(ServiceError::AuthorizationUnavailable)?;
        let owner = self
            .credentials
            .credentials(sender)
            .await
            .map_err(|_| ServiceError::AuthorizationUnavailable)?
            .uid;
        if self.deletes.is_unusable(owner, id) {
            return Err(ServiceError::NoSuchKey);
        }
        let _one_at_a_time = self.deletes.lock_key(owner, id).await;
        if self.deletes.is_unusable(owner, id) {
            return Err(ServiceError::NoSuchKey);
        }
        self.key_of(owner, id)?;
        match self.authorizer.authorize(sender, REPLACE_ACTION_ID).await {
            Ok(()) => {}
            Err(AuthError::Denied) => return Err(ServiceError::PolkitDenied),
            Err(AuthError::BadSender | AuthError::Unavailable(_)) => {
                return Err(ServiceError::AuthorizationUnavailable);
            }
        }
        // Read again: the key is not held across the wait for polkit.
        let key = self.key_of(owner, id)?;
        match certificate_matches_key(key.expose_secret(), certificate) {
            None => return Err(ServiceError::Internal),
            Some(false) => return Err(ServiceError::CertificateMismatch),
            Some(true) => {}
        }
        self.store
            .replace_existing(owner, &cert_id(id), certificate)
            .map_err(|_| ServiceError::Internal)
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
