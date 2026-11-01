//! The `DeleteKey` call: a key and its certificate leave the caller's area, after polkit approves.

use super::{Custodio, check_id};
use crate::credentials::CallerCredentials;
use crate::error::ServiceError;
use crate::import::cert_id;
use crate::polkit::{AuthError, Authorizer, DELETE_ACTION_ID};
use crate::store::StoreError;

/// What the lookup found among the caller's files for an id.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Found {
    /// The key file (and normally its certificate).
    Key,
    /// Only the certificate: what a delete that stopped half-way leaves. Deleting again clears it.
    OrphanCertificate,
}

impl<A: Authorizer + Sync, C: CallerCredentials + Sync> Custodio<A, C> {
    /// `DeleteKey` after the bus handed over the sender: the id against its bound, the caller, the
    /// caller's own key (a missing id and another uid's id both fail `NoSuchKey`, before polkit),
    /// polkit once under the delete action, then the key file and the certificate are removed.
    /// Nothing is cached and a failed call leaves the key as it was, except for a certificate that
    /// cannot be removed after the key went (`Internal`).
    ///
    /// # Errors
    /// A D-Bus error for a bad id, an unknown caller, a missing key, a refusal of polkit or a
    /// store failure.
    pub async fn delete_call(&self, sender: Option<&str>, id: &str) -> Result<(), ServiceError> {
        check_id(id).map_err(|e| ServiceError::from(&e))?;
        let owner = self.owner(sender).await?;
        let found = self.find_for_delete(owner, id)?;
        // `owner` succeeded, so there is a sender.
        let sender = sender.ok_or(ServiceError::AuthorizationUnavailable)?;
        match self.authorizer.authorize(sender, DELETE_ACTION_ID).await {
            Ok(()) => {}
            Err(AuthError::Denied) => return Err(ServiceError::PolkitDenied),
            Err(AuthError::BadSender | AuthError::Unavailable(_)) => {
                return Err(ServiceError::AuthorizationUnavailable);
            }
        }
        self.remove_key_and_certificate(owner, id, found)
    }

    fn find_for_delete(&self, owner: u32, id: &str) -> Result<Found, ServiceError> {
        match self.store.get(owner, id) {
            Ok(_) => return Ok(Found::Key),
            Err(StoreError::NotFound) => {}
            Err(_) => return Err(ServiceError::Internal),
        }
        match self.store.get(owner, &cert_id(id)) {
            Ok(_) => Ok(Found::OrphanCertificate),
            Err(StoreError::NotFound) => Err(ServiceError::NoSuchKey),
            Err(_) => Err(ServiceError::Internal),
        }
    }

    /// The key first, so a failure never leaves a key without its certificate. Of two deletes of
    /// one id only the one that removes the key (or, for an orphan certificate, the certificate)
    /// succeeds; the other is `NoSuchKey`.
    fn remove_key_and_certificate(
        &self,
        owner: u32,
        id: &str,
        found: Found,
    ) -> Result<(), ServiceError> {
        let internal = |_: StoreError| ServiceError::Internal;
        let key_removed = self.store.remove_existing(owner, id).map_err(internal)?;
        if found == Found::Key && !key_removed {
            return Err(ServiceError::NoSuchKey);
        }
        let cert_removed = self
            .store
            .remove_existing(owner, &cert_id(id))
            .map_err(internal)?;
        if found == Found::OrphanCertificate && !cert_removed {
            return Err(ServiceError::NoSuchKey);
        }
        Ok(())
    }
}
