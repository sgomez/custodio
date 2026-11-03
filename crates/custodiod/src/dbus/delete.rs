//! The `DeleteKey` call: a key and its certificate leave the caller's area, after polkit approves.

use std::sync::Arc;

use super::{Custodio, parse_delete_request};
use crate::audit::{DeleteOutcome, KeyId, OperationEntry};
use crate::credentials::CallerCredentials;
use crate::error::ServiceError;
use crate::import::cert_id;
use crate::offload::run_on_thread;
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
    /// polkit once under the delete action. From then on exactly one entry is recorded: after an
    /// approval the key is first made unusable, then the entry is submitted, and only then are the
    /// key file and the certificate removed. If the entry cannot be submitted the key is restored
    /// and the call fails. Deletes of one owner and id run one at a time, from the lookup to the end.
    /// Nothing is cached. If the removal fails after the entry went out (`Internal`), the key stays
    /// unusable until the service restarts.
    ///
    /// # Errors
    /// A D-Bus error for a bad id, an unknown caller, a missing key, a refusal of polkit or a
    /// store failure; [`ServiceError::AuditUnavailable`] if the entry could not be submitted.
    pub async fn delete_call(&self, sender: Option<&str>, id: &str) -> Result<(), ServiceError> {
        parse_delete_request(id).map_err(|e| ServiceError::from(&e))?;
        let key_id = KeyId::new(id).map_err(|_| ServiceError::AuditUnavailable)?;
        let known = self.known_caller(sender).await;
        let Some((sender, caller, pidfd)) = known else {
            let entry =
                OperationEntry::delete(DeleteOutcome::AuthorizationUnavailable, None, key_id);
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
        let found = self.find_for_delete(owner, id)?;
        let app_id = self.app_id_of(pidfd.as_ref(), owner).await;
        let approved = match self.authorizer.authorize(sender, DELETE_ACTION_ID).await {
            Ok(()) => true,
            Err(AuthError::Denied) => false,
            Err(AuthError::BadSender | AuthError::Unavailable(_)) => {
                let entry = OperationEntry::delete(
                    DeleteOutcome::AuthorizationUnavailable,
                    Some(caller),
                    key_id,
                )
                .with_app_id(app_id);
                self.submit(entry).await?;
                return Err(ServiceError::AuthorizationUnavailable);
            }
        };
        if !approved {
            let entry = OperationEntry::delete(DeleteOutcome::Denied, Some(caller), key_id)
                .with_app_id(app_id);
            self.submit(entry).await?;
            return Err(ServiceError::PolkitDenied);
        }
        self.deletes.mark_unusable(owner, id);
        let entry = OperationEntry::delete(DeleteOutcome::Deleted, Some(caller), key_id)
            .with_app_id(app_id);
        if let Err(e) = self.submit(entry).await {
            self.deletes.restore(owner, id);
            return Err(e);
        }
        self.remove_key_and_certificate(owner, id, found)?;
        // The files are gone, so the id is free: a later import must not find it marked.
        self.deletes.restore(owner, id);
        Ok(())
    }

    /// Submits an entry on its own thread; the reply waits for it.
    pub(super) async fn submit(&self, entry: OperationEntry) -> Result<(), ServiceError> {
        let sink = Arc::clone(&self.sink);
        match run_on_thread(move || sink.record_operation(&entry)).await {
            Some(Ok(())) => Ok(()),
            _ => Err(ServiceError::AuditUnavailable),
        }
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
