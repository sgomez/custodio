//! The `DeleteKey` call: a key record (key and certificate in one file) leaves the caller's area, after
//! polkit approves.

use std::sync::Arc;

use super::{Custodio, parse_delete_request};
use crate::audit::{DeleteOutcome, KeyId, OperationEntry};
use crate::credentials::CallerCredentials;
use crate::error::ServiceError;
use crate::offload::run_on_thread;
use crate::polkit::{AuthError, Authorizer, DELETE_ACTION_ID};
use crate::store::StoreError;

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
        self.find_for_delete(owner, id)?;
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
        self.remove_record(owner, id)?;
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

    /// The caller's record must be there (as a file the store rules accept; it is not parsed, so a
    /// record that no longer parses can still be deleted).
    fn find_for_delete(&self, owner: u32, id: &str) -> Result<(), ServiceError> {
        match self.store.contains(owner, id) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ServiceError::NoSuchKey),
            Err(_) => Err(ServiceError::Internal),
        }
    }

    /// One file holds the key and its certificate, so one removal is the whole delete. Of two deletes
    /// of one id only the one that removes the file succeeds; the other is `NoSuchKey`.
    fn remove_record(&self, owner: u32, id: &str) -> Result<(), ServiceError> {
        let internal = |_: StoreError| ServiceError::Internal;
        if self.store.remove_existing(owner, id).map_err(internal)? {
            Ok(())
        } else {
            Err(ServiceError::NoSuchKey)
        }
    }
}
