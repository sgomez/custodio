//! `Sign` on the snap socket. The key is the peer's own (its kernel uid), polkit is asked once per call about the
//! peer's process (`unix-process` on its pidfd and uid, `AllowUserInteraction`) and the answer is never kept. The
//! parse, the signing by storage kind and the audit entry are the bus service's own code
//! ([`crate::dbus`]): only who the caller is and how polkit is asked differ.

use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;

use crate::app_id::AppIdOutcome;
use crate::audit::{AuditSink, Caller, Outcome, PeerLabel};
use crate::creds::Credentials;
use crate::dbus::{audit_parts, parse_sign_request, record_sign, sign_entry, sign_with_record};
use crate::error::ServiceError;
use crate::polkit::{ACTION_ID, AuthError, ProcessAuthorizer, process_has_exited};
use crate::store::{KeyStore, StoreError};
use crate::tpm::TpmAccess;

/// What signing needs besides the store: polkit, the journal, and the two ways a key is read.
#[derive(Clone)]
pub struct Signing {
    pub authorizer: Arc<dyn ProcessAuthorizer>,
    pub sink: Arc<dyn AuditSink>,
    pub key_creds: Option<Arc<dyn Credentials>>,
    pub tpm: Arc<dyn TpmAccess>,
}

/// One admitted connection: everything the kernel said about its peer, and nothing the peer said.
pub(super) struct Session {
    pub store: Arc<KeyStore>,
    pub signing: Option<Signing>,
    pub uid: u32,
    pub pid: u32,
    pub label: PeerLabel,
    pub pidfd: OwnedFd,
}

impl Session {
    /// The call: validate, find the peer's key, ask polkit, sign, record one entry, then reply.
    ///
    /// # Errors
    /// The D-Bus error of the bus method for the same case; `AuthorizationUnavailable` when the service has no
    /// signing set up.
    pub(super) async fn sign(
        &self,
        id: &str,
        mechanism: u32,
        hash: u32,
        salt_len: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, ServiceError> {
        let request = parse_sign_request(id, mechanism, hash, salt_len, data)
            .map_err(|e| ServiceError::from(&e))?;
        let (key_id, audit_mechanism) = audit_parts(&request.id, &request.mechanism)?;
        let signing = self
            .signing
            .as_ref()
            .ok_or(ServiceError::AuthorizationUnavailable)?;
        // A missing key or another uid's key: no polkit call, no entry, as on the bus.
        let key = match self.store.get(self.uid, &request.id) {
            Err(StoreError::NotFound) => return Err(ServiceError::NoSuchKey),
            other => other.map_err(|e| ServiceError::from(&e)),
        };
        let kind = key.as_ref().ok().map(crate::store::Record::kind);
        let (outcome, result) = match self.authorize(signing).await {
            Ok(()) => {
                let signed = key.and_then(|record| {
                    sign_with_record(
                        signing.tpm.as_ref(),
                        signing.key_creds.as_deref(),
                        &record,
                        request.mechanism,
                        data,
                    )
                });
                let outcome = if signed.is_ok() {
                    Outcome::Signed
                } else {
                    Outcome::SigningFailed
                };
                (outcome, signed)
            }
            Err(AuthError::Denied) => (Outcome::Denied, Err(ServiceError::PolkitDenied)),
            Err(AuthError::BadSender | AuthError::Unavailable(_)) => (
                Outcome::AuthorizationUnavailable,
                Err(ServiceError::AuthorizationUnavailable),
            ),
        };
        let caller = Caller {
            uid: self.uid,
            pid: self.pid,
        };
        let entry = sign_entry(
            (outcome, Some(caller), kind),
            key_id,
            audit_mechanism,
            AppIdOutcome::Undetermined,
            &result,
        )
        .with_socket_peer(self.label.clone());
        record_sign(&signing.sink, entry, result).await
    }

    /// One polkit question about the peer's process. A peer that has exited is not asked about: its pidfd names
    /// nothing any more.
    async fn authorize(&self, signing: &Signing) -> Result<(), AuthError> {
        if process_has_exited(self.pidfd.as_fd()) {
            return Err(AuthError::Unavailable("the peer has exited".to_owned()));
        }
        signing
            .authorizer
            .authorize_process(self.pidfd.as_fd(), self.uid, ACTION_ID)
            .await
    }
}
