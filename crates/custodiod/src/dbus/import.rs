//! The `ImportP12` call: one journal entry per import that reaches polkit, and a rollback when it
//! cannot be recorded.

use std::sync::Arc;

use secrecy::SecretString;

use super::{Custodio, ImportRequest, kind_name, parse_import_request};
use crate::app_id::AppIdOutcome;
use crate::audit::{AuditKeyType, Caller, ImportCause, ImportOutcome, KeyId, OperationEntry};
use crate::credentials::CallerCredentials;
use crate::creds::CredsError;
use crate::error::ServiceError;
use crate::import::{ImportError, KeyKind, id_taken, rollback_import, store_parsed};
use crate::offload::run_on_thread;
use crate::polkit::{AuthError, Authorizer, IMPORT_ACTION_ID};
use crate::store::Kind as StorageKind;
use crate::tpm::classify::TpmError;
use crate::tpm::import::ImportError as TpmImportError;

pub(super) const fn audit_key_type(kind: KeyKind) -> AuditKeyType {
    match kind {
        KeyKind::Rsa2048 => AuditKeyType::Rsa2048,
        KeyKind::EcdsaP256 => AuditKeyType::EcdsaP256,
    }
}

/// The outcome an import that failed after approval is recorded as.
///
/// Every variant is named, so a new one does not compile until it is mapped. A wrong password is
/// the nearest outcome for every file that cannot be read as one key with a certificate; a
/// certificate that does not match the key is an unsupported key. `TooLarge` is refused by the
/// argument check before polkit, so it cannot happen here; it is a storage failure because the
/// store, not the caller, would have produced it.
pub(super) const fn import_outcome(e: &ImportError) -> ImportOutcome {
    match e {
        ImportError::Parse(_)
        | ImportError::NoPrivateKey
        | ImportError::MultipleKeys
        | ImportError::NoCertificate => ImportOutcome::WrongPassword,
        ImportError::UnsupportedKey(_) | ImportError::CertificateMismatch => {
            ImportOutcome::UnsupportedKey
        }
        ImportError::Protect(_)
        | ImportError::Tpm(_)
        | ImportError::BindingMismatch
        | ImportError::Store(_)
        | ImportError::TooLarge => ImportOutcome::StorageFailure,
    }
}

/// The cause an import that failed after approval is recorded with.
///
/// Every variant is named, so a new one does not compile until it is mapped. Only the failures that end in the
/// `storage_failure` outcome have a cause; the others (a file that cannot be read, an unsupported key) are told apart
/// by their outcome already. The cause comes from the typed error alone: the text of an error, a response code and
/// anything that came from the tool or the file never reach it.
pub(super) const fn import_cause(e: &ImportError) -> Option<ImportCause> {
    match e {
        ImportError::Parse(_)
        | ImportError::NoPrivateKey
        | ImportError::MultipleKeys
        | ImportError::NoCertificate
        | ImportError::CertificateMismatch
        | ImportError::UnsupportedKey(_) => None,
        ImportError::Tpm(t) => Some(tpm_import_cause(*t)),
        ImportError::Protect(c) => Some(match c {
            CredsError::Unavailable => ImportCause::CredentialsUnavailable,
            CredsError::CannotDecrypt | CredsError::Refused(_) | CredsError::BadRequest => {
                ImportCause::CredentialsRefused
            }
        }),
        ImportError::BindingMismatch => Some(ImportCause::BindingMismatch),
        ImportError::Store(_) => Some(ImportCause::Store),
        ImportError::TooLarge => Some(ImportCause::Internal),
    }
}

const fn tpm_import_cause(e: TpmImportError) -> ImportCause {
    match e {
        TpmImportError::Refused(_) => ImportCause::TpmKey,
        TpmImportError::NoTpm => ImportCause::TpmDevice,
        TpmImportError::Tpm(t) => match t {
            TpmError::ResourceManagerMissing | TpmError::OpenFailed | TpmError::TestTctiRefused => {
                ImportCause::TpmDevice
            }
            TpmError::OwnerAuthSet | TpmError::OwnerDisabled => ImportCause::TpmOwner,
            TpmError::Response(_) | TpmError::Transport => ImportCause::TpmError,
        },
        TpmImportError::ParentMismatch => ImportCause::TpmError,
        TpmImportError::Internal => ImportCause::Internal,
    }
}

/// What an `ImportP12` call records: the outcome, the key type if decoding got that far, the cause of a storage
/// failure, and the reply.
struct ImportAttempt {
    outcome: ImportOutcome,
    key_type: Option<AuditKeyType>,
    cause: Option<ImportCause>,
    result: Result<(KeyKind, StorageKind), ServiceError>,
}

impl ImportAttempt {
    const fn plain(
        outcome: ImportOutcome,
        key_type: Option<AuditKeyType>,
        result: Result<(KeyKind, StorageKind), ServiceError>,
    ) -> Self {
        Self {
            outcome,
            key_type,
            cause: None,
            result,
        }
    }

    /// The entry: the kind of a stored key, or the cause of a failure; never both.
    fn entry(&self, caller: Caller, key_id: KeyId, app_id: AppIdOutcome) -> OperationEntry {
        let entry = OperationEntry::import(self.outcome, Some(caller), key_id, self.key_type)
            .with_app_id(app_id);
        match (&self.result, self.cause) {
            (Ok((_, kind)), _) => entry.with_storage_kind(*kind),
            (Err(_), Some(cause)) => entry.with_cause(cause),
            (Err(_), None) => entry,
        }
    }
}

/// The reply of `ImportP12`: the key type and the storage kind, as wire strings.
pub type ImportReply = (String, String);

impl<A: Authorizer + Sync, C: CallerCredentials + Sync> Custodio<A, C> {
    /// `ImportP12` after the bus handed over the sender: arguments, credentials, whether the
    /// caller already has the id, polkit (once, under the import action), and only then the
    /// decoding of the `.p12` and the store. Once the arguments are valid, every call that gets
    /// past the credentials and the own-id check leaves exactly one entry, recorded before the reply.
    /// If it cannot be recorded the imported key is removed again and the call fails.
    ///
    /// # Errors
    /// A D-Bus error for bad arguments, an unknown caller, a taken id, a refusal of polkit or a
    /// failed import; [`ServiceError::AuditUnavailable`] if the entry could not be recorded.
    pub async fn import_call(
        &self,
        sender: Option<&str>,
        id: &str,
        p12: &[u8],
        password: &str,
    ) -> Result<ImportReply, ServiceError> {
        let ImportRequest { id, password } =
            parse_import_request(id, p12, password).map_err(|e| ServiceError::from(&e))?;
        let key_id = KeyId::new(&id).map_err(|_| ServiceError::AuditUnavailable)?;
        let known = self.known_caller(sender).await;
        let Some((sender, caller, pidfd)) = known else {
            let entry =
                OperationEntry::import(ImportOutcome::AuthorizationUnavailable, None, key_id, None);
            let result = Err(ServiceError::AuthorizationUnavailable);
            return self.finish_import(entry, 0, &id, result).await;
        };
        let owner = caller.uid;
        if id_taken(&self.store, owner, &id).map_err(|e| ServiceError::from(&e))? {
            return Err(ServiceError::KeyIdTaken);
        }
        let app_id = self.app_id_of(pidfd.as_ref(), owner).await;
        let attempt = self
            .authorize_and_import(sender, owner, &id, password, p12)
            .await;
        let entry = attempt.entry(caller, key_id, app_id);
        self.finish_import(entry, owner, &id, attempt.result).await
    }

    /// Records the entry of an import, then returns its reply. If the entry cannot be recorded, a
    /// stored key and its certificate are removed again and the reply is `AuditUnavailable`, also
    /// when that removal fails: a key is never reported as imported without its entry.
    async fn finish_import(
        &self,
        entry: OperationEntry,
        owner: u32,
        id: &str,
        result: Result<(KeyKind, StorageKind), ServiceError>,
    ) -> Result<ImportReply, ServiceError> {
        let sink = Arc::clone(&self.sink);
        if let Some(Ok(())) = run_on_thread(move || sink.record_operation(&entry)).await {
            return result
                .map(|(key_type, kind)| (kind_name(key_type).to_owned(), kind.wire().to_owned()));
        }
        if result.is_ok() {
            // Nothing more can be done if this fails: the reply is the same error either way.
            let _ = rollback_import(&self.store, owner, id);
        }
        Err(ServiceError::AuditUnavailable)
    }

    /// Polkit, the decoder and the store of an import, with the outcome to record.
    ///
    /// The password is taken by value and dropped (zeroized) as soon as the decoder has used it,
    /// before the storage kind is chosen. The `.p12` bytes are borrowed from the bus message,
    /// which the service cannot free early; the decoded key is consumed by `store_parsed`.
    async fn authorize_and_import(
        &self,
        sender: &str,
        owner: u32,
        id: &str,
        password: SecretString,
        p12: &[u8],
    ) -> ImportAttempt {
        match self.authorizer.authorize(sender, IMPORT_ACTION_ID).await {
            Ok(()) => {}
            Err(e) => {
                let outcome = match e {
                    AuthError::Denied => ImportOutcome::Denied,
                    AuthError::BadSender | AuthError::Unavailable(_) => {
                        ImportOutcome::AuthorizationUnavailable
                    }
                };
                return ImportAttempt::plain(outcome, None, Err(ServiceError::from(&e)));
            }
        }
        let decoded = self.decoder.decode(p12, &password);
        drop(password);
        let parsed = match decoded {
            Ok(parsed) => parsed,
            Err(e) => {
                let result = Err(ServiceError::from(&e));
                return ImportAttempt::plain(import_outcome(&e), None, result);
            }
        };
        let key_type = Some(audit_key_type(parsed.kind));
        let Some(creds) = self.key_creds.as_deref() else {
            return ImportAttempt {
                outcome: ImportOutcome::StorageFailure,
                key_type,
                cause: Some(ImportCause::Internal),
                result: Err(ServiceError::Internal),
            };
        };
        match store_parsed(&self.store, creds, &*self.tpm, owner, id, parsed) {
            Ok(stored) => ImportAttempt::plain(ImportOutcome::Stored, key_type, Ok(stored)),
            Err(e) => ImportAttempt {
                outcome: import_outcome(&e),
                key_type,
                cause: import_cause(&e),
                result: Err(ServiceError::from(&e)),
            },
        }
    }
}
