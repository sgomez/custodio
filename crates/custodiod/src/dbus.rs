//! The `com.rfirma.Custodio1` D-Bus service: list keys with their certificates, import a `.p12`, sign.
//!
//! Every `Sign` call for one of the caller's keys asks polkit and never caches the answer. Argument parsing lives in
//! plain functions ([`parse_sign_request`], [`parse_import_request`]) so it can be fuzzed.

use std::fmt;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretSlice, SecretString};
use zbus::interface;
use zbus::message::Header;

use crate::audit::{AuditMechanism, AuditSink, Caller, Entry, KeyId, Outcome};
use crate::credentials::CallerCredentials;
use crate::error::ServiceError;
use crate::import::{KeyKind, MAX_P12_LEN, P12Decoder, RealDecoder, cert_id, classify};
use crate::offload::run_on_thread;
use crate::polkit::{ACTION_ID, AuthError, Authorizer};
use crate::sign::{Mechanism, PssHash, sign};
use crate::store::{KeyStore, StoreError};

pub use custodio_client::{BUS_NAME, OBJECT_PATH};

/// `CKM_RSA_PKCS`.
pub const CKM_RSA_PKCS: u32 = 0x0001;
/// `CKM_RSA_PKCS_PSS`.
pub const CKM_RSA_PKCS_PSS: u32 = 0x000D;
/// `CKM_ECDSA`.
pub const CKM_ECDSA: u32 = 0x1041;
/// `CKM_SHA256`.
pub const CKM_SHA256: u32 = 0x0250;
/// `CKM_SHA384`.
pub const CKM_SHA384: u32 = 0x0260;
/// `CKM_SHA512`.
pub const CKM_SHA512: u32 = 0x0270;

const CERT_SUFFIX: &str = "-cert";
/// Keeps `<id>-cert` within the key store's id length limit.
const MAX_ID_LEN: usize = 64 - CERT_SUFFIX.len();
/// Largest data to sign: a `DigestInfo` or digest is far smaller.
const MAX_SIGN_DATA_LEN: usize = 1024;
/// Largest password accepted for a `.p12`.
const MAX_PASSWORD_LEN: usize = 1024;

/// Why a request was refused before any key was touched.
#[derive(Debug, PartialEq, Eq)]
pub enum RequestError {
    BadId,
    BadMechanism,
    BadHash,
    BadSaltLength,
    DataTooLarge,
    PasswordTooLarge,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadId => "invalid key id",
            Self::BadMechanism => "unsupported mechanism",
            Self::BadHash => "unsupported or unexpected hash for the mechanism",
            Self::BadSaltLength => "unexpected salt length for the mechanism",
            Self::DataTooLarge => "data too large",
            Self::PasswordTooLarge => "password too large",
        })
    }
}

impl std::error::Error for RequestError {}

/// A checked `Sign` request.
#[derive(Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub id: String,
    pub mechanism: Mechanism,
}

/// A checked `ImportP12` request.
pub struct ImportRequest {
    pub id: String,
    pub password: SecretString,
}

impl fmt::Debug for ImportRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportRequest")
            .field("id", &self.id)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// An id a client may name: valid for the store, and not one of the `-cert` entries.
fn check_id(id: &str) -> Result<(), RequestError> {
    let valid = !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && !id.ends_with(CERT_SUFFIX)
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if valid {
        Ok(())
    } else {
        Err(RequestError::BadId)
    }
}

/// Check the arguments of `Sign`.
///
/// `hash` and `salt_len` are only meaningful for `CKM_RSA_PKCS_PSS`; they must be 0 otherwise.
///
/// # Errors
/// See [`RequestError`].
pub fn parse_sign_request(
    id: &str,
    mechanism: u32,
    hash: u32,
    salt_len: u32,
    data: &[u8],
) -> Result<SignRequest, RequestError> {
    check_id(id)?;
    if data.len() > MAX_SIGN_DATA_LEN {
        return Err(RequestError::DataTooLarge);
    }
    let mechanism = match mechanism {
        CKM_RSA_PKCS | CKM_ECDSA if hash != 0 => return Err(RequestError::BadHash),
        CKM_RSA_PKCS | CKM_ECDSA if salt_len != 0 => return Err(RequestError::BadSaltLength),
        CKM_RSA_PKCS => Mechanism::RsaPkcs,
        CKM_ECDSA => Mechanism::Ecdsa,
        CKM_RSA_PKCS_PSS => {
            let hash = match hash {
                CKM_SHA256 => PssHash::Sha256,
                CKM_SHA384 => PssHash::Sha384,
                CKM_SHA512 => PssHash::Sha512,
                _ => return Err(RequestError::BadHash),
            };
            let salt_len = usize::try_from(salt_len).map_err(|_| RequestError::BadSaltLength)?;
            Mechanism::RsaPkcsPss { hash, salt_len }
        }
        _ => return Err(RequestError::BadMechanism),
    };
    Ok(SignRequest {
        id: id.to_owned(),
        mechanism,
    })
}

/// Check the arguments of `ImportP12`. The file itself is checked by `parse_p12`.
///
/// # Errors
/// See [`RequestError`].
pub fn parse_import_request(
    id: &str,
    data: &[u8],
    password: &str,
) -> Result<ImportRequest, RequestError> {
    check_id(id)?;
    if data.len() > MAX_P12_LEN {
        return Err(RequestError::DataTooLarge);
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(RequestError::PasswordTooLarge);
    }
    Ok(ImportRequest {
        id: id.to_owned(),
        password: SecretString::from(password.to_owned()),
    })
}

fn kind_name(kind: KeyKind) -> &'static str {
    match kind {
        KeyKind::Rsa2048 => "rsa2048",
        KeyKind::EcdsaP256 => "ecdsa-p256",
    }
}

/// The key id and mechanism for the audit entry of a checked request.
fn audit_parts(id: &str, mechanism: &Mechanism) -> Result<(KeyId, AuditMechanism), ServiceError> {
    let key_id = KeyId::new(id).map_err(|_| ServiceError::AuditUnavailable)?;
    Ok((key_id, AuditMechanism::from(mechanism)))
}

/// What a `Sign` call records: the outcome, the caller if known, and the reply.
type Attempt = (Outcome, Option<Caller>, Result<Vec<u8>, ServiceError>);

/// The object served at [`OBJECT_PATH`].
pub struct Custodio<A, C> {
    store: Arc<KeyStore>,
    authorizer: A,
    credentials: C,
    sink: Arc<dyn AuditSink>,
    decoder: Arc<dyn P12Decoder>,
    deletes: delete_state::DeleteState,
}

impl<A, C> Custodio<A, C> {
    #[must_use]
    pub fn new(
        store: Arc<KeyStore>,
        authorizer: A,
        credentials: C,
        sink: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            store,
            authorizer,
            credentials,
            sink,
            decoder: Arc::new(RealDecoder),
            deletes: delete_state::DeleteState::default(),
        }
    }

    /// Replaces the `.p12` decoder. Production uses the real parser; tests count the calls.
    #[must_use]
    pub fn with_decoder(mut self, decoder: Arc<dyn P12Decoder>) -> Self {
        self.decoder = decoder;
        self
    }
}

impl<A: Authorizer + Sync, C: CallerCredentials + Sync> Custodio<A, C> {
    /// The `Sign` call after the bus handed over the sender: validate, look up the caller, ask polkit,
    /// sign, then record exactly one entry. The reply is built only after the entry is recorded; if
    /// that fails nothing is returned but an error.
    ///
    /// # Errors
    /// A D-Bus error for a refused or failed call, [`ServiceError::AuditUnavailable`] if the entry could
    /// not be recorded.
    pub async fn sign_call(
        &self,
        sender: Option<&str>,
        id: &str,
        mechanism: u32,
        hash: u32,
        salt_len: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, ServiceError> {
        let request = parse_sign_request(id, mechanism, hash, salt_len, data)
            .map_err(|e| ServiceError::from(&e))?;
        let (key_id, audit_mechanism) = audit_parts(&request.id, &request.mechanism)?;
        // A missing key or another uid's key is refused here: no polkit call and no entry. The
        // entry would add nothing the caller does not know, and `NoSuchKey` must look the same
        // for both. See `docs/decisions.md`.
        let Some((outcome, caller, result)) = self.attempt(sender, &request, data).await? else {
            return Err(ServiceError::NoSuchKey);
        };
        let entry = match caller {
            Some(caller) => Entry::new(outcome, caller, key_id, Some(audit_mechanism)),
            None => Entry::without_caller(key_id, Some(audit_mechanism)),
        };
        let sink = Arc::clone(&self.sink);
        match run_on_thread(move || sink.record(&entry)).await {
            Some(Ok(())) => result,
            _ => Err(ServiceError::AuditUnavailable),
        }
    }

    /// The owner of this call: the uid the bus reports for the sender, never an argument.
    async fn owner(&self, sender: Option<&str>) -> Result<u32, ServiceError> {
        let sender = sender.ok_or(ServiceError::AuthorizationUnavailable)?;
        self.credentials
            .credentials(sender)
            .await
            .map(|c| c.uid)
            .map_err(|_| ServiceError::AuthorizationUnavailable)
    }

    /// `ListKeys` after the bus handed over the sender: `(id, key type, DER certificate)` of every
    /// key of the caller. Asks no polkit.
    ///
    /// # Errors
    /// [`ServiceError::AuthorizationUnavailable`] if the caller is unknown; [`ServiceError::Internal`]
    /// if the store cannot be read or a key has no readable certificate or a readable type.
    pub async fn list_keys_call(
        &self,
        sender: Option<&str>,
    ) -> Result<Vec<(String, String, Vec<u8>)>, ServiceError> {
        let owner = self.owner(sender).await?;
        let ids = self.store.list(owner).map_err(|e| ServiceError::from(&e))?;
        let mut out = Vec::new();
        // A key a delete has made unusable is not listed, whatever is still on disk.
        let listed = ids
            .iter()
            .filter(|i| !i.ends_with(CERT_SUFFIX) && !self.deletes.is_unusable(owner, i));
        for id in listed {
            let key = self
                .store
                .get(owner, id)
                .map_err(|_| ServiceError::Internal)?;
            let kind = classify(key.expose_secret()).map_err(|_| ServiceError::Internal)?;
            let cert = self
                .store
                .get(owner, &cert_id(id))
                .map_err(|_| ServiceError::Internal)?;
            out.push((
                id.clone(),
                kind_name(kind).to_owned(),
                cert.expose_secret().to_vec(),
            ));
        }
        Ok(out)
    }

    /// Credentials, the caller's key, polkit and signing, with the outcome to record. `Ok(None)`:
    /// the caller has no key with this id; nothing is recorded and polkit was not asked.
    async fn attempt(
        &self,
        sender: Option<&str>,
        request: &SignRequest,
        data: &[u8],
    ) -> Result<Option<Attempt>, ServiceError> {
        let unavailable = || ServiceError::AuthorizationUnavailable;
        let Some(sender) = sender else {
            return Ok(Some((
                Outcome::AuthorizationUnavailable,
                None,
                Err(unavailable()),
            )));
        };
        let Ok(caller) = self.credentials.credentials(sender).await else {
            return Ok(Some((
                Outcome::AuthorizationUnavailable,
                None,
                Err(unavailable()),
            )));
        };
        // Only the caller's own keys are looked at. Any other store failure is reported after
        // polkit, as a failed signature, as before.
        if self.deletes.is_unusable(caller.uid, &request.id) {
            return Ok(None);
        }
        let key = match self.store.get(caller.uid, &request.id) {
            Err(StoreError::NotFound) => return Ok(None),
            other => other.map_err(|e| ServiceError::from(&e)),
        };
        Ok(Some(
            self.authorize_and_sign(sender, caller, key, request, data)
                .await,
        ))
    }

    /// Polkit, then the signature with the key already looked up.
    async fn authorize_and_sign(
        &self,
        sender: &str,
        caller: Caller,
        key: Result<SecretSlice<u8>, ServiceError>,
        request: &SignRequest,
        data: &[u8],
    ) -> Attempt {
        let unavailable = || ServiceError::AuthorizationUnavailable;
        match self.authorizer.authorize(sender, ACTION_ID).await {
            Ok(()) => {}
            Err(AuthError::Denied) => {
                return (
                    Outcome::Denied,
                    Some(caller),
                    Err(ServiceError::PolkitDenied),
                );
            }
            Err(AuthError::BadSender | AuthError::Unavailable(_)) => {
                let outcome = Outcome::AuthorizationUnavailable;
                return (outcome, Some(caller), Err(unavailable()));
            }
        }
        let signed = key.and_then(|key| {
            sign(&key, request.mechanism, data).map_err(|e| ServiceError::from(&e))
        });
        let outcome = if signed.is_ok() {
            Outcome::Signed
        } else {
            Outcome::SigningFailed
        };
        (outcome, Some(caller), signed)
    }
}

#[interface(name = "com.rfirma.Custodio1")]
impl<A, C> Custodio<A, C>
where
    A: Authorizer + Send + Sync + 'static,
    C: CallerCredentials + Send + Sync + 'static,
{
    /// `(key id, key type, DER certificate)` for every stored key of the caller.
    async fn list_keys(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<(String, String, Vec<u8>)>, ServiceError> {
        self.list_keys_call(header.sender().map(zbus::names::UniqueName::as_str))
            .await
    }

    /// Imports a `.p12` as key `id` of the caller; returns the key type.
    // The `interface` macro cannot deserialize a borrowed `[u8]`, so the bytes are owned.
    #[allow(clippy::needless_pass_by_value)]
    async fn import_p12(
        &self,
        #[zbus(header)] header: Header<'_>,
        id: &str,
        p12: Vec<u8>,
        password: &str,
    ) -> Result<String, ServiceError> {
        self.import_call(
            header.sender().map(zbus::names::UniqueName::as_str),
            id,
            &p12,
            password,
        )
        .await
    }

    /// Deletes key `id` of the caller with its certificate, after polkit approves this one call.
    async fn delete_key(
        &self,
        #[zbus(header)] header: Header<'_>,
        id: &str,
    ) -> Result<(), ServiceError> {
        self.delete_call(header.sender().map(zbus::names::UniqueName::as_str), id)
            .await
    }

    /// Replaces the certificate of key `id` of the caller with one for the same key, after polkit
    /// approves this one call.
    // The `interface` macro cannot deserialize a borrowed `[u8]`, so the bytes are owned.
    #[allow(clippy::needless_pass_by_value)]
    async fn replace_certificate(
        &self,
        #[zbus(header)] header: Header<'_>,
        id: &str,
        certificate: Vec<u8>,
    ) -> Result<(), ServiceError> {
        self.replace_call(
            header.sender().map(zbus::names::UniqueName::as_str),
            id,
            &certificate,
        )
        .await
    }

    /// Signs `data` with key `id`, after polkit approves this one call.
    async fn sign(
        &self,
        #[zbus(header)] header: Header<'_>,
        id: String,
        mechanism: u32,
        hash: u32,
        salt_len: u32,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, ServiceError> {
        self.sign_call(
            header.sender().map(zbus::names::UniqueName::as_str),
            &id,
            mechanism,
            hash,
            salt_len,
            &data,
        )
        .await
    }
}

mod delete;
mod delete_state;
mod import;
mod replace;
#[cfg(test)]
mod tests;
