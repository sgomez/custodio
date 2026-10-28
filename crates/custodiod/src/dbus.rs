//! The `com.rfirma.Custodio1` D-Bus service: list keys and certificates, import a `.p12`, sign.
//!
//! Every `Sign` call asks polkit first and never caches the answer. Argument parsing lives in
//! plain functions ([`parse_sign_request`], [`parse_import_request`]) so it can be fuzzed.

use std::fmt;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use zbus::message::Header;
use zbus::{fdo, interface};

use crate::audit::{AuditMechanism, AuditSink, Caller, Entry, KeyId, Outcome};
use crate::credentials::CallerCredentials;
use crate::import::{KeyKind, MAX_P12_LEN, cert_id, import_p12};
use crate::offload::run_on_thread;
use crate::polkit::{AuthError, Authorizer};
use crate::sign::{Mechanism, PssHash, SignError, sign};
use crate::store::{KeyStore, StoreError};

/// Well-known bus name of the service.
pub const BUS_NAME: &str = "com.rfirma.Custodio1";
/// Object path of the service.
pub const OBJECT_PATH: &str = "/com/rfirma/Custodio1";

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

fn invalid(e: &RequestError) -> fdo::Error {
    fdo::Error::InvalidArgs(e.to_string())
}

/// Store errors go to the caller without paths.
fn store_error(e: &StoreError) -> fdo::Error {
    match e {
        StoreError::InvalidId => fdo::Error::InvalidArgs("invalid key id".into()),
        StoreError::AlreadyExists => fdo::Error::Failed("key already exists".into()),
        StoreError::NotFound => fdo::Error::Failed("no such key".into()),
        _ => fdo::Error::Failed("key store error".into()),
    }
}

fn kind_name(kind: KeyKind) -> &'static str {
    match kind {
        KeyKind::Rsa2048 => "rsa2048",
        KeyKind::EcdsaP256 => "ecdsa-p256",
    }
}

/// Why a signature was refused without a reason the caller may know.
fn audit_unavailable() -> fdo::Error {
    fdo::Error::Failed("audit unavailable".into())
}

/// The key id and mechanism for the audit entry of a checked request.
fn audit_parts(id: &str, mechanism: &Mechanism) -> Result<(KeyId, AuditMechanism), fdo::Error> {
    let key_id = KeyId::new(id).map_err(|_| audit_unavailable())?;
    Ok((key_id, AuditMechanism::from(mechanism)))
}

/// The object served at [`OBJECT_PATH`].
pub struct Custodio<A, C> {
    store: Arc<KeyStore>,
    authorizer: A,
    credentials: C,
    sink: Arc<dyn AuditSink>,
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
        }
    }
}

impl<A: Authorizer + Sync, C: CallerCredentials + Sync> Custodio<A, C> {
    /// The `Sign` call after the bus handed over the sender: validate, look up the caller, ask polkit,
    /// sign, then record exactly one entry. The reply is built only after the entry is recorded; if
    /// that fails nothing is returned but an error.
    ///
    /// # Errors
    /// A D-Bus error for a refused or failed call, `Failed("audit unavailable")` if the entry could
    /// not be recorded.
    pub async fn sign_call(
        &self,
        sender: Option<&str>,
        id: &str,
        mechanism: u32,
        hash: u32,
        salt_len: u32,
        data: &[u8],
    ) -> fdo::Result<Vec<u8>> {
        let request =
            parse_sign_request(id, mechanism, hash, salt_len, data).map_err(|e| invalid(&e))?;
        let (key_id, audit_mechanism) = audit_parts(&request.id, &request.mechanism)?;
        let (outcome, caller, result) = self.attempt(sender, &request, data).await;
        let entry = match caller {
            Some(caller) => Entry::new(outcome, caller, key_id, Some(audit_mechanism)),
            None => Entry::without_caller(key_id, Some(audit_mechanism)),
        };
        let sink = Arc::clone(&self.sink);
        match run_on_thread(move || sink.record(&entry)).await {
            Some(Ok(())) => result,
            _ => Err(audit_unavailable()),
        }
    }

    /// Credentials, polkit and signing, with the outcome to record.
    async fn attempt(
        &self,
        sender: Option<&str>,
        request: &SignRequest,
        data: &[u8],
    ) -> (Outcome, Option<Caller>, fdo::Result<Vec<u8>>) {
        let unavailable = || fdo::Error::AccessDenied("authorization unavailable".into());
        let Some(sender) = sender else {
            return (Outcome::AuthorizationUnavailable, None, Err(unavailable()));
        };
        let Ok(caller) = self.credentials.credentials(sender).await else {
            return (Outcome::AuthorizationUnavailable, None, Err(unavailable()));
        };
        match self.authorizer.authorize(sender).await {
            Ok(()) => {}
            Err(AuthError::Denied) => {
                let denied = fdo::Error::AccessDenied("not authorized".into());
                return (Outcome::Denied, Some(caller), Err(denied));
            }
            Err(AuthError::BadSender | AuthError::Unavailable(_)) => {
                let outcome = Outcome::AuthorizationUnavailable;
                return (outcome, Some(caller), Err(unavailable()));
            }
        }
        let signed = self
            .store
            .get(&request.id)
            .map_err(|e| store_error(&e))
            .and_then(|key| {
                sign(&key, request.mechanism, data).map_err(|e| match e {
                    SignError::BadData | SignError::MechanismMismatch => {
                        fdo::Error::InvalidArgs(e.to_string())
                    }
                    SignError::BadKey | SignError::Failed => fdo::Error::Failed(e.to_string()),
                })
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
    /// Ids of the stored keys.
    fn list_keys(&self) -> fdo::Result<Vec<String>> {
        let ids = self.store.list().map_err(|e| store_error(&e))?;
        Ok(ids
            .into_iter()
            .filter(|i| !i.ends_with(CERT_SUFFIX))
            .collect())
    }

    /// `(key id, DER certificate)` for every key that has a certificate.
    fn list_certificates(&self) -> fdo::Result<Vec<(String, Vec<u8>)>> {
        let ids = self.store.list().map_err(|e| store_error(&e))?;
        let mut out = Vec::new();
        for id in ids.iter().filter(|i| !i.ends_with(CERT_SUFFIX)) {
            if let Ok(cert) = self.store.get(&cert_id(id)) {
                out.push((id.clone(), cert.expose_secret().to_vec()));
            }
        }
        Ok(out)
    }

    /// Imports a `.p12` as key `id`; returns the key type.
    // The `interface` macro cannot deserialize a borrowed `[u8]`, so the bytes are owned.
    #[allow(clippy::needless_pass_by_value)]
    fn import_p12(&self, id: &str, p12: Vec<u8>, password: &str) -> fdo::Result<String> {
        let request = parse_import_request(id, &p12, password).map_err(|e| invalid(&e))?;
        let kind = import_p12(&self.store, &request.id, &p12, &request.password)
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        Ok(kind_name(kind).to_owned())
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
    ) -> fdo::Result<Vec<u8>> {
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

#[cfg(test)]
mod tests;
