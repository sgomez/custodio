use std::future::{Future, ready};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::audit::{FailingSink, MemorySink};
use crate::credentials::CredentialsError;
use crate::import::import_p12;
use crate::store::{Record, StoreError};

pub(super) struct Counting {
    pub(super) result: fn() -> Result<(), AuthError>,
    pub(super) calls: Arc<AtomicUsize>,
}

impl Authorizer for Counting {
    fn authorize(&self, _: &str, _: &str) -> impl Future<Output = Result<(), AuthError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ready((self.result)())
    }
}

pub(super) struct Creds(pub(super) Arc<AtomicUsize>);

impl CallerCredentials for Creds {
    fn credentials(
        &self,
        _: &str,
    ) -> impl Future<Output = Result<Caller, CredentialsError>> + Send {
        self.0.fetch_add(1, Ordering::SeqCst);
        ready(Ok(Caller { uid: 11, pid: 22 }))
    }
}

pub(super) struct Rig {
    pub(super) service: Custodio<Counting, Creds>,
    pub(super) sink: Arc<MemorySink>,
    pub(super) store: Arc<KeyStore>,
    pub(super) auth_calls: Arc<AtomicUsize>,
    pub(super) cred_calls: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

pub(super) fn rig(
    result: fn() -> Result<(), AuthError>,
) -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(KeyStore::open(dir.path().join("keys"))?);
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let cred_calls = Arc::new(AtomicUsize::new(0));
    let sink = Arc::new(MemorySink::default());
    let service = Custodio::new(
        store.clone(),
        Counting {
            result,
            calls: auth_calls.clone(),
        },
        Creds(cred_calls.clone()),
        sink.clone(),
    )
    .with_key_credentials(std::sync::Arc::new(
        crate::creds::memory::MemoryCreds::host(),
    ));
    Ok(Rig {
        service,
        sink,
        store,
        auth_calls,
        cred_calls,
        _dir: dir,
    })
}

#[test]
fn sign_without_sender_records_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    let r = rig(|| Ok(()))?;
    let got = zbus::block_on(r.service.sign_call(None, "k", CKM_ECDSA, 0, 0, b"x"));
    assert_eq!(got, Err(ServiceError::AuthorizationUnavailable));
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(r.cred_calls.load(Ordering::SeqCst), 0);
    let entries = r.sink.entries();
    assert_eq!(entries.len(), 1);
    let e = entries.first().ok_or("no entry")?;
    assert_eq!(e.outcome(), Outcome::AuthorizationUnavailable);
    assert_eq!(e.caller(), None);
    assert_eq!(e.key_id().as_str(), "k");
    assert_eq!(e.mechanism(), Some(AuditMechanism::Ecdsa));
    Ok(())
}

#[test]
fn bad_sender_and_unavailable_are_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    for result in [
        (|| Err(AuthError::BadSender)) as fn() -> Result<(), AuthError>,
        || Err(AuthError::Unavailable("x".into())),
    ] {
        let r = rig(result)?;
        seed(&r, "k")?;
        let got = zbus::block_on(
            r.service
                .sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"),
        );
        assert_eq!(got, Err(ServiceError::AuthorizationUnavailable));
        let entries = r.sink.entries();
        let e = entries.first().ok_or("no entry")?;
        assert_eq!(entries.len(), 1);
        assert_eq!(e.outcome(), Outcome::AuthorizationUnavailable);
        assert_eq!(e.caller(), Some(Caller { uid: 11, pid: 22 }));
    }
    Ok(())
}

#[test]
fn denied_and_missing_key_are_distinct() -> Result<(), Box<dyn std::error::Error>> {
    let r = rig(|| Err(AuthError::Denied))?;
    seed(&r, "k")?;
    let got = zbus::block_on(
        r.service
            .sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"),
    );
    assert_eq!(got, Err(ServiceError::PolkitDenied));
    let r2 = rig(|| Ok(()))?;
    let got = zbus::block_on(
        r2.service
            .sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"),
    );
    assert_eq!(got, Err(ServiceError::NoSuchKey));
    let outcomes = |r: &Rig| {
        r.sink
            .entries()
            .iter()
            .map(Entry::outcome)
            .collect::<Vec<_>>()
    };
    assert_eq!(outcomes(&r), [Outcome::Denied]);
    // A missing key is refused before polkit and leaves no entry.
    assert_eq!(outcomes(&r2), []);
    assert_eq!(r2.auth_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn refused_arguments_never_reach_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let r = rig(|| Ok(()))?;
    let got = zbus::block_on(
        r.service
            .sign_call(Some(":1.1"), "a/b", CKM_ECDSA, 0, 0, b"x"),
    );
    assert_eq!(got, Err(ServiceError::InvalidArgs));
    assert_eq!(r.cred_calls.load(Ordering::SeqCst), 0);
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn sign_with_unconstructible_key_id_is_refused() {
    let got = audit_parts("bad/id", &Mechanism::Ecdsa);
    assert_eq!(got.as_ref().err(), Some(&ServiceError::AuditUnavailable));
    let ok = audit_parts("good", &Mechanism::RsaPkcs).map(|(k, m)| (k.as_str().to_owned(), m));
    assert_eq!(ok.ok(), Some(("good".to_owned(), AuditMechanism::RsaPkcs)));
}

pub(super) const P12: &[u8] = include_bytes!("../../../tests/fixtures/p256.p12");
const SENDER: Option<&str> = Some(":1.1");

/// Owner 11 is the fake caller; the test process must be none of the two uids used here.
fn other_uid() -> u32 {
    let euid = rustix::process::geteuid().as_raw();
    assert_ne!(euid, 11);
    assert_ne!(euid, 12);
    12
}

/// Puts the key straight into the store, for tests whose authorizer refuses.
pub(super) fn seed(r: &Rig, id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let password = SecretString::from("test-password".to_owned());
    import_p12(
        &r.store,
        &crate::creds::memory::MemoryCreds::host(),
        &crate::tpm::open::NoTpm,
        11,
        id,
        P12,
        &password,
    )?;
    Ok(())
}

fn import(r: &Rig, id: &str) -> Result<String, ServiceError> {
    zbus::block_on(r.service.import_call(SENDER, id, P12, "test-password"))
        .map(|(key_type, _)| key_type)
}

#[test]
fn import_stores_key_and_certificate_under_the_bus_uid() -> Result<(), Box<dyn std::error::Error>> {
    let r = rig(|| Ok(()))?;
    let euid = rustix::process::geteuid().as_raw();
    assert_ne!(euid, 11);
    assert_eq!(import(&r, "mine")?, "ecdsa-p256");
    // One record holds the key and its certificate; the key in it is a credential, not PKCS#8.
    let record = r.store.get(11, "mine")?;
    assert_ne!(record.certificate().len(), 0);
    assert!(record.protected().credential().is_some());
    for uid in [euid, 0, other_uid()] {
        assert!(matches!(
            r.store.get(uid, "mine"),
            Err(StoreError::NotFound)
        ));
    }
    Ok(())
}

#[test]
fn list_reads_the_area_of_the_bus_uid() -> Result<(), Box<dyn std::error::Error>> {
    let r = rig(|| Ok(()))?;
    assert_eq!(import(&r, "mine")?, "ecdsa-p256");
    // Another owner's key with a certificate, which must not show.
    let mine = r.store.get(11, "mine")?;
    r.store.put(&Record::new(
        other_uid(),
        "theirs",
        mine.kind(),
        mine.certificate(),
        mine.protected().clone(),
    )?)?;
    let got = zbus::block_on(r.service.list_keys_call(SENDER))?;
    assert_eq!(
        got,
        [(
            "mine".to_owned(),
            "ecdsa-p256".to_owned(),
            mine.kind().wire().to_owned(),
            mine.certificate().to_vec()
        )]
    );
    Ok(())
}

#[test]
fn sign_uses_the_area_of_the_bus_uid() -> Result<(), Box<dyn std::error::Error>> {
    let r = rig(|| Ok(()))?;
    import(&r, "mine")?;
    let got = zbus::block_on(r.service.sign_call(SENDER, "mine", CKM_ECDSA, 0, 0, b"x"));
    assert!(got.is_ok(), "{got:?}");
    // The same key stored only under another uid is not found.
    let mine = r.store.get(11, "mine")?;
    r.store.put(&Record::new(
        other_uid(),
        "theirs",
        mine.kind(),
        mine.certificate(),
        mine.protected().clone(),
    )?)?;
    let got = zbus::block_on(r.service.sign_call(SENDER, "theirs", CKM_ECDSA, 0, 0, b"x"));
    assert_eq!(got, Err(ServiceError::from(&StoreError::NotFound)));
    Ok(())
}

#[test]
fn owner_needs_a_sender() -> Result<(), Box<dyn std::error::Error>> {
    let r = rig(|| Ok(()))?;
    assert_eq!(
        zbus::block_on(r.service.list_keys_call(None)),
        Err(ServiceError::AuthorizationUnavailable)
    );
    Ok(())
}

#[test]
fn a_failing_sink_replaces_the_error() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(KeyStore::open(dir.path().join("keys"))?);
    let password = SecretString::from("test-password".to_owned());
    import_p12(
        &store,
        &crate::creds::memory::MemoryCreds::host(),
        &crate::tpm::open::NoTpm,
        11,
        "k",
        P12,
        &password,
    )?;
    let service = Custodio::new(
        store,
        Counting {
            result: || Err(AuthError::Denied),
            calls: Arc::default(),
        },
        Creds(Arc::default()),
        Arc::new(FailingSink),
    )
    .with_key_credentials(std::sync::Arc::new(
        crate::creds::memory::MemoryCreds::host(),
    ));
    let got = zbus::block_on(service.sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"));
    assert_eq!(got, Err(ServiceError::AuditUnavailable));
    Ok(())
}

/// A decoder that counts and always fails.
struct FailingDecoder(Arc<AtomicUsize>);

impl crate::import::P12Decoder for FailingDecoder {
    fn decode(
        &self,
        _: &[u8],
        _: &SecretString,
    ) -> Result<crate::import::ParsedP12, crate::import::ImportError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(crate::import::ImportError::NoPrivateKey)
    }
}

type Answer = fn() -> Result<(), AuthError>;

/// The reply of an import, the polkit calls and the decoder calls.
type Imported = (Result<crate::dbus::ImportReply, ServiceError>, usize, usize);

fn import_with(
    result: fn() -> Result<(), AuthError>,
    sender: Option<&str>,
) -> Result<Imported, Box<dyn std::error::Error>> {
    let mut r = rig(result)?;
    let decoded = Arc::new(AtomicUsize::new(0));
    r.service = r
        .service
        .with_decoder(Arc::new(FailingDecoder(decoded.clone())));
    let got = zbus::block_on(r.service.import_call(sender, "k", b"x", "pw"));
    Ok((
        got,
        r.auth_calls.load(Ordering::SeqCst),
        decoded.load(Ordering::SeqCst),
    ))
}

#[test]
fn import_without_sender_asks_and_decodes_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let (got, polkit, decoded) = import_with(|| Ok(()), None)?;
    assert_eq!(got, Err(ServiceError::AuthorizationUnavailable));
    assert_eq!((polkit, decoded), (0, 0));
    Ok(())
}

#[test]
fn import_refusals_never_decode() -> Result<(), Box<dyn std::error::Error>> {
    let cases: [(Answer, ServiceError); 3] = [
        (|| Err(AuthError::Denied), ServiceError::PolkitDenied),
        (
            || Err(AuthError::BadSender),
            ServiceError::AuthorizationUnavailable,
        ),
        (
            || Err(AuthError::Unavailable("x".into())),
            ServiceError::AuthorizationUnavailable,
        ),
    ];
    for (result, want) in cases {
        let (got, polkit, decoded) = import_with(result, Some(":1.1"))?;
        assert_eq!(got, Err(want));
        assert_eq!((polkit, decoded), (1, 0));
    }
    // Control: approval reaches the decoder.
    let (got, polkit, decoded) = import_with(|| Ok(()), Some(":1.1"))?;
    assert_eq!(got, Err(ServiceError::WrongPasswordOrBadP12));
    assert_eq!((polkit, decoded), (1, 1));
    Ok(())
}

use crate::audit::{AuditKeyType, ImportOutcome, Operation};
use crate::dbus::import::{audit_key_type, import_outcome};
use crate::import::ImportError;

/// Every `ImportError`, with the outcome it is recorded as: a literal table, not the code's own rule.
#[test]
fn every_import_error_has_its_outcome() {
    use ImportOutcome::{StorageFailure, UnsupportedKey, WrongPassword};
    let table = [
        (ImportError::TooLarge, StorageFailure),
        (ImportError::Parse("x".into()), WrongPassword),
        (ImportError::NoPrivateKey, WrongPassword),
        (ImportError::MultipleKeys, WrongPassword),
        (ImportError::NoCertificate, WrongPassword),
        (ImportError::CertificateMismatch, UnsupportedKey),
        (ImportError::UnsupportedKey("x".into()), UnsupportedKey),
        (
            ImportError::Store(StoreError::AlreadyExists),
            StorageFailure,
        ),
        (ImportError::Store(StoreError::NotFound), StorageFailure),
        (ImportError::Store(StoreError::TooLarge), StorageFailure),
    ];
    for (error, want) in table {
        assert_eq!(import_outcome(&error), want, "{error}");
    }
}

#[test]
fn key_kinds_map_to_audit_key_types() {
    assert_eq!(audit_key_type(KeyKind::Rsa2048), AuditKeyType::Rsa2048);
    assert_eq!(audit_key_type(KeyKind::EcdsaP256), AuditKeyType::EcdsaP256);
}

/// The one entry of an import, as `(outcome, caller, key id, key type)`.
type Seen = (&'static str, Option<Caller>, String, Option<AuditKeyType>);

fn only_entry(sink: &MemorySink) -> Result<Seen, Box<dyn std::error::Error>> {
    assert_eq!(sink.entries().len(), 0);
    let all = sink.operation_entries();
    assert_eq!(all.len(), 1);
    let e = all.first().ok_or("no entry")?;
    assert_eq!(e.operation(), Operation::Import);
    Ok((
        e.outcome_name(),
        e.caller(),
        e.key_id().as_str().to_owned(),
        e.key_type(),
    ))
}

#[test]
fn import_without_sender_records_unavailable_without_caller()
-> Result<(), Box<dyn std::error::Error>> {
    let r = rig(|| Ok(()))?;
    let got = zbus::block_on(r.service.import_call(None, "k", P12, "test-password"));
    assert_eq!(got, Err(ServiceError::AuthorizationUnavailable));
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(r.cred_calls.load(Ordering::SeqCst), 0);
    let want = ("authorization_unavailable", None, "k".to_owned(), None);
    assert_eq!(only_entry(&r.sink)?, want);
    Ok(())
}

#[test]
fn import_without_sender_fails_closed_with_a_failing_sink() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let store = Arc::new(KeyStore::open(dir.path().join("keys"))?);
    let service = Custodio::new(
        store,
        Counting {
            result: || Ok(()),
            calls: Arc::default(),
        },
        Creds(Arc::default()),
        Arc::new(FailingSink),
    )
    .with_key_credentials(std::sync::Arc::new(
        crate::creds::memory::MemoryCreds::host(),
    ));
    let got = zbus::block_on(service.import_call(None, "k", P12, "test-password"));
    assert_eq!(got, Err(ServiceError::AuditUnavailable));
    Ok(())
}

#[test]
fn import_refusals_of_polkit_are_recorded_with_the_caller() -> Result<(), Box<dyn std::error::Error>>
{
    let cases: [(Answer, &str); 3] = [
        (|| Err(AuthError::Denied), "denied"),
        (|| Err(AuthError::BadSender), "authorization_unavailable"),
        (
            || Err(AuthError::Unavailable("x".into())),
            "authorization_unavailable",
        ),
    ];
    for (result, outcome) in cases {
        let r = rig(result)?;
        let got = import(&r, "k");
        assert!(got.is_err());
        let want = (
            outcome,
            Some(Caller { uid: 11, pid: 22 }),
            "k".to_owned(),
            None,
        );
        assert_eq!(only_entry(&r.sink)?, want);
        assert!(matches!(r.store.get(11, "k"), Err(StoreError::NotFound)));
    }
    Ok(())
}
