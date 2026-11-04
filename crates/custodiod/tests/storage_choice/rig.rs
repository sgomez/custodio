//! The service under test, its doubles, and what to read back.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use custodio_it::tpm_filter::{CommandFault, FaultAction, Lacks, alg, cc};
use custodiod::audit::{AuditKeyType, MemorySink, OperationEntry};
use custodiod::credentials::BusCredentials;
use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::{Credentials, CredsError};
use custodiod::dbus::{BUS_NAME, Custodio, OBJECT_PATH};
use custodiod::polkit::PolkitAuthorizer;
use custodiod::store::{KeyStore, Kind};
use custodiod::tpm::{OpenError, Session, TpmAccess};
use secrecy::SecretSlice;
use zbus::Connection;

use crate::bus::{Answer, Bus, FakePolkit, call, error_name};
use crate::common::{EC_SENTINEL_P12, RSA_SENTINEL_P12, SENTINEL_PASSWORD, uid};

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;
pub type TestResult = Res<()>;

pub use crate::support::Rig;

/// Both key types with their sentinel `.p12` and the names the API and the journal use.
pub const SUBJECTS: [Subject; 2] = [
    Subject {
        p12: RSA_SENTINEL_P12,
        reply: "rsa2048",
        audit: AuditKeyType::Rsa2048,
    },
    Subject {
        p12: EC_SENTINEL_P12,
        reply: "ecdsa-p256",
        audit: AuditKeyType::EcdsaP256,
    },
];

#[derive(Clone, Copy)]
pub struct Subject {
    pub p12: &'static [u8],
    pub reply: &'static str,
    pub audit: AuditKeyType,
}

pub const ERR_TPM: &str = custodio_client::ERROR_TPM_FAILED;
pub const ERR_CREDS: &str = custodio_client::ERROR_CREDENTIALS_UNAVAILABLE;

/// A TPM access point that counts the opens and passes them on.
pub struct Counting {
    inner: Mutex<Arc<dyn TpmAccess>>,
    pub opens: AtomicUsize,
}

impl Counting {
    pub fn new(inner: impl TpmAccess + 'static) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Arc::new(inner)),
            opens: AtomicUsize::new(0),
        })
    }

    /// Replaces the TPM behind the counter (a repaired one).
    pub fn swap(&self, inner: impl TpmAccess + 'static) {
        *self.inner.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(inner);
    }

    pub fn opens(&self) -> usize {
        self.opens.load(Ordering::SeqCst)
    }
}

impl TpmAccess for Counting {
    fn open(&self) -> Result<Box<dyn Session>, OpenError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        inner.open()
    }
}

/// A credential double that counts `encrypt` calls, can fail them with a chosen error, and answers with the header of
/// the wrapped [`MemoryCreds`].
pub struct SpyCreds {
    inner: MemoryCreds,
    pub encrypts: AtomicUsize,
    fail: Mutex<Option<CredsError>>,
}

impl SpyCreds {
    pub fn new(inner: MemoryCreds) -> Arc<Self> {
        Arc::new(Self {
            inner,
            encrypts: AtomicUsize::new(0),
            fail: Mutex::new(None),
        })
    }

    pub fn fail_with(&self, error: Option<CredsError>) {
        *self.fail.lock().unwrap_or_else(PoisonError::into_inner) = error;
    }

    pub fn encrypts(&self) -> usize {
        self.encrypts.load(Ordering::SeqCst)
    }
}

impl Credentials for SpyCreds {
    fn encrypt(&self, name: &str, plaintext: &SecretSlice<u8>) -> Result<Vec<u8>, CredsError> {
        self.encrypts.fetch_add(1, Ordering::SeqCst);
        if let Some(e) = *self.fail.lock().unwrap_or_else(PoisonError::into_inner) {
            return Err(e);
        }
        self.inner.encrypt(name, plaintext)
    }

    fn decrypt(&self, name: &str, credential: &[u8]) -> Result<SecretSlice<u8>, CredsError> {
        self.inner.decrypt(name, credential)
    }
}

/// A `Lacks` with one command code that fails with `code`.
pub fn fault(command: u32, code: u32) -> Lacks {
    Lacks {
        faults: vec![CommandFault {
            command,
            action: FaultAction::Respond(code),
        }],
        ..Lacks::default()
    }
}

/// A TPM that lacks `Import`: both key types are `Lacks`.
pub fn lacks_import() -> Lacks {
    Lacks {
        commands: vec![cc::IMPORT],
        ..Lacks::default()
    }
}

/// A TPM that cannot serve the mechanism of the key type: RSA decrypt for RSA, ECDSA signing for ECC.
pub fn lacks_mechanism(rsa: bool) -> Lacks {
    if rsa {
        Lacks {
            commands: vec![cc::RSA_DECRYPT],
            ..Lacks::default()
        }
    } else {
        Lacks {
            algorithms: vec![alg::ECDSA],
            ..Lacks::default()
        }
    }
}

/// The service, its bus and the doubles.
pub struct Svc {
    _bus: Bus,
    _state: tempfile::TempDir,
    pub store: Arc<KeyStore>,
    _polkit: Connection,
    _service: Connection,
    client: Connection,
    pub sink: Arc<MemorySink>,
    pub creds: Arc<SpyCreds>,
    pub tpm: Arc<Counting>,
}

impl Svc {
    pub async fn start(tpm: Arc<Counting>, creds: Arc<SpyCreds>, answer: Answer) -> Res<Self> {
        let bus = Bus::start()?;
        let answer = Arc::new(Mutex::new(answer));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let polkit = bus.connect().await?;
        polkit
            .object_server()
            .at(
                "/org/freedesktop/PolicyKit1/Authority",
                FakePolkit {
                    answer,
                    asked,
                    requests: Arc::default(),
                    hold: Arc::default(),
                    hook: Arc::default(),
                },
            )
            .await?;
        polkit.request_name("org.freedesktop.PolicyKit1").await?;
        let state = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(state.path().join("keys"))?);
        let sink = Arc::new(MemorySink::default());
        let service = bus.connect().await?;
        let object = Custodio::new(
            store.clone(),
            PolkitAuthorizer::new(service.clone()),
            BusCredentials::new(service.clone()),
            sink.clone(),
        )
        .with_key_credentials(creds.clone())
        .with_tpm(tpm.clone());
        service.object_server().at(OBJECT_PATH, object).await?;
        service.request_name(BUS_NAME).await?;
        let client = bus.connect().await?;
        Ok(Self {
            _bus: bus,
            _state: state,
            store,
            _polkit: polkit,
            _service: service,
            client,
            sink,
            creds,
            tpm,
        })
    }

    /// `ImportP12`: the key type name of the reply, or the error name.
    pub async fn import(&self, id: &str, p12: &[u8], password: &str) -> Result<String, String> {
        let reply = call(&self.client, "ImportP12", &(id, p12.to_vec(), password))
            .await
            .map_err(|e| error_name(&e))?;
        reply.body().deserialize().map_err(|e| e.to_string())
    }

    pub async fn import_subject(&self, id: &str, subject: Subject) -> Result<String, String> {
        self.import(id, subject.p12, SENTINEL_PASSWORD).await
    }

    /// The kind the store holds for the test user's key `id`.
    pub fn kind_of(&self, id: &str) -> Option<Kind> {
        self.store.get(uid(), id).ok().map(|r| r.kind())
    }

    /// Every file (not directory) under the store, relative: temporary files included.
    pub fn files(&self) -> Vec<PathBuf> {
        fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push(path);
                }
            }
        }
        let mut out = Vec::new();
        walk(self.store.dir(), &mut out);
        out.sort();
        out
    }

    /// The store lists nothing for the test user and holds no file at all.
    pub fn assert_empty(&self, context: &str) {
        assert_eq!(
            self.store.list(uid()).unwrap(),
            Vec::<String>::new(),
            "{context}"
        );
        assert_eq!(self.files(), Vec::<PathBuf>::new(), "{context}");
    }

    pub fn entries(&self) -> Vec<OperationEntry> {
        self.sink.operation_entries()
    }

    /// Exactly one entry: an import with this outcome and key type.
    pub fn assert_one_entry(&self, outcome: &str, key_type: AuditKeyType, context: &str) {
        let entries = self.entries();
        assert_eq!(entries.len(), 1, "{context}");
        assert_eq!(entries[0].outcome_name(), outcome, "{context}");
        assert_eq!(entries[0].key_type(), Some(key_type), "{context}");
        assert_eq!(
            entries[0].operation(),
            custodiod::audit::Operation::Import,
            "{context}"
        );
    }
}

/// Whether any file under the store holds `needle`.
pub fn plaintext_in_store(svc: &Svc, needle: &[u8]) -> bool {
    svc.files()
        .iter()
        .any(|f| crate::support::contains(&std::fs::read(f).unwrap(), needle))
}

/// The PKCS#8 DER of the key in a sentinel `.p12`.
pub fn pkcs8_of(subject: Subject) -> Vec<u8> {
    use secrecy::ExposeSecret;
    let password = secrecy::SecretString::from(SENTINEL_PASSWORD.to_owned());
    custodiod::import::parse_p12(subject.p12, &password)
        .unwrap()
        .key
        .expose_secret()
        .to_vec()
}
