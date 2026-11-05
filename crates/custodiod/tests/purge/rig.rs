//! The fixture, the doubles and the private bus of the `purge` target.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use custodiod::audit::{AuditError, AuditSink, Entry, MemorySink, OperationEntry};
use custodiod::creds::memory::MemoryCreds;
use custodiod::import::import_p12;
use custodiod::startup::{StartError, start};
use custodiod::store::KeyStore;
use custodiod::tpm::open::NoTpm;
use secrecy::SecretString;
use zbus::connection::Builder;
use zbus::{Connection, block_on};

use crate::bus::{Answer, Bus, FakePolkit, call, error_name};
use crate::common::{EC_P12, PASSWORD, uid};

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;
pub type TestResult = Res<()>;

/// What the bus answers for a name nobody owns.
pub const NO_SERVICE: [&str; 2] = [
    "org.freedesktop.DBus.Error.ServiceUnknown",
    "org.freedesktop.DBus.Error.NameHasNoOwner",
];

/// The sentinels in the files of the fixture: they must appear in no entry.
pub fn key_bytes(id: &str) -> Vec<u8> {
    let mut v = vec![0x30, 0x82, 0x01, 0x22];
    v.extend(format!("KEY-SENTINEL-{id}-d41f").bytes());
    v
}

pub fn cert_bytes(id: &str) -> Vec<u8> {
    let mut v = vec![0x30, 0x82, 0x02, 0x10];
    v.extend(format!("CERT-SENTINEL-{id}-9b27").bytes());
    v
}

pub fn put_file(area: &Path, name: &str, bytes: &[u8]) -> TestResult {
    let path = area.join(name);
    fs::write(&path, bytes)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn area_of(root: &Path, owner: u32) -> Res<PathBuf> {
    let area = root.join(owner.to_string());
    if !area.exists() {
        fs::create_dir(&area)?;
        fs::set_permissions(&area, fs::Permissions::from_mode(0o700))?;
    }
    Ok(area)
}

/// A key of the earlier format: `<id>` and, unless `cert` is false, `<id>-cert`.
pub fn legacy_key(root: &Path, owner: u32, id: &str, cert: bool) -> TestResult {
    let area = area_of(root, owner)?;
    put_file(&area, id, &key_bytes(id))?;
    if cert {
        put_file(&area, &format!("{id}-cert"), &cert_bytes(id))?;
    }
    Ok(())
}

/// The keys the fixture purges, by owner then id.
pub fn expected() -> Vec<(u32, &'static str)> {
    let mut all = vec![
        (uid(), "alpha"),
        (uid(), "beta"),
        (uid(), "ghost"),
        (2000, "delta"),
        (3000, "eps"),
    ];
    all.sort_unstable();
    all
}

/// Every file name of the fixture's legacy keys, by owner.
pub fn legacy_files() -> Vec<(u32, &'static str)> {
    vec![
        (uid(), "alpha"),
        (uid(), "alpha-cert"),
        (uid(), "beta"),
        (uid(), "ghost-cert"),
        (2000, "delta"),
        (2000, "delta-cert"),
        (3000, "eps"),
    ]
}

/// A state of the earlier format: several owners; a key with its certificate, a key without one, an orphan
/// certificate; and a key of the current format next to them (`fresh`, and `ghost`'s namesake is not there).
pub fn m3_state(root: &Path) -> TestResult {
    let store = KeyStore::open(root)?;
    legacy_key(root, uid(), "alpha", true)?;
    legacy_key(root, uid(), "beta", false)?;
    put_file(&area_of(root, uid())?, "ghost-cert", &cert_bytes("ghost"))?;
    legacy_key(root, 2000, "delta", true)?;
    legacy_key(root, 3000, "eps", false)?;
    import_p12(
        &store,
        &MemoryCreds::host(),
        &NoTpm,
        uid(),
        "fresh",
        EC_P12,
        &SecretString::from(PASSWORD.to_owned()),
    )?;
    Ok(())
}

pub fn names(dir: &Path) -> Res<Vec<String>> {
    let mut all = fs::read_dir(dir)?
        .map(|e| Ok(e?.file_name().to_string_lossy().into_owned()))
        .collect::<Res<Vec<_>>>()?;
    all.sort();
    Ok(all)
}

/// A journal sink that can block on, or fail at, the n-th purge entry (counted from 0).
pub struct Gate {
    pub inner: MemorySink,
    pub seen: AtomicUsize,
    pub block_at: Option<usize>,
    pub fail_at: Option<usize>,
    pub entered: Mutex<Sender<usize>>,
    pub release: Mutex<Receiver<()>>,
}

pub struct GateHandle {
    pub sink: Arc<Gate>,
    pub entered: Receiver<usize>,
    pub release: Sender<()>,
}

impl Gate {
    pub fn handle(block_at: Option<usize>, fail_at: Option<usize>) -> GateHandle {
        let (entered_tx, entered) = channel();
        let (release, release_rx) = channel();
        GateHandle {
            sink: Arc::new(Self {
                inner: MemorySink::default(),
                seen: AtomicUsize::new(0),
                block_at,
                fail_at,
                entered: Mutex::new(entered_tx),
                release: Mutex::new(release_rx),
            }),
            entered,
            release,
        }
    }
}

impl AuditSink for Gate {
    fn record(&self, entry: &Entry) -> Result<(), AuditError> {
        self.inner.record(entry)
    }

    fn record_operation(&self, entry: &OperationEntry) -> Result<(), AuditError> {
        let n = self.seen.fetch_add(1, Ordering::SeqCst);
        if self.block_at == Some(n) {
            let _ = self
                .entered
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .send(n);
            let _ = self
                .release
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .recv_timeout(Duration::from_secs(20));
        }
        if self.fail_at == Some(n) {
            return Err(AuditError::Io(std::io::ErrorKind::Other));
        }
        self.inner.record_operation(entry)
    }
}

/// A private bus with fake polkit, a client, and a state directory.
pub struct Env {
    pub bus: Bus,
    pub _polkit: Connection,
    pub client: Connection,
    pub state: tempfile::TempDir,
}

impl Env {
    pub fn root(&self) -> PathBuf {
        self.state.path().join("keys")
    }

    /// A fresh bus over the state directory of `other`, which may hold a state already.
    pub fn start(state: Option<tempfile::TempDir>) -> Res<Self> {
        block_on(async {
            let bus = Bus::start()?;
            let polkit = bus.connect().await?;
            polkit
                .object_server()
                .at(
                    "/org/freedesktop/PolicyKit1/Authority",
                    FakePolkit {
                        answer: Arc::new(Mutex::new(Answer::Yes)),
                        asked: Arc::default(),
                        requests: Arc::default(),
                        hold: Arc::default(),
                        hook: Arc::default(),
                    },
                )
                .await?;
            polkit.request_name("org.freedesktop.PolicyKit1").await?;
            let client = bus.connect().await?;
            Ok(Self {
                bus,
                _polkit: polkit,
                client,
                state: match state {
                    Some(s) => s,
                    None => tempfile::tempdir()?,
                },
            })
        })
    }

    /// Runs the start-up function on its own thread; the connection (or the reason) comes back on join.
    pub fn spawn(
        &self,
        sink: Arc<dyn AuditSink>,
    ) -> Res<JoinHandle<Result<Connection, StartError>>> {
        let store = Arc::new(KeyStore::open(self.root())?);
        let address = self.bus.address.clone();
        Ok(std::thread::spawn(move || {
            block_on(start(
                store,
                Builder::address(address.as_str()).build(),
                sink,
                Arc::new(MemoryCreds::host()),
                Arc::new(NoTpm),
            ))
        }))
    }

    /// Starts the service and waits for it to take the name.
    pub fn serve(&self, sink: Arc<dyn AuditSink>) -> Res<Connection> {
        self.spawn(sink)?
            .join()
            .map_err(|_| "the start-up thread panicked")?
            .map_err(Into::into)
    }

    pub async fn owner_of_name(&self) -> Result<bool, String> {
        let reply = self
            .client
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "NameHasOwner",
                &(custodiod::dbus::BUS_NAME,),
            )
            .await
            .map_err(|e| error_name(&e))?;
        reply
            .body()
            .deserialize::<bool>()
            .map_err(|e| e.to_string())
    }

    pub async fn listed(&self) -> Result<Vec<(String, String, String, Vec<u8>)>, String> {
        let reply = call(&self.client, "ListKeys", &())
            .await
            .map_err(|e| error_name(&e))?;
        reply.body().deserialize().map_err(|e| e.to_string())
    }
}

pub fn find_entries(sink: &MemorySink) -> Vec<(u32, String)> {
    sink.operation_entries()
        .iter()
        .map(|e| (e.owner().unwrap(), e.key_id().as_str().to_owned()))
        .collect()
}
