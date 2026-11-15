//! The service side shared by `snap_transport.rs` and `module_compat.rs` (F178): the real snap-socket service code
//! (`custodiod::snap_socket::handle`, with the `test-seam` source giving the Firefox label, uid `UID` and the test
//! process as the peer), a real key sealed in the store, a scripted polkit on a private `dbus-daemon`, and a counting
//! listener in front of it: every accepted connection is counted, and so is the end of each one (`handle` returns when
//! the peer has hung up). The "system bus" for the module is a double that counts connections and hangs up.

use std::collections::VecDeque;
use std::error::Error;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use custodiod::audit::{AuditSink, MemorySink};
use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::{Credentials, seal};
use custodiod::import::{credential_name, parse_p12};
use custodiod::polkit::PolkitAuthorizer;
use custodiod::snap_socket::peer::{Peer, Source};
use custodiod::snap_socket::{Service, Signing, handle};
use custodiod::store::{KeyStore, Kind, Protected, Record};
use custodiod::tpm::open::NoTpm;
use secrecy::SecretString;
use zbus::{Connection, block_on};

#[path = "../../../custodiod/tests/snap_socket_sign/polkit.rs"]
#[allow(
    dead_code,
    reason = "the scripted polkit is shared; each test binary uses part of it"
)]
pub mod polkit;
pub use polkit::{Answer, Call};

pub type TestResult = Result<(), Box<dyn Error>>;

pub const UID: u32 = 4001;
pub const P12: &[u8] = include_bytes!("../fixtures/p256-other.p12");
pub const CERT: &[u8] = include_bytes!("../fixtures/cert-p256-other.der");
const PASSWORD: &str = "test-password";

/// What a listener has seen: connections accepted, open now, the most open at once, and ended.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountState {
    pub accepted: usize,
    pub open: usize,
    pub max_open: usize,
    pub closed: usize,
}

#[derive(Default)]
pub struct Counts {
    state: Mutex<CountState>,
    changed: Condvar,
}

impl Counts {
    fn update(&self, f: impl FnOnce(&mut CountState)) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut state);
        self.changed.notify_all();
    }

    pub fn snapshot(&self) -> CountState {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Blocks on the condition that `closed` connections have ended, not on a sleep; fails after a deadline.
    pub fn wait_closed(&self, closed: usize) -> CountState {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while state.closed < closed {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "only {state:?} after the deadline");
            state = self
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        *state
    }
}

fn own_pidfd() -> Option<OwnedFd> {
    // SAFETY: `pidfd_open` takes a pid and flags and returns a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
    let fd = i32::try_from(fd).ok().filter(|fd| *fd >= 0)?;
    // SAFETY: the descriptor was just returned by the kernel and nothing else owns it.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn dir_mode(path: &Path, mode: u32) -> TestResult {
    Ok(std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(mode),
    )?)
}

/// A store with the key `ec` of `UID`, sealed under the in-memory credentials.
pub fn make_store() -> Result<(tempfile::TempDir, Arc<KeyStore>), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(KeyStore::open(dir.path().join("keys"))?);
    let parsed = parse_p12(P12, &SecretString::from(PASSWORD.to_owned()))?;
    let sealed = seal(
        &MemoryCreds::host(),
        &credential_name(UID, "ec"),
        &parsed.key,
    )?;
    store.put(&Record::new(
        UID,
        "ec",
        Kind::EncryptedHost,
        &parsed.certificate,
        Protected::from_sealed(&sealed),
    )?)?;
    Ok((dir, store))
}

pub struct Rig {
    pub base: tempfile::TempDir,
    _store: tempfile::TempDir,
    pub bus: PathBuf,
    bus_connections: Arc<AtomicUsize>,
    service: Service,
    /// The listener of the `snap.<name>` directory `start` made.
    pub counts: Arc<Counts>,
    calls: Arc<Mutex<Vec<Call>>>,
    script: Arc<Mutex<VecDeque<Answer>>>,
    _polkit_bus: polkit::Bus,
    _connections: Vec<Connection>,
}

impl Rig {
    /// `name`: the instance name the directory is made for; `mode` its permissions.
    pub fn start(name: &str, mode: u32) -> Result<Self, Box<dyn Error>> {
        let base = tempfile::tempdir()?;
        let (store_dir, store) = make_store()?;
        let polkit_bus = polkit::Bus::start()?;
        let script = Arc::new(Mutex::new(VecDeque::new()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::new(MemorySink::default());
        let (polkit_conn, service_conn) = block_on(async {
            let c = polkit_bus.connect().await?;
            c.object_server()
                .at(
                    "/org/freedesktop/PolicyKit1/Authority",
                    polkit::FakePolkit {
                        script: Arc::clone(&script),
                        calls: Arc::clone(&calls),
                        rule: None,
                    },
                )
                .await?;
            c.request_name("org.freedesktop.PolicyKit1").await?;
            Ok::<_, Box<dyn Error>>((c, polkit_bus.connect().await?))
        })?;
        let creds: Arc<dyn Credentials> = Arc::new(MemoryCreds::host());
        let signing = Signing {
            authorizer: Arc::new(PolkitAuthorizer::new(service_conn.clone())),
            sink: sink as Arc<dyn AuditSink>,
            key_creds: Some(creds),
            tpm: Arc::new(NoTpm),
        };
        let service = Service::new(store, Arc::new(|_| {}))
            .with_signing(signing)
            .with_source(Source::Injected(Arc::new(|_| Peer {
                uid: Some(UID),
                pid: Some(std::process::id()),
                pidfd: own_pidfd(),
                label: Some(b"snap.firefox.firefox (enforce)".to_vec()),
            })));
        let bus = base.path().join("bus");
        let bus_listener = UnixListener::bind(&bus)?;
        let bus_connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&bus_connections);
        thread::spawn(move || {
            // Counts and hangs up at once, so a client that reaches it fails instead of waiting.
            for stream in bus_listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let mut rig = Self {
            base,
            _store: store_dir,
            bus,
            bus_connections,
            service,
            counts: Arc::default(),
            calls,
            script,
            _polkit_bus: polkit_bus,
            _connections: vec![polkit_conn, service_conn],
        };
        rig.counts = rig.listen(&format!("snap.{name}"), mode)?;
        Ok(rig)
    }

    /// Serves the real service on `<base>/<rel>/custodio.sock`; the directory gets `mode`.
    pub fn listen(&self, rel: &str, mode: u32) -> Result<Arc<Counts>, Box<dyn Error>> {
        let dir = self.base.path().join(rel);
        std::fs::create_dir_all(&dir)?;
        dir_mode(&dir, mode)?;
        let listener = UnixListener::bind(dir.join("custodio.sock"))?;
        let counts = Arc::new(Counts::default());
        let (seen, service) = (Arc::clone(&counts), self.service.clone());
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                seen.update(|s| {
                    s.accepted += 1;
                    s.open += 1;
                    s.max_open = s.max_open.max(s.open);
                });
                let (seen, service) = (Arc::clone(&seen), service.clone());
                thread::spawn(move || {
                    handle(&stream, &service);
                    seen.update(|s| {
                        s.open -= 1;
                        s.closed += 1;
                    });
                });
            }
        });
        Ok(counts)
    }

    pub fn answers(&self, answers: &[Answer]) {
        self.script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(answers.iter().copied());
    }

    pub fn polkit_calls(&self) -> Vec<Call> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn bus_connections(&self) -> usize {
        self.bus_connections.load(Ordering::SeqCst)
    }
}
