//! The parent: the private bus, the fake polkit and the service.

use std::pin::Pin;

use zbus::export::futures_core::Stream;

use super::*;

struct Bus {
    child: Child,
    address: String,
}

impl Bus {
    fn start() -> Result<Self, Box<dyn Error>> {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()?;
        let mut address = String::new();
        BufReader::new(child.stdout.take().ok_or("no stdout")?).read_line(&mut address)?;
        Ok(Self {
            child,
            address: address.trim().to_owned(),
        })
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct FakePolkit {
    approve: Arc<AtomicBool>,
    asked: Arc<Mutex<Vec<String>>>,
}

#[interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl FakePolkit {
    // The `interface` macro needs owned argument types to deserialize the D-Bus message.
    #[allow(clippy::needless_pass_by_value)]
    fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedVariant>),
        action_id: String,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: String,
    ) -> (bool, bool, HashMap<String, String>) {
        let _ = (details, flags, cancellation_id);
        if let Ok(mut asked) = self.asked.lock() {
            asked.push(action_id);
        }
        let _ = subject;
        (self.approve.load(Ordering::SeqCst), false, HashMap::new())
    }
}

/// A `Sign` call as the service received it on the bus, seen by the monitor.
#[derive(Clone)]
pub(super) struct Recorded {
    pub(super) id: String,
    pub(super) mechanism: u32,
    pub(super) hash: u32,
    pub(super) salt_len: u32,
    pub(super) data: Vec<u8>,
    /// The whole message as it went over the wire.
    pub(super) raw: Vec<u8>,
}

/// Whether `msg` is a method call to the service, whatever the method.
fn is_service_call(msg: &zbus::Message) -> bool {
    let header = msg.header();
    header.message_type() == zbus::message::Type::MethodCall
        && header.destination().is_some_and(|d| d.as_str() == BUS_NAME)
}

fn record(msg: &zbus::Message) -> Option<Recorded> {
    let header = msg.header();
    let to_service = header.destination().is_some_and(|d| d.as_str() == BUS_NAME);
    let is_sign = header.member().is_some_and(|m| m.as_str() == "Sign");
    if header.message_type() != zbus::message::Type::MethodCall || !to_service || !is_sign {
        return None;
    }
    let (id, mechanism, hash, salt_len, data): (String, u32, u32, u32, Vec<u8>) =
        msg.body().deserialize().ok()?;
    Some(Recorded {
        id,
        mechanism,
        hash,
        salt_len,
        data,
        raw: msg.data().bytes().to_vec(),
    })
}

pub(super) struct Fixture {
    /// Every method call to the service, of any method.
    service_calls: Arc<AtomicUsize>,
    signs: Arc<Mutex<Vec<Recorded>>>,
    _bus: Bus,
    state: tempfile::TempDir,
    asked: Arc<Mutex<Vec<String>>>,
    approve: Arc<AtomicBool>,
    address: String,
}

impl Fixture {
    /// A bus with polkit, and, if `service`, the service holding an RSA and a P-256 key. They
    /// run on their own thread: the connections only make progress while a thread is inside
    /// `block_on`, and the test thread is busy waiting for the child process.
    pub(super) fn start(approve: bool, service: bool) -> Result<Self, Box<dyn Error>> {
        let bus = Bus::start()?;
        let asked = Arc::new(Mutex::new(Vec::new()));
        let state = tempfile::tempdir()?;
        let (ready, wait) = std::sync::mpsc::channel::<Result<(), String>>();
        let signs = Arc::new(Mutex::new(Vec::new()));
        let service_calls = Arc::new(AtomicUsize::new(0));
        let counter = service_calls.clone();
        let approve = Arc::new(AtomicBool::new(approve));
        let switch = approve.clone();
        let (address, path, log, recorded) = (
            bus.address.clone(),
            state.path().join("keys"),
            asked.clone(),
            signs.clone(),
        );
        std::thread::spawn(move || {
            let setup = async {
                let bus = Builder::address(address.as_str());
                let polkit = bus.build().await?;
                polkit
                    .object_server()
                    .at(
                        "/org/freedesktop/PolicyKit1/Authority",
                        FakePolkit {
                            approve: switch,
                            asked: log,
                        },
                    )
                    .await?;
                polkit.request_name("org.freedesktop.PolicyKit1").await?;
                let mut connections = vec![polkit];
                if service {
                    let store = Arc::new(KeyStore::open(path)?);
                    let password = SecretString::from(PASSWORD);
                    import_p12(&store, "rsa", RSA_P12, &password)?;
                    import_p12(&store, "ec", EC_P12, &password)?;
                    let conn = Builder::address(address.as_str()).build().await?;
                    conn.object_server()
                        .at(
                            OBJECT_PATH,
                            Custodio::new(store, PolkitAuthorizer::new(conn.clone())),
                        )
                        .await?;
                    conn.request_name(BUS_NAME).await?;
                    connections.push(conn);
                }
                // A second connection that sees every message on the bus, so what the service
                // receives is recorded as it went over the wire. Failing to become a monitor is
                // an error of the whole fixture.
                let monitor = Builder::address(address.as_str()).build().await?;
                let stream = zbus::MessageStream::from(&monitor);
                zbus::fdo::MonitoringProxy::new(&monitor)
                    .await?
                    .become_monitor(&[], 0)
                    .await?;
                connections.push(monitor);
                Ok::<_, Box<dyn Error>>((connections, stream))
            };
            block_on(async {
                match setup.await {
                    Ok((connections, mut stream)) => {
                        let _ = ready.send(Ok(()));
                        while let Some(Ok(msg)) =
                            std::future::poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await
                        {
                            if is_service_call(&msg) {
                                counter.fetch_add(1, Ordering::SeqCst);
                            }
                            if let (Some(sign), Ok(mut all)) = (record(&msg), recorded.lock()) {
                                all.push(sign);
                            }
                        }
                        drop(connections);
                    }
                    Err(e) => {
                        let _ = ready.send(Err(e.to_string()));
                    }
                }
            });
        });
        wait.recv()??;
        Ok(Self {
            address: bus.address.clone(),
            _bus: bus,
            signs,
            service_calls,
            state,
            asked,
            approve,
        })
    }

    pub(super) fn store(&self) -> Result<KeyStore, Box<dyn Error>> {
        Ok(KeyStore::open(self.state.path().join("keys"))?)
    }

    /// Makes polkit approve or refuse from now on.
    pub(super) fn approve(&self, yes: bool) {
        self.approve.store(yes, Ordering::SeqCst);
    }

    pub(super) fn asked(&self) -> usize {
        self.asked.lock().map(|a| a.len()).unwrap_or_default()
    }

    /// The number of method calls the service received, once it has stopped changing for 200 ms
    /// (the monitor runs on its own thread, so the last calls may still be on their way).
    pub(super) fn settled_service_calls(&self) -> usize {
        let mut last = self.service_calls.load(Ordering::SeqCst);
        let mut quiet = 0;
        while quiet < 2 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let now = self.service_calls.load(Ordering::SeqCst);
            quiet = if now == last { quiet + 1 } else { 0 };
            last = now;
        }
        last
    }

    /// The `Sign` calls the service received, once at least `expected` have been seen, plus a
    /// moment for any extra one; fails if fewer arrive.
    pub(super) fn signs(&self, expected: usize) -> Result<Vec<Recorded>, Box<dyn Error>> {
        let count = || self.signs.lock().map(|s| s.len()).unwrap_or_default();
        for _ in 0..100 {
            if count() >= expected {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        Ok(self.signs.lock().map_err(|_| "poisoned")?.clone())
    }

    /// Runs a child scenario; returns whether it passed and its stdout.
    pub(super) fn run(&self, mode: &str) -> Result<(bool, String), Box<dyn Error>> {
        let out = Command::new(std::env::current_exe()?)
            .args(["--exact", "client", "--nocapture", "--test-threads=1"])
            .env(MODE_VAR, mode)
            .env(MODULE_VAR, module_path()?)
            .env("DBUS_SYSTEM_BUS_ADDRESS", &self.address)
            .output()?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() {
            eprintln!("{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
        }
        Ok((out.status.success(), stdout))
    }
}

/// Builds the module (cargo does not build the `cdylib` of a package for its own tests) and
/// returns `target/<profile>/libcustodio_pkcs11.so`, next to the `deps` directory of this binary.
static BUILT: Once = Once::new();

fn module_path() -> Result<PathBuf, Box<dyn Error>> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .and_then(|d| d.parent())
        .ok_or("no target dir")?
        .to_path_buf();
    // Build into the target directory this binary lives in (`cargo llvm-cov` uses its own).
    let target = dir.parent().ok_or("no target dir")?.to_path_buf();
    BUILT.call_once(|| {
        let mut build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
        build.args(["build", "--quiet", "--locked", "-p", "custodio-pkcs11"]);
        build.arg("--target-dir").arg(&target);
        if !cfg!(debug_assertions) {
            build.arg("--release");
        }
        assert!(
            build.status().is_ok_and(|s| s.success()),
            "building the module failed"
        );
    });
    let path = dir.join("libcustodio_pkcs11.so");
    assert!(path.exists(), "{} was not built", path.display());
    Ok(path)
}
