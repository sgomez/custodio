//! The private bus, the fake polkit and the service of the `custodio delete` tests.

use std::error::Error;
use std::io::{self, BufRead, BufReader};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use custodio_cli::bus::DbusImporter;
use custodio_cli::{ImportArgs, KeyLister, PasswordPrompt, ServiceFailure, run_import};
use custodio_client::{BUS_NAME, OBJECT_PATH};
use custodiod::audit::{Caller, MemorySink};
use custodiod::credentials::{CallerCredentials, CredentialsError};
use custodiod::dbus::Custodio;
use custodiod::polkit::{AuthError, Authorizer};
use custodiod::store::KeyStore;
use secrecy::SecretString;
use zbus::connection::Builder;
use zbus::export::futures_core::Stream;
use zbus::{block_on, message::Type};

pub type TestResult = Result<(), Box<dyn Error>>;

pub const P256_P12: &[u8] = include_bytes!("../fixtures/p256.p12");
pub const PASSWORD: &str = "test-password";
pub const FREE_TEXT: &str = "SERVICE FREE TEXT";
pub const WAIT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy)]
pub enum Polkit {
    Approve,
    Deny,
}

#[derive(Clone)]
pub struct FakePolkit {
    pub mode: Arc<Mutex<Polkit>>,
    pub asked: Arc<Mutex<Vec<String>>>,
}

impl Authorizer for FakePolkit {
    fn authorize(
        &self,
        _sender: &str,
        action: &str,
    ) -> impl Future<Output = Result<(), AuthError>> + Send {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(action.to_owned());
        let mode = *self.mode.lock().unwrap_or_else(PoisonError::into_inner);
        std::future::ready(match mode {
            Polkit::Approve => Ok(()),
            Polkit::Deny => Err(AuthError::Denied),
        })
    }
}

/// The caller is always the same uid, or cannot be identified.
#[derive(Clone)]
pub struct Caller4001 {
    pub broken: Arc<AtomicBool>,
}

impl CallerCredentials for Caller4001 {
    fn credentials(
        &self,
        _: &str,
    ) -> impl Future<Output = Result<Caller, CredentialsError>> + Send {
        std::future::ready(if self.broken.load(Ordering::SeqCst) {
            Err(CredentialsError::Missing)
        } else {
            Ok(Caller {
                uid: 4001,
                pid: std::process::id(),
            })
        })
    }
}

pub struct Typed;

impl PasswordPrompt for Typed {
    fn password(&mut self, _prompt: &str) -> io::Result<SecretString> {
        Ok(SecretString::from(PASSWORD))
    }
}

pub struct Bus {
    pub child: Child,
    pub address: String,
}

impl Bus {
    pub fn start() -> Result<Self, Box<dyn Error>> {
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

/// (destination, path, interface, member, signature) of a method call seen on the bus.
pub type Seen = (String, String, String, String, String);

pub fn monitor(
    address: &str,
    log: Arc<Mutex<Vec<Seen>>>,
) -> Result<zbus::Connection, Box<dyn Error>> {
    let (conn, stream) = block_on(async {
        let conn = Builder::address(address).build().await?;
        let stream = zbus::MessageStream::from(&conn);
        zbus::fdo::MonitoringProxy::new(&conn)
            .await?
            .become_monitor(&[], 0)
            .await?;
        Ok::<_, zbus::Error>((conn, stream))
    })?;
    std::thread::spawn(move || {
        let mut stream = stream;
        block_on(async {
            while let Some(Ok(msg)) =
                std::future::poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await
            {
                let header = msg.header();
                if msg.message_type() != Type::MethodCall {
                    continue;
                }
                let text = |s: Option<String>| s.unwrap_or_default();
                let seen = (
                    text(header.destination().map(ToString::to_string)),
                    text(header.path().map(ToString::to_string)),
                    text(header.interface().map(ToString::to_string)),
                    text(header.member().map(ToString::to_string)),
                    msg.body().signature().to_string(),
                );
                log.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(seen);
            }
        });
    });
    Ok(conn)
}

pub struct Rig {
    pub bus: Bus,
    pub client: DbusImporter,
    pub mode: Arc<Mutex<Polkit>>,
    pub broken: Arc<AtomicBool>,
    pub polkit: Arc<Mutex<Vec<String>>>,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub dir: tempfile::TempDir,
    pub _connections: Vec<zbus::Connection>,
}

impl Rig {
    /// With `service` false nobody owns the service's bus name. Polkit approves until `polkit`.
    pub fn start(service: bool) -> Result<Self, Box<dyn Error>> {
        let bus = Bus::start()?;
        let dir = tempfile::tempdir()?;
        let mode = Arc::new(Mutex::new(Polkit::Approve));
        let broken = Arc::new(AtomicBool::new(false));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut connections = vec![monitor(&bus.address, seen.clone())?];
        if service {
            let store = Arc::new(KeyStore::open(dir.path().join("state"))?);
            let polkit = FakePolkit {
                mode: mode.clone(),
                asked: asked.clone(),
            };
            let credentials = Caller4001 {
                broken: broken.clone(),
            };
            let address = bus.address.clone();
            connections.push(block_on(async {
                let conn = Builder::address(address.as_str()).build().await?;
                let object =
                    Custodio::new(store, polkit, credentials, Arc::new(MemorySink::default()));
                conn.object_server().at(OBJECT_PATH, object).await?;
                conn.request_name(BUS_NAME).await?;
                Ok::<_, zbus::Error>(conn)
            })?);
        }
        let client = DbusImporter::new(block_on(Builder::address(bus.address.as_str()).build())?);
        Ok(Self {
            bus,
            client,
            mode,
            broken,
            polkit: asked,
            seen,
            dir,
            _connections: connections,
        })
    }

    pub fn polkit(&self, mode: Polkit) {
        *self.mode.lock().unwrap_or_else(PoisonError::into_inner) = mode;
    }

    pub fn import(&self, id: &str) -> TestResult {
        let file = self.dir.path().join(format!("{id}.p12"));
        std::fs::write(&file, P256_P12)?;
        let args = ImportArgs {
            file,
            id: id.to_owned(),
        };
        run_import(&args, &mut Typed, &self.client, &mut Vec::new())?;
        Ok(())
    }

    /// File names under the owners' directories of the service's state directory, sorted.
    pub fn files(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let mut names = Vec::new();
        for owner in std::fs::read_dir(self.dir.path().join("state"))? {
            for entry in std::fs::read_dir(owner?.path())? {
                names.push(entry?.file_name().to_string_lossy().into_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn keys(&self) -> Result<Vec<String>, ServiceFailure> {
        Ok(self.client.list_keys()?.into_iter().map(|k| k.id).collect())
    }

    /// Forgets the setup: calls and polkit questions so far.
    pub fn forget(&self) {
        std::thread::sleep(Duration::from_millis(300));
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.polkit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Method calls to the service seen since `forget`, as (path, interface, member, signature).
    pub fn service_calls(&self) -> Vec<(String, String, String, String)> {
        std::thread::sleep(Duration::from_millis(300));
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(dest, ..)| dest == BUS_NAME)
            .map(|(_, path, iface, member, sig)| {
                (path.clone(), iface.clone(), member.clone(), sig.clone())
            })
            .collect()
    }

    pub fn polkit_asked(&self) -> Vec<String> {
        self.polkit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
