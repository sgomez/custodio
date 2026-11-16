//! The rig of the `list` and `list_view` tests: the real service on a private `dbus-daemon`, a fake
//! polkit that counts its calls, and a credentials double that says which uid is calling.
//! Needs `dbus-daemon` (`/usr/bin/dbus-daemon` in the dev container); a missing one fails the tests.
#![allow(
    dead_code,
    reason = "each test crate that includes the rig uses a different part of it"
)]

use std::error::Error;
use std::io::{self, BufRead, BufReader};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use custodio_cli::bus::DbusImporter;
use custodio_cli::{
    CliError, ImportArgs, PasswordPrompt, exit_status, finish, run_import, run_list, run_show,
};
use custodio_client::{BUS_NAME, OBJECT_PATH};
use custodiod::audit::Caller;
use custodiod::audit::MemorySink;
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
pub const P256_OTHER_P12: &[u8] = include_bytes!("../fixtures/p256-other.p12");
pub const RSA2048_P12: &[u8] = include_bytes!("../fixtures/rsa2048.p12");
pub const P256_HOSTILE: &[u8] = include_bytes!("../fixtures/cert-p256-other-hostile.der");
pub const P256_RECERT: &[u8] = include_bytes!("../fixtures/cert-p256-recert.der");
pub const PASSWORD: &str = "test-password";
pub const UID_A: u32 = 4001;
pub const UID_B: u32 = 4002;
pub const UID_C: u32 = 4003;

/// Says which uid calls, or that the caller cannot be identified.
#[derive(Clone)]
struct Switch {
    uid: Arc<AtomicU32>,
    broken: Arc<AtomicBool>,
}

impl CallerCredentials for Switch {
    fn credentials(
        &self,
        _: &str,
    ) -> impl Future<Output = Result<Caller, CredentialsError>> + Send {
        std::future::ready(if self.broken.load(Ordering::SeqCst) {
            Err(CredentialsError::Missing)
        } else {
            Ok(Caller {
                uid: self.uid.load(Ordering::SeqCst),
                pid: std::process::id(),
            })
        })
    }
}

#[derive(Clone, Default)]
pub struct CountingPolkit(Arc<Mutex<Vec<String>>>);

impl Authorizer for CountingPolkit {
    fn authorize(
        &self,
        _sender: &str,
        action: &str,
    ) -> impl Future<Output = Result<(), AuthError>> + Send {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(action.to_owned());
        std::future::ready(Ok(()))
    }
}

pub struct Bus {
    child: Child,
    pub address: String,
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

    fn client(&self) -> Result<DbusImporter, Box<dyn Error>> {
        Ok(DbusImporter::new(block_on(
            Builder::address(self.address.as_str()).build(),
        )?))
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What a monitor on the bus saw: (destination, path, interface, member, signature) of every
/// method call.
pub type Seen = (String, String, String, String, String);

fn monitor(address: &str, log: Arc<Mutex<Vec<Seen>>>) -> Result<zbus::Connection, Box<dyn Error>> {
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
    pub uid: Arc<AtomicU32>,
    pub broken: Arc<AtomicBool>,
    pub polkit: CountingPolkit,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub dir: tempfile::TempDir,
    pub _connections: Vec<zbus::Connection>,
}

impl Rig {
    /// With `service` false nobody owns the service's bus name.
    pub fn start(service: bool) -> Result<Self, Box<dyn Error>> {
        let bus = Bus::start()?;
        let dir = tempfile::tempdir()?;
        let uid = Arc::new(AtomicU32::new(UID_A));
        let broken = Arc::new(AtomicBool::new(false));
        let polkit = CountingPolkit::default();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut connections = vec![monitor(&bus.address, seen.clone())?];
        if service {
            let store = Arc::new(KeyStore::open(dir.path().join("state"))?);
            let credentials = Switch {
                uid: uid.clone(),
                broken: broken.clone(),
            };
            let polkit = polkit.clone();
            let address = bus.address.clone();
            connections.push(block_on(async {
                let conn = Builder::address(address.as_str()).build().await?;
                let object =
                    Custodio::new(store, polkit, credentials, Arc::new(MemorySink::default()))
                        .with_key_credentials(std::sync::Arc::new(
                            custodiod::creds::memory::MemoryCreds::host(),
                        ));
                conn.object_server().at(OBJECT_PATH, object).await?;
                conn.request_name(BUS_NAME).await?;
                Ok::<_, zbus::Error>(conn)
            })?);
        }
        let client = bus.client()?;
        Ok(Self {
            bus,
            client,
            uid,
            broken,
            polkit,
            seen,
            dir,
            _connections: connections,
        })
    }

    pub fn as_uid(&self, uid: u32) {
        self.uid.store(uid, Ordering::SeqCst);
    }

    /// `custodio import` as the current uid.
    pub fn import(&self, id: &str, p12: &[u8]) -> TestResult {
        let file = self.dir.path().join(format!("{id}.p12"));
        std::fs::write(&file, p12)?;
        let args = ImportArgs {
            file,
            id: id.to_owned(),
        };
        run_import(&args, &mut Typed, &self.client, &mut Vec::new())?;
        Ok(())
    }

    /// `ReplaceCertificate` as the current uid.
    pub fn replace_certificate(&self, id: &str, der: &[u8]) -> TestResult {
        block_on(self.client_connection()?.call_method(
            Some(BUS_NAME),
            OBJECT_PATH,
            Some(BUS_NAME),
            "ReplaceCertificate",
            &(id, der),
        ))?;
        Ok(())
    }

    pub fn client_connection(&self) -> Result<zbus::Connection, Box<dyn Error>> {
        Ok(block_on(
            Builder::address(self.bus.address.as_str()).build(),
        )?)
    }

    pub fn polkit_calls(&self) -> usize {
        self.polkit
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Calls the monitor has recorded, once it has caught up with `at_least`.
    pub fn calls(&self, at_least: usize) -> Vec<Seen> {
        for _ in 0..100 {
            if self
                .seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len()
                >= at_least
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What the person sees of `custodio list <id>`: `run_show` and the diagnostic and status `main` derives from it.
    pub fn show(&self, id: &str) -> Listed {
        let mut stdout = Vec::new();
        let result = run_show(&self.client, id, &mut stdout).map_err(CliError::List);
        let mut stderr = Vec::new();
        let status = finish(&result, &mut stderr, false);
        assert_eq!(status, exit_status(&result));
        Listed {
            result,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            status,
        }
    }

    /// What the person sees: `run_list` and the diagnostic and status `main` derives from it.
    pub fn list(&self) -> Listed {
        let mut stdout = Vec::new();
        let result = run_list(&self.client, &mut stdout).map_err(CliError::List);
        let mut stderr = Vec::new();
        let status = finish(&result, &mut stderr, false);
        assert_eq!(status, exit_status(&result));
        Listed {
            result,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            status,
        }
    }
}

pub struct Typed;

impl PasswordPrompt for Typed {
    fn password(&mut self, _prompt: &str) -> io::Result<SecretString> {
        Ok(SecretString::from(PASSWORD))
    }
}

pub struct Listed {
    pub result: Result<(), CliError>,
    pub stdout: String,
    pub stderr: String,
    pub status: u8,
}
