//! `custodio list` on the documented API: the real service on a private `dbus-daemon`, a fake
//! polkit that counts its calls, and a credentials double that says which uid is calling.
//! Needs `dbus-daemon` (`/usr/bin/dbus-daemon` in the dev container); a missing one fails the tests.

use std::error::Error;
use std::io::{self, BufRead, BufReader};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use custodio_cli::bus::DbusImporter;
use custodio_cli::list::NO_KEYS;
use custodio_cli::{
    CliError, ImportArgs, ListFailure, PasswordPrompt, ServiceFailure, exit_status, finish,
    run_import, run_list,
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

type TestResult = Result<(), Box<dyn Error>>;

const P256_P12: &[u8] = include_bytes!("fixtures/p256.p12");
const P256_OTHER_P12: &[u8] = include_bytes!("fixtures/p256-other.p12");
const RSA2048_P12: &[u8] = include_bytes!("fixtures/rsa2048.p12");
const P256_RECERT: &[u8] = include_bytes!("fixtures/cert-p256-recert.der");
const PASSWORD: &str = "test-password";
const UID_A: u32 = 4001;
const UID_B: u32 = 4002;
const UID_C: u32 = 4003;

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
struct CountingPolkit(Arc<Mutex<Vec<String>>>);

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
type Seen = (String, String, String, String, String);

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

struct Rig {
    bus: Bus,
    client: DbusImporter,
    uid: Arc<AtomicU32>,
    broken: Arc<AtomicBool>,
    polkit: CountingPolkit,
    seen: Arc<Mutex<Vec<Seen>>>,
    dir: tempfile::TempDir,
    _connections: Vec<zbus::Connection>,
}

impl Rig {
    /// With `service` false nobody owns the service's bus name.
    fn start(service: bool) -> Result<Self, Box<dyn Error>> {
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

    fn as_uid(&self, uid: u32) {
        self.uid.store(uid, Ordering::SeqCst);
    }

    /// `custodio import` as the current uid.
    fn import(&self, id: &str, p12: &[u8]) -> TestResult {
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
    fn replace_certificate(&self, id: &str, der: &[u8]) -> TestResult {
        block_on(self.client_connection()?.call_method(
            Some(BUS_NAME),
            OBJECT_PATH,
            Some(BUS_NAME),
            "ReplaceCertificate",
            &(id, der),
        ))?;
        Ok(())
    }

    fn client_connection(&self) -> Result<zbus::Connection, Box<dyn Error>> {
        Ok(block_on(
            Builder::address(self.bus.address.as_str()).build(),
        )?)
    }

    fn polkit_calls(&self) -> usize {
        self.polkit
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Calls the monitor has recorded, once it has caught up with `at_least`.
    fn calls(&self, at_least: usize) -> Vec<Seen> {
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

    /// What the person sees: `run_list` and the diagnostic and status `main` derives from it.
    fn list(&self) -> Listed {
        let mut stdout = Vec::new();
        let result = run_list(&self.client, &mut stdout).map_err(CliError::List);
        let mut stderr = Vec::new();
        let status = finish(&result, &mut stderr);
        assert_eq!(status, exit_status(&result));
        Listed {
            result,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            status,
        }
    }
}

struct Typed;

impl PasswordPrompt for Typed {
    fn password(&mut self, _prompt: &str) -> io::Result<SecretString> {
        Ok(SecretString::from(PASSWORD))
    }
}

struct Listed {
    result: Result<(), CliError>,
    stdout: String,
    stderr: String,
    status: u8,
}

fn block(id: &str, kind: &str, subject: &str, until: &str) -> String {
    format!("id: {id}\n  type: {kind}\n  subject: {subject}\n  valid until: {until}\n")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[test]
fn several_keys_show_their_own_id_type_subject_and_end_of_validity() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("rsa", RSA2048_P12)?;
    rig.import("ec", P256_P12)?;
    // Another certificate for the same key: a different subject and a different end of validity.
    rig.replace_certificate("ec", P256_RECERT)?;
    let before = rig.polkit_calls();
    assert_eq!(before, 3, "the imports and the replace asked polkit");

    let listed = rig.list();
    assert!(listed.result.is_ok());
    assert_eq!(listed.status, 0);
    assert_eq!(listed.stderr, "");
    // Sorted by id; each key keeps its own subject and end of validity.
    assert_eq!(
        listed.stdout,
        block(
            "ec",
            "ecdsa-p256",
            "CN=custodio test p256-recert",
            "2126-10-08T20:52:07Z"
        ) + &block(
            "rsa",
            "rsa2048",
            "CN=custodio test rsa2048",
            "2126-10-03T16:05:48Z"
        )
    );
    assert!(!listed.stdout.contains(NO_KEYS));
    // Certificate bytes are read, never shown.
    assert!(!listed.stdout.contains(&hex(P256_RECERT)));
    assert!(!listed.stdout.contains(&hex(&P256_RECERT[..32])));
    // Asking again gives the same list, and polkit is never asked by `list`.
    assert_eq!(rig.list().stdout, listed.stdout);
    assert_eq!(rig.polkit_calls(), before);
    Ok(())
}

#[test]
fn no_keys_says_so_with_status_0_and_nothing_on_stderr() -> TestResult {
    let rig = Rig::start(true)?;
    let listed = rig.list();
    assert!(listed.result.is_ok());
    assert_eq!(listed.status, 0);
    assert_eq!(listed.stdout, format!("{NO_KEYS}\n"));
    assert_eq!(listed.stderr, "");
    assert_eq!(rig.polkit_calls(), 0);
    Ok(())
}

#[test]
fn a_service_error_shows_the_message_of_its_name_and_no_key_line() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("ec", P256_P12)?;
    let asked = rig.polkit_calls();
    // The caller cannot be identified: the service answers AuthorizationUnavailable, never a list.
    rig.broken.store(true, Ordering::SeqCst);
    let listed = rig.list();
    assert!(matches!(
        listed.result,
        Err(CliError::List(ListFailure::Service(
            ServiceFailure::AuthorizationUnavailable
        )))
    ));
    assert_eq!(listed.status, 1);
    assert_eq!(listed.stdout, "");
    assert!(
        listed
            .stderr
            .contains(&ServiceFailure::AuthorizationUnavailable.message())
    );
    assert!(!listed.stderr.contains("ec"));
    assert_eq!(rig.polkit_calls(), asked);
    Ok(())
}

#[test]
fn an_unavailable_service_is_status_1_with_the_cannot_talk_message() -> TestResult {
    let rig = Rig::start(false)?;
    let listed = rig.list();
    assert!(matches!(
        listed.result,
        Err(CliError::List(ListFailure::Service(
            ServiceFailure::ServiceAbsent
        )))
    ));
    assert_eq!(listed.status, 1);
    assert_eq!(listed.stdout, "");
    assert!(
        listed.stderr.contains("cannot talk to the service"),
        "{}",
        listed.stderr
    );
    Ok(())
}

#[test]
fn two_uids_see_only_their_own_keys_even_with_the_same_id() -> TestResult {
    let rig = Rig::start(true)?;
    rig.as_uid(UID_A);
    rig.import("shared", P256_P12)?;
    rig.import("only-a", RSA2048_P12)?;
    rig.as_uid(UID_B);
    rig.import("shared", P256_OTHER_P12)?;
    let asked = rig.polkit_calls();
    assert_eq!(asked, 3);

    rig.as_uid(UID_A);
    let a = rig.list();
    assert_eq!(
        a.stdout,
        block(
            "only-a",
            "rsa2048",
            "CN=custodio test rsa2048",
            "2126-10-03T16:05:48Z"
        ) + &block(
            "shared",
            "ecdsa-p256",
            "CN=custodio test p256",
            "2126-10-03T16:05:48Z"
        )
    );
    rig.as_uid(UID_B);
    let b = rig.list();
    assert_eq!(
        b.stdout,
        block(
            "shared",
            "ecdsa-p256",
            "CN=custodio test p256-other",
            "2126-10-03T16:05:48Z"
        )
    );
    assert!(!b.stdout.contains("only-a") && !b.stdout.contains("rsa2048"));
    assert!(!b.stdout.contains("CN=custodio test p256\n"));
    assert!(!a.stdout.contains("p256-other"));
    rig.as_uid(UID_C);
    let c = rig.list();
    assert_eq!(c.stdout, format!("{NO_KEYS}\n"));
    assert_eq!((a.status, b.status, c.status), (0, 0, 0));
    assert_eq!(
        rig.polkit_calls(),
        asked,
        "three lists asked polkit nothing"
    );
    Ok(())
}

#[test]
fn list_makes_exactly_one_call_list_keys_without_arguments() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("ec", P256_P12)?;
    let imports = rig.calls(1).len();
    let listed = rig.list();
    assert_eq!(listed.status, 0);
    let all = rig.calls(imports + 1);
    let calls: Vec<_> = all[imports..]
        .iter()
        .filter(|c| c.0 == BUS_NAME || c.3 == "ListKeys" || c.1 == OBJECT_PATH)
        .cloned()
        .collect();
    let want = (
        BUS_NAME.to_owned(),
        OBJECT_PATH.to_owned(),
        BUS_NAME.to_owned(),
        "ListKeys".to_owned(),
        String::new(),
    );
    assert_eq!(calls, [want]);
    // Nothing else of any kind went to polkit or the service during the list.
    assert_eq!(all.len(), imports + 1, "{:?}", &all[imports..]);
    Ok(())
}
