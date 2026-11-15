//! The `StateStorage` addition to the bus API and the start-up journal field (F180): the service computes the result
//! once at start, journals it, and the bus returns that value; it asks no polkit and changes nothing.
//! `snap_socket_surface` shows that the snap socket does not serve it.

use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use custodiod::audit::{AuditSink, JournalSink, MemorySink};
use custodiod::creds::memory::MemoryCreds;
use custodiod::dbus::{BUS_NAME, OBJECT_PATH};
use custodiod::import::import_p12;
use custodiod::startup::start;
use custodiod::storage::StateStorage;
use custodiod::store::KeyStore;
use custodiod::tpm::open::NoTpm;
use secrecy::SecretString;
use zbus::connection::Builder;
use zbus::{Connection, OwnedVariant, block_on, interface};

type TestResult = Result<(), Box<dyn Error>>;

const INTERFACE: &str = "com.rfirma.Custodio1";

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A fake polkit that approves and counts.
struct Polkit(Arc<AtomicUsize>);

#[interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl Polkit {
    // The `interface` macro needs owned arguments and a `&self` receiver.
    #[allow(clippy::needless_pass_by_value)]
    fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedVariant>),
        action_id: String,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: String,
    ) -> (bool, bool, HashMap<String, String>) {
        let _ = (subject, action_id, details, flags, cancellation_id);
        self.0.fetch_add(1, Ordering::SeqCst);
        (true, false, HashMap::new())
    }
}

/// The service started by `startup::start` on a private bus, with the classifier stubbed.
struct Rig {
    _daemon: Daemon,
    tmp: tempfile::TempDir,
    address: String,
    asked: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    sink: Arc<MemorySink>,
    store: Arc<KeyStore>,
    _service: Connection,
    _polkit: Connection,
}

fn daemon() -> Result<(Daemon, String), Box<dyn Error>> {
    let mut child = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut address = String::new();
    BufReader::new(child.stdout.take().ok_or("no stdout")?).read_line(&mut address)?;
    Ok((Daemon(child), address.trim().to_owned()))
}

impl Rig {
    fn start(result: StateStorage, journal: Option<&Path>) -> Result<Self, Box<dyn Error>> {
        let (daemon, address) = daemon()?;
        let tmp = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(tmp.path().join("keys"))?);
        let asked = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(MemorySink::default());
        let counted = Arc::clone(&calls);
        let journal_sink: Arc<dyn AuditSink> = match journal {
            Some(path) => Arc::new(JournalSink::new(path)),
            None => Arc::clone(&sink) as Arc<dyn AuditSink>,
        };
        let (polkit, service) = block_on(async {
            let polkit = Builder::address(address.as_str()).build().await?;
            polkit
                .object_server()
                .at(
                    "/org/freedesktop/PolicyKit1/Authority",
                    Polkit(Arc::clone(&asked)),
                )
                .await?;
            polkit.request_name("org.freedesktop.PolicyKit1").await?;
            let service = start(
                Arc::clone(&store),
                Builder::address(address.as_str()).build(),
                journal_sink,
                Arc::new(MemoryCreds::host()),
                Arc::new(NoTpm),
                move || {
                    // The classifier runs once; a second call fails the test.
                    assert_eq!(
                        counted.fetch_add(1, Ordering::SeqCst),
                        0,
                        "classified twice"
                    );
                    result
                },
            )
            .await?;
            Ok::<_, Box<dyn Error>>((polkit, service))
        })?;
        Ok(Self {
            _daemon: daemon,
            tmp,
            address,
            asked,
            calls,
            sink,
            store,
            _service: service,
            _polkit: polkit,
        })
    }

    fn client(&self) -> Result<Connection, Box<dyn Error>> {
        Ok(block_on(Builder::address(self.address.as_str()).build())?)
    }

    fn storage(&self) -> Result<(String, String), Box<dyn Error>> {
        let client = self.client()?;
        let reply = block_on(client.call_method(
            Some(BUS_NAME),
            OBJECT_PATH,
            Some(INTERFACE),
            "StateStorage",
            &(),
        ))?;
        let body = reply.body();
        Ok((body.signature().to_string(), body.deserialize::<String>()?))
    }

    fn snapshot(&self) -> Result<BTreeMap<PathBuf, Vec<u8>>, Box<dyn Error>> {
        fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) -> std::io::Result<()> {
            for entry in std::fs::read_dir(dir)? {
                let path = entry?.path();
                if path.is_dir() {
                    walk(&path, out)?;
                } else {
                    out.insert(path.clone(), std::fs::read(&path)?);
                }
            }
            Ok(())
        }
        let mut out = BTreeMap::new();
        walk(self.tmp.path(), &mut out)?;
        Ok(out)
    }
}

fn returns(result: StateStorage, wire: &str) -> TestResult {
    let rig = Rig::start(result, None)?;
    // Twice, to show the value is stored: the classifier stub fails on a second call.
    assert_eq!(rig.storage()?, ("s".to_owned(), wire.to_owned()));
    assert_eq!(rig.storage()?.1, wire);
    assert_eq!(rig.calls.load(Ordering::SeqCst), 1);
    assert_eq!(rig.sink.state_storage(), [result]);
    Ok(())
}

#[test]
fn bus_returns_encrypted() -> TestResult {
    returns(StateStorage::Encrypted, "encrypted")
}

#[test]
fn bus_returns_not_encrypted() -> TestResult {
    returns(StateStorage::NotEncrypted, "not-encrypted")
}

#[test]
fn bus_returns_unknown() -> TestResult {
    returns(StateStorage::Unknown, "unknown")
}

#[test]
fn bus_asks_no_polkit() -> TestResult {
    let rig = Rig::start(StateStorage::NotEncrypted, None)?;
    rig.storage()?;
    assert_eq!(rig.asked.load(Ordering::SeqCst), 0);
    // Control: a call that does ask polkit moves the counter (a signature of an imported key).
    import_p12(
        &rig.store,
        &MemoryCreds::host(),
        &NoTpm,
        rustix::process::geteuid().as_raw(),
        "ec",
        include_bytes!("fixtures/p256.p12"),
        &SecretString::from("test-password".to_owned()),
    )?;
    let client = rig.client()?;
    block_on(client.call_method(
        Some(BUS_NAME),
        OBJECT_PATH,
        Some(INTERFACE),
        "Sign",
        &("ec", 0x1041_u32, 0_u32, 0_u32, vec![7_u8; 32]),
    ))?;
    assert_eq!(rig.asked.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn bus_changes_no_state() -> TestResult {
    let rig = Rig::start(StateStorage::Unknown, None)?;
    let before = rig.snapshot()?;
    let entries = rig.sink.state_storage();
    rig.storage()?;
    rig.storage()?;
    assert_eq!(rig.snapshot()?, before);
    assert_eq!(rig.sink.state_storage(), entries);
    assert_eq!(rig.sink.entries(), []);
    assert_eq!(rig.sink.operation_entries(), []);
    Ok(())
}

#[test]
fn start_journals_storage_field() -> TestResult {
    for (result, wire, priority) in [
        (StateStorage::Encrypted, "encrypted", "6"),
        (StateStorage::NotEncrypted, "not-encrypted", "4"),
        (StateStorage::Unknown, "unknown", "4"),
    ] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal.sock");
        let socket = UnixDatagram::bind(&path)?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        let rig = Rig::start(result, Some(&path))?;
        let mut buf = vec![0_u8; 65536];
        let n = socket.recv(&mut buf)?;
        let text = String::from_utf8(buf.get(..n).ok_or("short")?.to_vec())?;
        assert!(
            text.contains(&format!("CUSTODIO_STATE_STORAGE={wire}\n")),
            "{text}"
        );
        assert!(text.contains(&format!("PRIORITY={priority}\n")), "{text}");
        assert!(text.contains("SYSLOG_IDENTIFIER=custodiod\n"), "{text}");
        assert!(
            text.contains("MESSAGE_ID=5b0d7a2e91c34f68b3e4a7d1c09f2e86\n"),
            "{text}"
        );
        // Written once.
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        assert!(socket.recv(&mut buf).is_err(), "a second datagram");
        assert_eq!(rig.calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[test]
fn start_survives_an_unwritable_journal() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (_daemon, address) = daemon()?;
    let store = Arc::new(KeyStore::open(dir.path().join("keys"))?);
    // No journal socket at the path.
    let sink: Arc<dyn AuditSink> = Arc::new(JournalSink::new(dir.path().join("none.sock")));
    let result = block_on(start(
        store,
        Builder::address(address.as_str()).build(),
        sink,
        Arc::new(MemoryCreds::host()),
        Arc::new(NoTpm),
        || StateStorage::Unknown,
    ));
    // The service runs and answers; only the entry is missing.
    let connection = result.map_err(|e| e.to_string())?;
    assert!(connection.unique_name().is_some());
    Ok(())
}
