//! What the snap socket serves (F177): `ListKeys` and `Sign` of `com.rfirma.Custodio1`, nothing else. Every other
//! method fails as the standard D-Bus error, writes no journal entry and changes nothing in the store.

use std::collections::BTreeMap;
use std::error::Error;
use std::os::fd::BorrowedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use custodiod::audit::{AuditSink, MemorySink};
use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::{Credentials, seal};
use custodiod::dbus::{BUS_NAME, OBJECT_PATH};
use custodiod::import::{credential_name, parse_p12};
use custodiod::polkit::{AuthError, BoxFuture, ProcessAuthorizer};
use custodiod::snap_socket::peer::{Peer, Source};
use custodiod::snap_socket::{Outcome, Service, Signing, serve};
use custodiod::store::{KeyStore, Kind, Protected, Record};
use custodiod::tpm::open::NoTpm;
use secrecy::SecretString;
use zbus::connection::{AuthMechanism, Builder};
use zbus::{Connection, block_on};

type TestResult = Result<(), Box<dyn Error>>;

const UID: u32 = 4001;

fn own_pidfd() -> Option<std::os::fd::OwnedFd> {
    let pid = rustix::process::Pid::from_raw(i32::try_from(std::process::id()).ok()?)?;
    rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok()
}

/// A polkit that approves everything and counts the questions.
struct Counting(Arc<AtomicUsize>);

impl ProcessAuthorizer for Counting {
    fn authorize_process<'a>(
        &'a self,
        _pidfd: BorrowedFd<'a>,
        _uid: u32,
        _action: &'a str,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

struct Rig {
    tmp: tempfile::TempDir,
    path: PathBuf,
    asked: Arc<AtomicUsize>,
    sink: Arc<MemorySink>,
}

impl Rig {
    fn start() -> Result<Self, Box<dyn Error>> {
        let tmp = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(tmp.path().join("keys"))?);
        let parsed = parse_p12(
            include_bytes!("fixtures/p256.p12"),
            &SecretString::from("test-password".to_owned()),
        )?;
        let sealed = seal(
            &MemoryCreds::host(),
            &credential_name(UID, "k"),
            &parsed.key,
        )?;
        store.put(&Record::new(
            UID,
            "k",
            Kind::EncryptedHost,
            &parsed.certificate,
            Protected::from_sealed(&sealed),
        )?)?;
        let path = tmp.path().join("custodio.sock");
        let asked = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(MemorySink::default());
        let creds: Arc<dyn Credentials> = Arc::new(MemoryCreds::host());
        let signing = Signing {
            authorizer: Arc::new(Counting(Arc::clone(&asked))),
            sink: Arc::clone(&sink) as Arc<dyn AuditSink>,
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
        let outcome = serve(
            "snap-firefox",
            UnixListener::bind(&path)?,
            Path::new("/usr"),
            &mut Vec::new(),
            &service,
        );
        assert!(matches!(outcome, Outcome::Serving));
        Ok(Self {
            tmp,
            path,
            asked,
            sink,
        })
    }

    fn client(&self) -> Result<Connection, Box<dyn Error>> {
        let stream = UnixStream::connect(&self.path)?;
        Ok(block_on(async {
            Builder::unix_stream(stream)
                .p2p()
                .auth_mechanism(AuthMechanism::Anonymous)
                .build()
                .await
        })?)
    }

    /// Every file under the key store with its bytes.
    fn store_snapshot(&self) -> Result<BTreeMap<PathBuf, Vec<u8>>, Box<dyn Error>> {
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
        walk(&self.tmp.path().join("keys"), &mut out)?;
        Ok(out)
    }
}

/// The name of the D-Bus error `method` on `interface` at `path` fails with.
fn error_of(
    connection: &Connection,
    path: &str,
    interface: &str,
    method: &str,
    body: &(impl zbus::export::serde::Serialize + zbus::zvariant::DynamicType),
) -> Result<String, Box<dyn Error>> {
    let reply = block_on(connection.call_method(None::<&str>, path, Some(interface), method, body));
    match reply {
        Err(error) => {
            // zbus renders the standard errors as `<name>: <message>`.
            let text = error.to_string();
            let name = text.split(':').next().unwrap_or_default().to_owned();
            Ok(name)
        }
        Ok(_) => Err(format!("{method} was served").into()),
    }
}

const UNKNOWN_METHOD: &str = "org.freedesktop.DBus.Error.UnknownMethod";
const UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject";
const UNKNOWN_INTERFACE: &str = "org.freedesktop.DBus.Error.UnknownInterface";

#[test]
fn other_methods_are_unknown() -> TestResult {
    let rig = Rig::start()?;
    let before = rig.store_snapshot()?;
    let connection = rig.client()?;
    let p12 = (vec![1_u8, 2, 3], "id", "password");
    let cases: [(&str, &str, &str, String); 8] = [
        (
            OBJECT_PATH,
            BUS_NAME,
            "ImportP12",
            error_of(&connection, OBJECT_PATH, BUS_NAME, "ImportP12", &p12)?,
        ),
        (
            OBJECT_PATH,
            BUS_NAME,
            "DeleteKey",
            error_of(&connection, OBJECT_PATH, BUS_NAME, "DeleteKey", &("k",))?,
        ),
        (
            OBJECT_PATH,
            BUS_NAME,
            "ReplaceCertificate",
            error_of(
                &connection,
                OBJECT_PATH,
                BUS_NAME,
                "ReplaceCertificate",
                &("k", vec![1_u8]),
            )?,
        ),
        (
            OBJECT_PATH,
            BUS_NAME,
            "NeverExisted",
            error_of(&connection, OBJECT_PATH, BUS_NAME, "NeverExisted", &())?,
        ),
        (
            OBJECT_PATH,
            BUS_NAME,
            "StateStorage",
            error_of(&connection, OBJECT_PATH, BUS_NAME, "StateStorage", &())?,
        ),
        (
            OBJECT_PATH,
            BUS_NAME,
            "StateStorageReason",
            error_of(
                &connection,
                OBJECT_PATH,
                BUS_NAME,
                "StateStorageReason",
                &(),
            )?,
        ),
        (
            OBJECT_PATH,
            "com.rfirma.Custodio2",
            "ListKeys",
            error_of(
                &connection,
                OBJECT_PATH,
                "com.rfirma.Custodio2",
                "ListKeys",
                &(),
            )?,
        ),
        (
            "/com/rfirma/Other",
            BUS_NAME,
            "ListKeys",
            error_of(&connection, "/com/rfirma/Other", BUS_NAME, "ListKeys", &())?,
        ),
    ];
    let expected = [
        UNKNOWN_METHOD,
        UNKNOWN_METHOD,
        UNKNOWN_METHOD,
        UNKNOWN_METHOD,
        UNKNOWN_METHOD,
        UNKNOWN_METHOD,
        UNKNOWN_INTERFACE,
        UNKNOWN_OBJECT,
    ];
    for ((.., got), want) in cases.iter().zip(expected) {
        assert_eq!(got, want, "{cases:?}");
    }
    assert_eq!(rig.store_snapshot()?, before);
    assert_eq!(rig.asked.load(Ordering::SeqCst), 0, "polkit was asked");
    assert!(rig.sink.entries().is_empty(), "a journal entry was written");
    // Negative control: the same harness sees the question and the entry after a real `Sign`.
    let _ = block_on(connection.call_method(
        None::<&str>,
        OBJECT_PATH,
        Some(BUS_NAME),
        "Sign",
        &("k", 0x1041_u32, 0_u32, 0_u32, vec![7_u8; 32]),
    ));
    assert_eq!(rig.asked.load(Ordering::SeqCst), 1);
    assert_eq!(rig.sink.entries().len(), 1);
    Ok(())
}

#[test]
fn introspection_lists_exactly_two() -> TestResult {
    let rig = Rig::start()?;
    let connection = rig.client()?;
    let reply = block_on(connection.call_method(
        None::<&str>,
        OBJECT_PATH,
        Some("org.freedesktop.DBus.Introspectable"),
        "Introspect",
        &(),
    ))?;
    let xml: String = reply.body().deserialize()?;
    let (_, after) = xml
        .split_once(&format!("<interface name=\"{BUS_NAME}\">"))
        .ok_or("no Custodio interface")?;
    let (section, _) = after.split_once("</interface>").ok_or("unterminated")?;
    let mut methods: Vec<&str> = section
        .lines()
        .filter_map(|l| l.trim().strip_prefix("<method name=\""))
        .filter_map(|l| l.split('"').next())
        .collect();
    methods.sort_unstable();
    assert_eq!(methods, ["ListKeys", "Sign"]);
    assert!(!section.contains("<property") && !section.contains("<signal"));
    // Negative control: the expected set with a write method added does not match.
    assert_ne!(methods, ["DeleteKey", "ListKeys", "Sign"]);
    Ok(())
}
