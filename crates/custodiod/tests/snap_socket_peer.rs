//! The per-connection peer check and the peer-to-peer interface on the snap socket (F175). In process: a listener in
//! a tempdir, served by `serve`, a private p2p client per case. The kernel's values are replaced by the `test-seam`
//! source except in `real_peer_without_label`. Waits are on the connection, never a sleep.

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::seal;
use custodiod::dbus::{BUS_NAME, ListedKey, OBJECT_PATH};
use custodiod::snap_socket::peer::{OVERFLOW_UID, Peer, Refusal, Source, admit, decide};
use custodiod::snap_socket::{Outcome, Service, serve};
use custodiod::store::{KeyStore, Kind, Protected, Record};
use secrecy::SecretSlice;
use zbus::connection::{AuthMechanism, Builder};
use zbus::{Connection, block_on};

type TestResult = Result<(), Box<dyn Error>>;

const GOOD: &[u8] = b"snap.firefox.firefox (enforce)";
const CERT_A: &[u8] = include_bytes!("fixtures/cert-p256-other.der");
const CERT_B: &[u8] = include_bytes!("fixtures/cert-rsa2048-other.der");
const UID_A: u32 = 4001;
const UID_B: u32 = 4002;

/// What the seam supplies for the next connection.
#[derive(Clone)]
struct Creds {
    uid: Option<u32>,
    pidfd: bool,
    label: Option<Vec<u8>>,
}

fn creds(uid: u32, label: &[u8]) -> Creds {
    Creds {
        uid: Some(uid),
        pidfd: true,
        label: Some(label.to_vec()),
    }
}

fn null_fd() -> Result<OwnedFd, Box<dyn Error>> {
    Ok(File::open("/dev/null")?.into())
}

fn peer_of(c: &Creds) -> Peer {
    Peer {
        uid: c.uid,
        pid: c.uid.map(|_| 4242),
        pidfd: if c.pidfd { null_fd().ok() } else { None },
        label: c.label.clone(),
    }
}

/// Hex of the bytes of `text`, as `AUTH EXTERNAL` carries a uid.
fn hex_of(text: &str) -> String {
    use std::fmt::Write as _;
    text.bytes().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn put(store: &KeyStore, owner: u32, id: &str, cert: &[u8]) -> TestResult {
    let key = SecretSlice::from(b"a-key-that-is-not-in-the-clear".to_vec());
    let sealed = seal(&MemoryCreds::host(), &format!("{owner}-{id}"), &key)?;
    let record = Record::new(
        owner,
        id,
        Kind::EncryptedHost,
        cert,
        Protected::from_sealed(&sealed),
    )?;
    store.put(&record)?;
    Ok(())
}

struct Rig {
    _tmp: tempfile::TempDir,
    path: PathBuf,
    next: Arc<Mutex<Creds>>,
    log: Arc<Mutex<Vec<String>>>,
}

impl Rig {
    /// A served socket over a store with one key for `UID_A` ("a-key") and one for `UID_B` ("b-key"), whose
    /// connections get the credentials of `set`. `kernel` serves with no seam.
    fn start(kernel: bool) -> Result<Self, Box<dyn Error>> {
        let tmp = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(tmp.path().join("keys"))?);
        put(&store, UID_A, "a-key", CERT_A)?;
        put(&store, UID_B, "b-key", CERT_B)?;
        let path = tmp.path().join("custodio.sock");
        let listener = UnixListener::bind(&path)?;
        let next = Arc::new(Mutex::new(creds(UID_A, GOOD)));
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let mut service = Service::new(
            store,
            Arc::new(move |line| {
                sink.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(line.to_owned());
            }),
        );
        if !kernel {
            let next = Arc::clone(&next);
            service = service.with_source(Source::Injected(Arc::new(move |_| {
                peer_of(&next.lock().unwrap_or_else(PoisonError::into_inner))
            })));
        }
        // `/usr` is root-owned and root-writable only, so the directory check passes.
        let mut journal = Vec::new();
        let outcome = serve(
            "snap-firefox",
            listener,
            std::path::Path::new("/usr"),
            &mut journal,
            &service,
        );
        assert!(matches!(outcome, Outcome::Serving));
        Ok(Self {
            _tmp: tmp,
            path,
            next,
            log,
        })
    }

    fn set(&self, c: Creds) {
        *self.next.lock().unwrap_or_else(PoisonError::into_inner) = c;
    }

    fn lines(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// A stock p2p client (`ANONYMOUS`) calling `ListKeys`. A refused connection fails here, in the handshake, or
    /// at the call, as a closed connection; never as an error reply of the service.
    fn list(&self) -> Result<Vec<ListedKey>, zbus::Error> {
        let stream = UnixStream::connect(&self.path)?;
        block_on(async {
            let connection: Connection = Builder::unix_stream(stream)
                .p2p()
                .auth_mechanism(AuthMechanism::Anonymous)
                .build()
                .await?;
            let reply = connection
                .call_method(None::<&str>, OBJECT_PATH, Some(BUS_NAME), "ListKeys", &())
                .await?;
            reply.body().deserialize::<Vec<ListedKey>>()
        })
    }

    fn ids(&self) -> Result<Vec<String>, zbus::Error> {
        Ok(self.list()?.into_iter().map(|k| k.0).collect())
    }

    /// The connection is closed with no method answered.
    fn assert_closed(&self) -> TestResult {
        let err = self.list().err().ok_or("a refused peer got a reply")?;
        assert!(
            !matches!(err, zbus::Error::MethodError(..)),
            "an error reply means a method was answered: {err}"
        );
        Ok(())
    }
}

#[test]
fn own_keys_only() -> TestResult {
    let rig = Rig::start(false)?;
    rig.set(creds(UID_A, GOOD));
    let keys = rig.list()?;
    let [(id, kind, storage, cert)] = keys.as_slice() else {
        return Err("expected one key".into());
    };
    assert_eq!((id.as_str(), kind.as_str()), ("a-key", "ecdsa-p256"));
    assert_eq!(storage, "encrypted-host");
    assert_eq!(cert, CERT_A);
    rig.set(creds(UID_B, GOOD));
    assert_eq!(rig.ids()?, ["b-key"]);
    rig.set(creds(4003, GOOD));
    assert_eq!(rig.ids()?, Vec::<String>::new());
    Ok(())
}

#[test]
fn refused_labels() -> TestResult {
    let rig = Rig::start(false)?;
    // The control: the exact enforce label is accepted in the same harness.
    rig.set(creds(UID_A, GOOD));
    assert_eq!(rig.ids()?, ["a-key"]);
    for label in [
        &b"unconfined"[..],
        b"snap.other.app (enforce)",
        b"/usr/bin/foo (enforce)",
        b"snap.firefox.firefox (complain)",
        b"snap.firefox.firefox (enforce)//&unconfined",
        b"snap.firefox.firefox//child (enforce)",
        b"system_u:system_r:unconfined_t:s0",
    ] {
        rig.set(creds(UID_A, label));
        // The connection is closed (end of file or a failed handshake), not answered with an error reply.
        rig.assert_closed()?;
    }
    Ok(())
}

/// No pidfd, no label, the overflow uid, and a failed `SO_PEERCRED` read (a different input from the overflow uid).
#[test]
fn incomplete_credentials_are_refused() -> TestResult {
    let rig = Rig::start(false)?;
    for bad in [
        Creds {
            pidfd: false,
            ..creds(UID_A, GOOD)
        },
        Creds {
            label: None,
            ..creds(UID_A, GOOD)
        },
        creds(OVERFLOW_UID, GOOD),
        Creds {
            uid: None,
            ..creds(UID_A, GOOD)
        },
    ] {
        rig.set(bad);
        rig.assert_closed()?;
        rig.set(creds(UID_A, GOOD));
        assert_eq!(rig.ids()?, ["a-key"]);
    }
    Ok(())
}

/// Root comes only through the seam: this shows the decision has no uid 0 shortcut.
#[test]
fn root() -> TestResult {
    let rig = Rig::start(false)?;
    rig.set(creds(0, b"unconfined"));
    rig.assert_closed()?;
    rig.set(creds(0, GOOD));
    assert_eq!(rig.ids()?, Vec::<String>::new());
    Ok(())
}

#[test]
fn real_peer_without_label() -> TestResult {
    // The kernel's own values, no seam.
    let (a, _b) = UnixStream::pair()?;
    let read = Source::Kernel.read(&a);
    assert_eq!(read.uid, Some(rustix::process::getuid().as_raw()));
    assert!(read.pidfd.is_some());
    assert!(admit(&a, &Source::Kernel).is_err());
    // And served: the real peer is closed.
    let rig = Rig::start(true)?;
    rig.assert_closed()?;
    Ok(())
}

#[test]
fn claimed_uid_ignored() -> TestResult {
    let rig = Rig::start(false)?;
    rig.set(creds(UID_A, GOOD));
    let hex = hex_of(&UID_B.to_string());
    let mut raw = UnixStream::connect(&rig.path)?;
    raw.set_read_timeout(Some(Duration::from_secs(10)))?;
    raw.write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())?;
    let mut buf = [0u8; 64];
    let n = raw.read(&mut buf)?;
    assert!(buf.get(..n).is_some_and(|b| b.starts_with(b"REJECTED")));
    // An anonymous client still gets its kernel uid's keys, not B's.
    assert_eq!(rig.ids()?, ["a-key"]);
    Ok(())
}

#[test]
fn refusal_journal() -> TestResult {
    let rig = Rig::start(false)?;
    rig.set(creds(UID_A, b"secret-label-bytes (enforce)"));
    rig.assert_closed()?;
    let lines = rig.lines();
    assert_eq!(lines.len(), 1);
    for line in &lines {
        assert!(line.contains("refused"));
        assert!(line.contains("label"), "the line names the reason: {line}");
        assert!(!line.contains("secret-label-bytes"));
        assert!(!line.contains("a-key") && !line.contains("b-key"));
    }
    // An accepted connection journals nothing.
    let before = rig.lines().len();
    rig.set(creds(UID_A, GOOD));
    rig.ids()?;
    assert_eq!(rig.lines().len(), before);
    Ok(())
}

#[test]
fn bad_peer_then_good() -> TestResult {
    let rig = Rig::start(false)?;
    rig.set(creds(UID_A, b"unconfined"));
    rig.assert_closed()?;
    rig.set(creds(UID_A, GOOD));
    let mut garbage = UnixStream::connect(&rig.path)?;
    garbage.write_all(b"\xff\xfe not a handshake \0\0\r\n\r\n")?;
    drop(garbage);
    assert_eq!(rig.ids()?, ["a-key"]);
    Ok(())
}

/// The decision function alone: each input gives its own reason, and the uid is judged before the rest.
#[test]
fn decisions() {
    let reason = |c: &Creds| decide(peer_of(c)).err();
    assert_eq!(reason(&creds(UID_A, GOOD)), None);
    assert_eq!(
        reason(&Creds {
            uid: None,
            ..creds(UID_A, b"x")
        }),
        Some(Refusal::UnreadableUid)
    );
    assert_eq!(
        reason(&creds(OVERFLOW_UID, b"x")),
        Some(Refusal::OverflowUid)
    );
    assert_eq!(
        reason(&Creds {
            pidfd: false,
            label: None,
            ..creds(UID_A, GOOD)
        }),
        Some(Refusal::NoPidfd)
    );
    assert_eq!(
        reason(&Creds {
            label: None,
            ..creds(UID_A, GOOD)
        }),
        Some(Refusal::NoLabel)
    );
    assert!(matches!(
        reason(&creds(UID_A, b"unconfined")),
        Some(Refusal::Label(_))
    ));
    // Each reason has its own text, and none is empty.
    let texts: Vec<String> = [
        Refusal::UnreadableUid,
        Refusal::OverflowUid,
        Refusal::NoPidfd,
        Refusal::NoLabel,
        Refusal::Label(custodiod::peer_label::Refusal::Empty),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    for (i, a) in texts.iter().enumerate() {
        assert!(a.len() > 10);
        assert!(texts.iter().skip(i + 1).all(|b| a != b));
    }
    // A uid one off the overflow uid is a user.
    assert_eq!(reason(&creds(OVERFLOW_UID - 1, GOOD)), None);
    assert_eq!(reason(&creds(OVERFLOW_UID + 1, GOOD)), None);
}
