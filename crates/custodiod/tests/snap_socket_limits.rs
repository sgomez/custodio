//! The bounds of the snap socket (F177): connections, message size, handshake time, idle time and the rate of the
//! refusal lines. In process, with short time bounds; waits are on end of file or a reply, never a fixed sleep.

use std::error::Error;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::BorrowedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use custodiod::audit::{AuditSink, MemorySink};
use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::{Credentials, seal};
use custodiod::dbus::{BUS_NAME, MAX_SIGN_MESSAGE_LEN, OBJECT_PATH};
use custodiod::import::{credential_name, parse_p12};
use custodiod::polkit::{AuthError, BoxFuture, ProcessAuthorizer};
use custodiod::snap_socket::limits::{Limits, MAX_MESSAGE_LEN, RateLimit};
use custodiod::snap_socket::peer::{Peer, Source};
use custodiod::snap_socket::{Outcome, Service, Signing, serve};
use custodiod::store::{KeyStore, Kind, Protected, Record};
use custodiod::tpm::open::NoTpm;
use secrecy::SecretString;
use zbus::connection::{AuthMechanism, Builder};
use zbus::{Connection, block_on};

type TestResult = Result<(), Box<dyn Error>>;

const GOOD: &[u8] = b"snap.firefox.firefox (enforce)";
const UID: u32 = 4001;
/// Long enough to be sure a close did not come, short enough to fail fast.
const PATIENCE: Duration = Duration::from_secs(10);

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

fn own_pidfd() -> Option<std::os::fd::OwnedFd> {
    let pid = rustix::process::Pid::from_raw(i32::try_from(std::process::id()).ok()?)?;
    rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok()
}

struct Rig {
    sink: Arc<MemorySink>,
    _tmp: tempfile::TempDir,
    path: PathBuf,
    log: Arc<Mutex<Vec<String>>>,
    label: Arc<Mutex<Vec<u8>>>,
}

fn limits(connections: usize, handshake_ms: u64, idle_ms: u64) -> Limits {
    Limits {
        connections,
        message: 1024,
        handshake: Duration::from_millis(handshake_ms),
        idle: Duration::from_millis(idle_ms),
    }
}

impl Rig {
    fn start(limits: Limits, rate: RateLimit) -> Result<Self, Box<dyn Error>> {
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
        let listener = UnixListener::bind(&path)?;
        let log = Arc::new(Mutex::new(Vec::new()));
        let label = Arc::new(Mutex::new(GOOD.to_vec()));
        let sink = Arc::clone(&log);
        let seen = Arc::clone(&label);
        let audit = Arc::new(MemorySink::default());
        let creds: Arc<dyn Credentials> = Arc::new(MemoryCreds::host());
        let signing = Signing {
            authorizer: Arc::new(Counting(Arc::new(AtomicUsize::new(0)))),
            sink: Arc::clone(&audit) as Arc<dyn AuditSink>,
            key_creds: Some(creds),
            tpm: Arc::new(NoTpm),
        };
        let service = Service::new(
            store,
            Arc::new(move |line| {
                sink.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(line.to_owned());
            }),
        )
        .with_signing(signing)
        .with_limits(limits, rate)
        .with_source(Source::Injected(Arc::new(move |_| Peer {
            uid: Some(UID),
            pid: Some(std::process::id()),
            pidfd: own_pidfd(),
            label: Some(seen.lock().unwrap_or_else(PoisonError::into_inner).clone()),
        })));
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
            sink: audit,
            _tmp: tmp,
            path,
            log,
            label,
        })
    }

    fn lines(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn connect(&self) -> Result<UnixStream, Box<dyn Error>> {
        let stream = UnixStream::connect(&self.path)?;
        stream.set_read_timeout(Some(PATIENCE))?;
        Ok(stream)
    }

    /// A connection with the handshake done: the server's `OK` line was read.
    fn handshaken(&self) -> Result<UnixStream, Box<dyn Error>> {
        let mut stream = self.connect()?;
        stream.write_all(b"\0AUTH ANONYMOUS 74657374\r\n")?;
        let mut seen = Vec::new();
        let mut byte = [0_u8; 1];
        while !seen.starts_with(b"OK ") || !seen.ends_with(b"\n") {
            if stream.read(&mut byte)? == 0 {
                return Err(format!(
                    "closed in the handshake after {:?}",
                    String::from_utf8_lossy(&seen)
                )
                .into());
            }
            seen.push(byte[0]);
        }
        stream.write_all(b"BEGIN\r\n")?;
        Ok(stream)
    }

    /// A stock p2p client with the handshake done.
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

    fn list_on(connection: &Connection) -> Result<usize, Box<dyn Error>> {
        block_on(async {
            let reply = connection
                .call_method(None::<&str>, OBJECT_PATH, Some(BUS_NAME), "ListKeys", &())
                .await?;
            Ok(reply
                .body()
                .deserialize::<Vec<(String, String, String, Vec<u8>)>>()?
                .len())
        })
    }

    /// One `Sign` of a digest on `connection`; the signature's length.
    fn sign_on(connection: &Connection) -> Result<usize, Box<dyn Error>> {
        block_on(async {
            let reply = connection
                .call_method(
                    None::<&str>,
                    OBJECT_PATH,
                    Some(BUS_NAME),
                    "Sign",
                    &("k", 0x1041_u32, 0_u32, 0_u32, vec![7_u8; 32]),
                )
                .await?;
            Ok(reply.body().deserialize::<Vec<u8>>()?.len())
        })
    }

    fn list_count(&self) -> Result<usize, Box<dyn Error>> {
        Self::list_on(&self.client()?)
    }

    /// Retries until the server has room again (a closed connection frees its place asynchronously).
    fn list_when_room(&self) -> Result<usize, Box<dyn Error>> {
        let until = Instant::now() + PATIENCE;
        loop {
            match self.list_count() {
                Ok(n) => return Ok(n),
                Err(e) if Instant::now() < until => drop(e),
                Err(e) => return Err(e),
            }
        }
    }
}

/// Whether the server closed the connection, within `PATIENCE`; any bytes it sends first are read and dropped.
fn closed_within(stream: &mut UnixStream, bound: Duration) -> Result<Duration, Box<dyn Error>> {
    let start = Instant::now();
    let mut buf = [0_u8; 256];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Ok(start.elapsed()),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::ConnectionReset => return Ok(start.elapsed()),
            Err(e) => return Err(format!("not closed after {:?}: {e}", start.elapsed()).into()),
        }
        if start.elapsed() > bound {
            return Err("closed too late".into());
        }
    }
}

/// A fixed header of a method call that announces a body of `body` bytes and no header fields.
fn header(body: u32) -> Vec<u8> {
    let mut h = vec![b'l', 1, 0, 1];
    h.extend_from_slice(&body.to_le_bytes());
    h.extend_from_slice(&1_u32.to_le_bytes());
    h.extend_from_slice(&0_u32.to_le_bytes());
    h
}

#[test]
fn the_message_bound_is_not_above_the_buses() {
    const { assert!(MAX_MESSAGE_LEN <= MAX_SIGN_MESSAGE_LEN) };
    // The largest legal `Sign`: the longest id, three words and 1024 bytes of data, with a header of a client that
    // names every field. It must fit under the bound.
    let id = "i".repeat(59);
    let body = 4 + id.len() + 1 + 3 + 12 + 4 + 4 + 1024;
    let header_fields = 8 * 16;
    assert!(16 + header_fields + body + 8 <= MAX_MESSAGE_LEN);
}

#[test]
fn connection_bound_closes_the_extra() -> TestResult {
    let rig = Rig::start(
        limits(2, 5000, 60_000),
        RateLimit::new(100, Duration::from_secs(60)),
    )?;
    let first = rig.handshaken()?;
    let _second = rig.handshaken()?;
    let mut extra = rig.connect()?;
    closed_within(&mut extra, PATIENCE)?;
    drop(first);
    assert_eq!(rig.list_when_room()?, 1);
    Ok(())
}

#[test]
fn oversized_message_closes_only_that_connection() -> TestResult {
    let rig = Rig::start(
        limits(8, 5000, 60_000),
        RateLimit::new(100, Duration::from_secs(60)),
    )?;
    let mut big = rig.handshaken()?;
    let mut ok = rig.handshaken()?;
    // 16 + 0 + 1009 = 1025 bytes: one over the bound of 1024.
    big.write_all(&header(1009))?;
    closed_within(&mut big, PATIENCE)?;
    // The other peer's connection is still open: a message of exactly the bound is not answered with a close.
    ok.write_all(&header(1008))?;
    ok.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut buf = [0_u8; 1];
    let err = ok
        .read(&mut buf)
        .err()
        .ok_or("data on an idle connection")?;
    assert!(matches!(
        err.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut
    ));
    assert_eq!(rig.list_count()?, 1);
    Ok(())
}

#[test]
fn a_stalled_handshake_is_closed() -> TestResult {
    let rig = Rig::start(
        limits(8, 300, 60_000),
        RateLimit::new(100, Duration::from_secs(60)),
    )?;
    let mut silent = rig.connect()?;
    let mut half = rig.connect()?;
    half.write_all(b"\0AUTH ANON")?;
    let took = closed_within(&mut silent, PATIENCE)?;
    assert!(took >= Duration::from_millis(200), "{took:?}");
    closed_within(&mut half, PATIENCE)?;
    assert_eq!(rig.list_count()?, 1);
    Ok(())
}

#[test]
fn an_idle_connection_is_closed() -> TestResult {
    let rig = Rig::start(
        limits(8, 5000, 400),
        RateLimit::new(100, Duration::from_secs(60)),
    )?;
    let mut idle = rig.handshaken()?;
    let took = closed_within(&mut idle, PATIENCE)?;
    // The idle bound starts when the handshake ends, not at the handshake bound (5 s here).
    assert!(
        took >= Duration::from_millis(250) && took < Duration::from_secs(3),
        "{took:?}"
    );
    // One byte at a time does not hold the connection: closed within the bound from the start of the message.
    let mut slow = rig.handshaken()?;
    let start = Instant::now();
    let head = header(40);
    for byte in head.iter().take(10) {
        if slow.write_all(&[*byte]).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    closed_within(&mut slow, PATIENCE)?;
    assert!(
        start.elapsed() < Duration::from_millis(1500),
        "{:?}",
        start.elapsed()
    );
    Ok(())
}

#[test]
fn a_connection_that_keeps_calling_stays_open() -> TestResult {
    let rig = Rig::start(
        limits(8, 5000, 500),
        RateLimit::new(100, Duration::from_secs(60)),
    )?;
    let busy = rig.client()?;
    for _ in 0..8 {
        assert_eq!(Rig::list_on(&busy)?, 1);
        std::thread::sleep(Duration::from_millis(150));
    }
    Ok(())
}

#[test]
fn refusal_lines_are_bounded() -> TestResult {
    let rig = Rig::start(
        limits(8, 5000, 60_000),
        RateLimit::new(5, Duration::from_secs(3600)),
    )?;
    *rig.label.lock().unwrap_or_else(PoisonError::into_inner) = b"SECRET-LABEL-BYTES".to_vec();
    for _ in 0..300 {
        let mut refused = rig.connect()?;
        closed_within(&mut refused, PATIENCE)?;
    }
    let lines = rig.lines();
    assert_eq!(lines.len(), 5, "{lines:?}");
    assert!(lines.iter().all(|l| !l.contains("SECRET")));
    Ok(())
}

#[test]
fn a_flood_does_not_stop_a_peer_that_is_already_connected() -> TestResult {
    let rig = Rig::start(
        limits(4, 5000, 60_000),
        RateLimit::new(10, Duration::from_secs(60)),
    )?;
    // The second peer connects before the flood: one peer can use every slot, and `docs/api.md` says so.
    let kept = rig.client()?;
    let flood = (0..40)
        .map(|i| {
            let mut s = rig.connect()?;
            if i % 2 == 0 {
                let _ = s.write_all(&header(100_000));
            } else {
                let _ = s.write_all(b"garbage\r\n");
            }
            Ok(s)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    // The kept peer signs while the flood is open, and a new peer signs once the flood is gone.
    assert!(Rig::sign_on(&kept)? > 0);
    assert_eq!(Rig::list_on(&kept)?, 1);
    drop(flood);
    let later = {
        let until = Instant::now() + PATIENCE;
        loop {
            match rig.client() {
                Ok(c) if Rig::list_on(&c).is_ok() => break c,
                _ if Instant::now() < until => {}
                _ => return Err("no room after the flood".into()),
            }
        }
    };
    assert!(Rig::sign_on(&later)? > 0);
    // Every signature has its entry: the flood costs the audit log nothing (refusal lines go to the service log).
    assert_eq!(rig.sink.entries().len(), 2);
    assert!(rig.lines().len() <= 10);
    Ok(())
}
