#![no_main]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::BorrowedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use custodiod::audit::{AuditSink, MemorySink};
use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::{Credentials, seal};
use custodiod::polkit::{AuthError, BoxFuture, ProcessAuthorizer};
use custodiod::snap_socket::peer::{Peer, Source};
use custodiod::snap_socket::{Service, Signing, handle};
use custodiod::store::{KeyStore, Kind, Protected, Record};
use custodiod::tpm::open::NoTpm;
use libfuzzer_sys::fuzz_target;
use secrecy::SecretSlice;

const CERT: &[u8] = include_bytes!("../../tests/fixtures/cert-p256-other.der");

/// A polkit that denies everything and counts the questions.
struct Counting(Arc<AtomicUsize>);

impl ProcessAuthorizer for Counting {
    fn authorize_process<'a>(
        &'a self,
        _pidfd: BorrowedFd<'a>,
        _uid: u32,
        _action: &'a str,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(AuthError::Unavailable("fuzz".to_owned())) })
    }
}

struct World {
    dir: tempfile::TempDir,
    service: Service,
    asked: Arc<AtomicUsize>,
}

fn files(dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, out);
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.insert(path, bytes);
        }
    }
}

fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(KeyStore::open(dir.path().join("keys")).expect("store"));
        let key = SecretSlice::from(b"a-key-that-is-not-in-the-clear".to_vec());
        let sealed = seal(&MemoryCreds::host(), "4001-k", &key).expect("seal");
        let record = Record::new(
            4001,
            "k",
            Kind::EncryptedHost,
            CERT,
            Protected::from_sealed(&sealed),
        )
        .expect("record");
        store.put(&record).expect("put");
        let asked = Arc::new(AtomicUsize::new(0));
        let creds: Arc<dyn Credentials> = Arc::new(MemoryCreds::host());
        let signing = Signing {
            authorizer: Arc::new(Counting(Arc::clone(&asked))),
            sink: Arc::new(MemorySink::default()) as Arc<dyn AuditSink>,
            key_creds: Some(creds),
            tpm: Arc::new(NoTpm),
        };
        let service = Service::new(store, Arc::new(|_| {}))
            .with_signing(signing)
            .with_source(Source::Injected(Arc::new(|_| Peer {
                uid: Some(4001),
                pid: Some(4242),
                pidfd: std::fs::File::open("/dev/null").ok().map(Into::into),
                label: Some(b"snap.firefox.firefox (enforce)".to_vec()),
            })));
        World {
            dir,
            service,
            asked,
        }
    })
}

// A peer's bytes through the handshake and the dispatch, with a counting polkit that denies: the store must be the
// same afterwards and, unless the input names `Sign`, polkit was not asked.
fuzz_target!(|bytes: &[u8]| {
    let world = world();
    let asked_before = world.asked.load(Ordering::SeqCst);
    let keys = world.dir.path().join("keys");
    let mut before = BTreeMap::new();
    files(&keys, &mut before);
    let Ok((server, mut client)) = UnixStream::pair() else {
        return;
    };
    let Ok(mut reader) = client.try_clone() else {
        return;
    };
    let drain = std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = reader.read_to_end(&mut sink);
    });
    // A pending write only ends when the server closes or reads: the server reads until the bounds or the hang-up.
    let _ = client.write_all(b"\0AUTH ANONYMOUS 74657374\r\nBEGIN\r\n");
    let _ = client.write_all(bytes);
    let _ = client.shutdown(std::net::Shutdown::Write);
    handle(&server, &world.service);
    drop(server);
    let _ = drain.join();
    let mut after = BTreeMap::new();
    files(&keys, &mut after);
    assert_eq!(before, after);
    // A polkit question needs a method call that names `Sign`; any other input must not reach polkit.
    if !bytes.windows(4).any(|w| w == b"Sign") {
        assert_eq!(world.asked.load(Ordering::SeqCst), asked_before);
    }
});
