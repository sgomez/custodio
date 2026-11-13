#![no_main]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::seal;
use custodiod::snap_socket::peer::{Peer, Source};
use custodiod::snap_socket::{Service, handle};
use custodiod::store::{KeyStore, Kind, Protected, Record};
use libfuzzer_sys::fuzz_target;
use secrecy::SecretSlice;

const CERT: &[u8] = include_bytes!("../../tests/fixtures/cert-p256-other.der");

struct World {
    dir: tempfile::TempDir,
    service: Service,
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
        let service =
            Service::new(store, Arc::new(|_| {})).with_source(Source::Injected(Arc::new(|_| {
                Peer {
                    uid: Some(4001),
                    pid: Some(4242),
                    pidfd: std::fs::File::open("/dev/null").ok().map(Into::into),
                    label: Some(b"snap.firefox.firefox (enforce)".to_vec()),
                }
            })));
        World { dir, service }
    })
}

// A peer's bytes through the handshake and the dispatch. Without `Signing` every `Sign` fails closed, so no input
// reaches polkit or a key; the store must be the same afterwards.
fuzz_target!(|bytes: &[u8]| {
    let world = world();
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
});
