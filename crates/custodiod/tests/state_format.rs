//! The state format of the key store (F116), through the public API of the store: no D-Bus.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    // The helpers are shared by the test modules of this one target and panic on a broken setup.
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

#[path = "state_format/api.rs"]
mod api;
#[path = "state_format/concurrent.rs"]
mod concurrent;
#[path = "state_format/framing.rs"]
mod framing;
#[path = "state_format/legacy.rs"]
mod legacy;
#[path = "state_format/plaintext.rs"]
mod plaintext;
#[path = "state_format/reload.rs"]
mod reload;
#[path = "state_format/replace.rs"]
mod replace;
#[path = "state_format/rules.rs"]
mod rules;
#[path = "state_format/rules_files.rs"]
mod rules_files;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::seal;
use custodiod::import::{ParsedP12, parse_p12};
use custodiod::store::{KeyStore, Kind, Protected, Record};
use secrecy::{SecretSlice, SecretString};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The owner of the records the tests store.
pub const OWNER: u32 = 4242;

/// The P-256 key and certificate of the fixture.
pub fn fixture() -> ParsedP12 {
    let data = include_bytes!("fixtures/p256.p12");
    parse_p12(data, &SecretString::from("test-password".to_owned())).expect("the fixture parses")
}

/// A record of `kind` (an encrypted one) for `owner`'s `id`, made through a fake credential service.
pub fn encrypted(owner: u32, id: &str, kind: Kind, certificate: &[u8]) -> Record {
    let creds = match kind {
        Kind::EncryptedTpm => MemoryCreds::tpm(),
        _ => MemoryCreds::host(),
    };
    let key = SecretSlice::from(b"a-key-that-is-not-in-the-clear".to_vec());
    let sealed = seal(&creds, &format!("{owner}-{id}"), &key).expect("sealed");
    Record::new(
        owner,
        id,
        kind,
        certificate,
        Protected::from_sealed(&sealed),
    )
    .expect("a record")
}

pub fn host(id: &str, certificate: &[u8]) -> Record {
    encrypted(OWNER, id, Kind::EncryptedHost, certificate)
}

pub fn area(store: &KeyStore, owner: u32) -> PathBuf {
    store.dir().join(owner.to_string())
}

pub fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

pub fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A store in a fresh directory.
pub fn fresh() -> (tempfile::TempDir, KeyStore) {
    let tmp = tempfile::tempdir().unwrap();
    let store = KeyStore::open(tmp.path().join("state")).unwrap();
    (tmp, store)
}

/// Writes `bytes` as a file of mode `0600` and makes the area of `owner` if it is missing.
pub fn plant(store: &KeyStore, owner: u32, name: &str, bytes: &[u8]) -> PathBuf {
    let dir = area(store, owner);
    if !dir.exists() {
        fs::create_dir(&dir).unwrap();
        set_mode(&dir, 0o700);
    }
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    set_mode(&path, 0o600);
    path
}

/// The names in a directory, sorted.
pub fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}
