//! What must never reach an entry, and the way to look for it: in `Debug`, in `message()`, in the fields and in the
//! datagram the `JournalSink` sends, raw, as hex and as base64.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::os::unix::net::UnixDatagram;

use custodiod::audit::{AuditSink, Entry, JournalSink, OperationEntry};

use crate::common::SENTINEL_PASSWORD;
use crate::scan::leaks;

/// The datagram the production sink sends for `fields`.
fn send(record: impl FnOnce(&JournalSink)) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.sock");
    let socket = UnixDatagram::bind(&path).unwrap();
    record(&JournalSink::new(&path));
    let mut buf = vec![0_u8; 64 * 1024];
    let n = socket.recv(&mut buf).unwrap();
    buf.truncate(n);
    buf
}

/// Everything an operation entry shows, as one list of texts.
fn shown_operation(e: &OperationEntry) -> Vec<Vec<u8>> {
    let datagram = send(|sink| sink.record_operation(e).unwrap());
    texts(
        format!("{e:?}"),
        e.message(),
        &e.fields()
            .into_iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>(),
        datagram,
    )
}

fn shown_sign(e: &Entry) -> Vec<Vec<u8>> {
    let datagram = send(|sink| sink.record(e).unwrap());
    texts(
        format!("{e:?}"),
        e.message(),
        &e.fields()
            .into_iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>(),
        datagram,
    )
}

fn texts(debug: String, message: String, fields: &[String], datagram: Vec<u8>) -> Vec<Vec<u8>> {
    vec![
        debug.into_bytes(),
        message.into_bytes(),
        fields.join("\n").into_bytes(),
        datagram,
    ]
}

/// What the rows plant: the `.p12`, its password, the key's DER, and the bytes of the stored record.
pub struct Secrets(pub Vec<(&'static str, Vec<u8>)>);

impl Secrets {
    pub fn new(p12: &[u8], pkcs8: Vec<u8>, record: Vec<Vec<u8>>) -> Self {
        let mut all = vec![
            ("p12", p12.to_vec()),
            ("password", SENTINEL_PASSWORD.as_bytes().to_vec()),
            ("key DER", pkcs8),
        ];
        all.extend(record.into_iter().map(|r| ("stored record", r)));
        Self(all)
    }
}

fn assert_none(shown: &[Vec<u8>], secrets: &Secrets, context: &str) {
    for text in shown {
        for (what, value) in &secrets.0 {
            assert_ne!(value.len(), 0, "{context}: empty {what}");
            let found = leaks(text, value);
            assert!(found.is_empty(), "{context}: {what} leaked as {found:?}");
        }
    }
}

pub fn assert_operation_clean(e: &OperationEntry, secrets: &Secrets, context: &str) {
    assert_none(&shown_operation(e), secrets, context);
}

pub fn assert_sign_clean(e: &Entry, secrets: &Secrets, context: &str) {
    assert_none(&shown_sign(e), secrets, context);
}

/// The scan finds what is there: a datagram that carries the password in any form is reported.
pub fn scan_finds_planted(secrets: &Secrets) {
    for (what, value) in &secrets.0 {
        for (form, bytes) in crate::scan::forms(value) {
            let mut text = b"MESSAGE=x\nCUSTODIO_CAUSE=".to_vec();
            text.extend_from_slice(&bytes);
            assert!(
                !leaks(&text, value).is_empty(),
                "{what} in form {form} is not found"
            );
        }
    }
}

/// Every row of this target checks each entry it reads with [`assert_operation_clean`] / [`assert_sign_clean`] against
/// the `.p12`, the password, the key's DER and the stored record. This is the control for that check: it finds what is
/// planted in every form, in the `Debug` text, in `message()`, in the fields and in the datagram, so a clean result
/// means something.
#[test]
fn no_secret_in_entries() {
    use custodiod::audit::{AuditKeyType, ImportOutcome, KeyId, OperationEntry};
    let secrets = Secrets::new(b"p12-sentinel-bytes", b"der-sentinel".to_vec(), vec![]);
    scan_finds_planted(&secrets);
    let entry = OperationEntry::import(
        ImportOutcome::Stored,
        None,
        KeyId::new("key-sentinel").unwrap(),
        Some(AuditKeyType::Rsa2048),
    );
    // The key id is the one free text of an entry: as a planted value it is found in all four places.
    let planted = Secrets(vec![("key id", b"key-sentinel".to_vec())]);
    for (n, shown) in shown_operation(&entry).iter().enumerate() {
        assert!(!leaks(shown, b"key-sentinel").is_empty(), "text {n}");
    }
    let caught = std::panic::catch_unwind(|| assert_operation_clean(&entry, &planted, "control"));
    assert!(caught.is_err(), "a planted value was not reported");
    // And an entry without it is clean.
    assert_operation_clean(&entry, &secrets, "clean");
}
