//! `ReplaceCertificate` leaves exactly one journal entry once polkit has been asked, stores the new
//! certificate before the entry is submitted, and puts the old one back if the entry cannot be
//! submitted. Private bus, fake polkit, a sink that can fail, count and block.

// The shared helpers are used in full by the audit tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;
#[path = "replace_audit/concurrent.rs"]
mod concurrent;
#[allow(dead_code, unused_imports)]
#[path = "audit/deadline.rs"]
mod deadline;
#[path = "replace_audit/failing.rs"]
mod failing;
#[path = "replace_audit/outputs.rs"]
mod outputs;
#[allow(dead_code, unused_imports)]
#[path = "audit/scan.rs"]
mod scan;

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};

use custodio_client::{
    ERROR_AUDIT_UNAVAILABLE, ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_CERTIFICATE_MISMATCH,
    ERROR_INTERNAL, ERROR_INVALID_ARGS, ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED,
};
use custodiod::audit::{
    AuditError, AuditSink, Caller, Entry, MemorySink, Operation, OperationEntry,
};
use custodiod::credentials::BusCredentials;
use rsa::pkcs8::DecodePrivateKey;
use zbus::{Connection, block_on};

use bus::{Answer, Fixture, TestResult, call, error_name, sign};
use common::{CKM_RSA_PKCS, NoCredentials, PASSWORD, RSA_P12, digest, digest_info, uid};

const NEW: &[u8] = include_bytes!("fixtures/cert-rsa2048-recert.der");
const NEWER: &[u8] = include_bytes!("fixtures/cert-rsa2048-expired.der");
const OTHER_KEY: &[u8] = include_bytes!("fixtures/cert-rsa2048-other.der");

/// A sink that records, and can be told to fail or to block the next operation entry.
#[derive(Default)]
struct TestSink {
    /// What was stored (entries that were accepted).
    inner: MemorySink,
    /// Every entry that was handed in, accepted or not.
    offered: MemorySink,
    fail: AtomicBool,
    operation_attempts: AtomicUsize,
    gate: Mutex<Option<Gate>>,
    /// A file whose bytes are read each time an entry is handed in.
    watch: Mutex<Option<PathBuf>>,
    watched: Mutex<Vec<Option<Vec<u8>>>>,
    /// Runs when the sink is about to fail.
    on_fail: Mutex<Option<Box<dyn Fn() + Send>>>,
}

struct Gate {
    entered: Sender<()>,
    release: Receiver<()>,
}

impl TestSink {
    fn failing(&self, on: bool) {
        self.fail.store(on, Ordering::SeqCst);
    }

    /// The next `record_operation` announces itself on the returned receiver and blocks until the
    /// returned sender is used; it then stores or fails as usual.
    fn arm_gate(&self) -> (Receiver<()>, Sender<()>) {
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release) = std::sync::mpsc::channel();
        *self.gate.lock().unwrap_or_else(PoisonError::into_inner) = Some(Gate { entered, release });
        (entered_rx, release_tx)
    }

    fn attempts(&self) -> usize {
        self.operation_attempts.load(Ordering::SeqCst)
    }

    fn replaced(&self) -> usize {
        self.inner
            .operation_entries()
            .iter()
            .filter(|e| e.outcome_name() == "replaced")
            .count()
    }

    fn watch(&self, path: PathBuf) {
        *self.watch.lock().unwrap_or_else(PoisonError::into_inner) = Some(path);
    }

    fn watched(&self) -> Vec<Option<Vec<u8>>> {
        self.watched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn on_fail(&self, hook: impl Fn() + Send + 'static) {
        *self.on_fail.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(hook));
    }
}

impl AuditSink for TestSink {
    fn record(&self, entry: &Entry) -> Result<(), AuditError> {
        self.inner.record(entry)
    }

    fn record_operation(&self, entry: &OperationEntry) -> Result<(), AuditError> {
        self.operation_attempts.fetch_add(1, Ordering::SeqCst);
        self.offered.record_operation(entry)?;
        let path = self
            .watch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(path) = path {
            let bytes = fs::read(path)
                .ok()
                .and_then(|b| custodiod::store::Record::decode(&b).ok())
                .map(|r| r.certificate().to_vec());
            self.watched
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(bytes);
        }
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(gate) = gate {
            let _ = gate.entered.send(());
            let _ = gate.release.recv();
        }
        if self.fail.load(Ordering::SeqCst) {
            if let Some(hook) = &*self.on_fail.lock().unwrap_or_else(PoisonError::into_inner) {
                hook();
            }
            return Err(AuditError::Io(std::io::ErrorKind::Other));
        }
        self.inner.record_operation(entry)
    }
}

async fn start(answer: Answer) -> Result<(Fixture, Arc<TestSink>), Box<dyn Error>> {
    let sink = Arc::new(TestSink::default());
    let f = Fixture::start_reading(
        answer,
        |c: &Connection| BusCredentials::new(c.clone()),
        sink.clone(),
    )
    .await?;
    Ok((f, sink))
}

async fn replace(c: &Connection, id: &str, cert: &[u8]) -> Result<(), String> {
    let body = (id, cert.to_vec());
    let pending = call(c, "ReplaceCertificate", &body);
    match deadline::within(std::time::Duration::from_secs(15), pending).await {
        Some(reply) => reply.map(|_| ()).map_err(|e| error_name(&e)),
        None => Err("ReplaceCertificate did not return".to_owned()),
    }
}

async fn delete(c: &Connection, id: &str) -> Result<(), String> {
    let body = (id,);
    let pending = call(c, "DeleteKey", &body);
    match deadline::within(std::time::Duration::from_secs(15), pending).await {
        Some(reply) => reply.map(|_| ()).map_err(|e| error_name(&e)),
        None => Err("DeleteKey did not return".to_owned()),
    }
}

async fn sign_rsa(c: &Connection, id: &str) -> Result<Vec<u8>, String> {
    sign(c, id, CKM_RSA_PKCS, &digest_info())
        .await
        .map_err(|e| error_name(&e))
}

type Listed = Vec<(String, String, Vec<u8>)>;

async fn listed(c: &Connection) -> Result<Listed, Box<dyn Error>> {
    Ok(call(c, "ListKeys", &()).await?.body().deserialize()?)
}

/// The certificate `ListKeys` shows for `id`.
async fn listed_cert(c: &Connection, id: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = listed(c).await?.into_iter().find(|k| k.0 == id);
    Ok(key.ok_or("key not listed")?.2)
}

fn area(f: &Fixture) -> PathBuf {
    f.store_dir().join(uid().to_string())
}

fn record_path(f: &Fixture, id: &str) -> PathBuf {
    area(f).join(id)
}

/// The certificate in the record of `id`.
fn cert_of(f: &Fixture, id: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let record = custodiod::store::Record::decode(&fs::read(record_path(f, id))?)?;
    Ok(record.certificate().to_vec())
}

/// Every file of `dir` with its bytes, sorted by name.
fn snapshot(dir: &Path) -> Result<Vec<(String, Vec<u8>)>, std::io::Error> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let bytes = if entry.path().is_dir() {
            Vec::new()
        } else {
            fs::read(entry.path())?
        };
        out.push((entry.file_name().to_string_lossy().into_owned(), bytes));
    }
    out.sort();
    Ok(out)
}

fn me() -> Caller {
    Caller {
        uid: uid(),
        pid: std::process::id(),
    }
}

/// An RSA key under the test process's uid, so a signature can be checked against its public key.
fn put_rsa(f: &Fixture, id: &str) -> TestResult {
    custodiod::import::import_p12(
        &f.store,
        &custodiod::creds::memory::MemoryCreds::host(),
        &custodiod::tpm::open::NoTpm,
        uid(),
        id,
        RSA_P12,
        &secrecy::SecretString::from(PASSWORD.to_owned()),
    )?;
    Ok(())
}

/// The polkit requests made under the replace action.
fn replace_asks(f: &Fixture) -> usize {
    f.requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|r| r.0 == custodiod::polkit::REPLACE_ACTION_ID)
        .count()
}

fn rsa_public() -> Result<rsa::RsaPublicKey, Box<dyn Error>> {
    let key =
        custodiod::import::parse_p12(RSA_P12, &secrecy::SecretString::from(PASSWORD.to_owned()))?
            .key;
    Ok(
        rsa::RsaPrivateKey::from_pkcs8_der(secrecy::ExposeSecret::expose_secret(&key))?
            .to_public_key(),
    )
}

fn verifies(public: &rsa::RsaPublicKey, sig: &[u8]) -> TestResult {
    public.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &digest(), sig)?;
    Ok(())
}

fn running_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

fn set_mode(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// What an entry says, in plain values.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    operation: Operation,
    outcome: &'static str,
    caller: Option<Caller>,
    key_id: String,
}

fn seen(e: &OperationEntry) -> Seen {
    Seen {
        operation: e.operation(),
        outcome: e.outcome_name(),
        caller: e.caller(),
        key_id: e.key_id().as_str().to_owned(),
    }
}

fn expected(outcome: &'static str, caller: Option<Caller>) -> Seen {
    Seen {
        operation: Operation::ReplaceCertificate,
        outcome,
        caller,
        key_id: "k".to_owned(),
    }
}

/// How a polkit double and a certificate are made to give one outcome.
enum Make {
    Plain,
    /// The area is made unwritable while polkit answers (after the lookup).
    UnwritableArea,
    /// The record becomes a directory while polkit answers.
    RecordIsDirectory,
}

impl Make {
    fn arm(&self, f: &Fixture) {
        let dir = area(f);
        let record = record_path(f, "k");
        match self {
            Self::Plain => {}
            Self::UnwritableArea => f.on_request(move || {
                let _ = set_mode(&dir, 0o500);
            }),
            Self::RecordIsDirectory => f.on_request(move || {
                let _ = fs::remove_file(&record);
                let _ = fs::create_dir(&record);
            }),
        }
    }
}

type Case = (
    Answer,
    &'static [u8],
    Make,
    Result<(), &'static str>,
    &'static str,
);

/// Polkit answer, certificate, how the store is made to fail, expected reply, expected outcome.
fn cases() -> Vec<Case> {
    vec![
        (Answer::Yes, NEW, Make::Plain, Ok(()), "replaced"),
        (
            Answer::No,
            NEW,
            Make::Plain,
            Err(ERROR_POLKIT_DENIED),
            "denied",
        ),
        (
            Answer::Challenge,
            NEW,
            Make::Plain,
            Err(ERROR_POLKIT_DENIED),
            "denied",
        ),
        (
            Answer::Fail,
            NEW,
            Make::Plain,
            Err(ERROR_AUTHORIZATION_UNAVAILABLE),
            "authorization_unavailable",
        ),
        (
            Answer::Yes,
            OTHER_KEY,
            Make::Plain,
            Err(ERROR_CERTIFICATE_MISMATCH),
            "certificate_mismatch",
        ),
        (
            Answer::Yes,
            NEW,
            Make::UnwritableArea,
            Err(ERROR_INTERNAL),
            "storage_failure",
        ),
        (
            Answer::Yes,
            NEW,
            Make::RecordIsDirectory,
            Err(ERROR_INTERNAL),
            "storage_failure",
        ),
    ]
}

#[test]
fn replace_entry_per_outcome() -> TestResult {
    block_on(async {
        for (answer, cert, make, reply, outcome) in cases() {
            if !matches!(make, Make::Plain) && running_as_root() {
                eprintln!("skipped {outcome}: needs a user that mode bits bind");
                continue;
            }
            let (f, sink) = start(answer).await?;
            put_rsa(&f, "k")?;
            let before = cert_of(&f, "k")?;
            make.arm(&f);
            let got = replace(&f.client, "k", cert).await;
            set_mode(&area(&f), 0o700)?;
            assert_eq!(got, reply.map_err(str::to_owned), "{outcome}");
            let entries = sink.inner.operation_entries();
            assert_eq!(entries.len(), 1, "{outcome}");
            let first = entries.first().ok_or("no entry")?;
            assert_eq!(seen(first), expected(outcome, Some(me())), "{outcome}");
            assert_eq!(f.asked().len(), 1, "{outcome}");
            assert_eq!(replace_asks(&f), 1, "{outcome}");
            assert_eq!(sink.attempts(), 1, "{outcome}");
            if outcome == "replaced" {
                assert_eq!(cert_of(&f, "k")?, cert);
            } else if !matches!(make, Make::RecordIsDirectory) {
                assert_eq!(cert_of(&f, "k")?, before, "{outcome}");
            }
        }
        Ok(())
    })
}

#[test]
fn replace_without_caller_leaves_unavailable_entry() -> TestResult {
    block_on(async {
        let sink = Arc::new(TestSink::default());
        let f = Fixture::start(Answer::Yes, |_: &Connection| NoCredentials, sink.clone()).await?;
        put_rsa(&f, "k")?;
        let before = snapshot(&area(&f))?;
        assert_eq!(
            replace(&f.client, "k", NEW).await,
            Err(ERROR_AUTHORIZATION_UNAVAILABLE.to_owned())
        );
        let entries = sink.inner.operation_entries();
        assert_eq!(entries.len(), 1);
        let first = entries.first().ok_or("no entry")?;
        assert_eq!(seen(first), expected("authorization_unavailable", None));
        assert_eq!(f.asked().len(), 0);
        assert_eq!(snapshot(&area(&f))?, before);
        // With the failing sink the reply is the audit error.
        sink.failing(true);
        assert_eq!(
            replace(&f.client, "k", NEW).await,
            Err(ERROR_AUDIT_UNAVAILABLE.to_owned())
        );
        assert_eq!(snapshot(&area(&f))?, before);
        Ok(())
    })
}

#[test]
fn replace_refusals_leave_no_entry() -> TestResult {
    {
        let (f, sink) = block_on(start(Answer::Yes))?;
        put_rsa(&f, "k")?;
        put_rsa(&f, "gone")?;
        // Another uid's key with the id `other`.
        custodiod::import::import_p12(
            &f.store,
            &custodiod::creds::memory::MemoryCreds::host(),
            &custodiod::tpm::open::NoTpm,
            uid() + 1,
            "other",
            RSA_P12,
            &secrecy::SecretString::from(PASSWORD.to_owned()),
        )?;
        let mut oversized = NEW.to_vec();
        oversized.resize(custodio_client::MAX_CERT_LEN + 1, 0);
        let mut trailing = NEW.to_vec();
        trailing.push(0);
        let before = snapshot(&area(&f))?;
        for failing in [false, true] {
            sink.failing(failing);
            for (id, cert, want) in [
                ("", NEW, ERROR_INVALID_ARGS),
                ("a b", NEW, ERROR_INVALID_ARGS),
                ("k-cert", NEW, ERROR_INVALID_ARGS),
                ("k", &oversized[..], ERROR_INVALID_ARGS),
                ("k", b"junk", ERROR_INVALID_ARGS),
                ("k", &trailing[..], ERROR_INVALID_ARGS),
                ("missing", NEW, ERROR_NO_SUCH_KEY),
                ("other", NEW, ERROR_NO_SUCH_KEY),
            ] {
                assert_eq!(
                    block_on(replace(&f.client, id, cert)),
                    Err(want.to_owned()),
                    "{id} failing={failing}"
                );
            }
        }
        // A key a pending delete made unusable: the delete's entry is held in the sink.
        sink.failing(false);
        let (entered, release) = sink.arm_gate();
        let c = f.client.clone();
        let pending = std::thread::spawn(move || block_on(delete(&c, "gone")));
        if entered
            .recv_timeout(std::time::Duration::from_secs(10))
            .is_err()
        {
            return Err(format!("no entry: {:?}", pending.join()).into());
        }
        let delete_attempts = sink.attempts();
        let delete_asks = f.asked().len();
        for failing in [false, true] {
            sink.failing(failing);
            assert_eq!(
                block_on(replace(&f.client, "gone", NEW)),
                Err(ERROR_NO_SUCH_KEY.to_owned()),
                "failing={failing}"
            );
        }
        assert_eq!(sink.attempts(), delete_attempts);
        assert_eq!(f.asked().len(), delete_asks);
        sink.failing(false);
        release.send(())?;
        pending.join().map_err(|_| "panic")??;
        assert_eq!(replace_asks(&f), 0);
        let replaced = sink
            .inner
            .operation_entries()
            .iter()
            .filter(|e| e.operation() == Operation::ReplaceCertificate)
            .count();
        assert_eq!(replaced, 0);
        let after = snapshot(&area(&f))?;
        assert_eq!(after.iter().filter(|e| e.0 == "k").count(), 1);
        assert_eq!(
            after
                .into_iter()
                .filter(|e| e.0.starts_with('k'))
                .collect::<Vec<_>>(),
            before
                .into_iter()
                .filter(|e| e.0.starts_with('k'))
                .collect::<Vec<_>>()
        );
        Ok(())
    }
}
