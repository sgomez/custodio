//! `DeleteKey` leaves exactly one journal entry once polkit has been asked, makes the key unusable
//! before the entry is submitted, removes the files only after that, and restores the key if the
//! entry cannot be submitted. Private bus, fake polkit, a sink that can fail, count and block.

// The shared helpers are used in full by the audit tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;
#[path = "delete_audit/concurrent.rs"]
mod concurrent;
#[allow(dead_code, unused_imports)]
#[path = "audit/deadline.rs"]
mod deadline;
#[path = "delete_audit/order.rs"]
mod order;
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
    ERROR_AUDIT_UNAVAILABLE, ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_INTERNAL, ERROR_INVALID_ARGS,
    ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED,
};
use custodiod::audit::{
    AuditError, AuditSink, Caller, Entry, MemorySink, Operation, OperationEntry,
};
use custodiod::credentials::BusCredentials;
use rsa::pkcs8::DecodePrivateKey;
use zbus::{Connection, block_on};

use bus::{Answer, Fixture, TestResult, call, error_name, sign};
use common::{CKM_RSA_PKCS, NoCredentials, PASSWORD, RSA_P12, digest, digest_info, uid};

/// A sink that records, and can be told to fail or to block the next delete entry.
#[derive(Default)]
struct TestSink {
    inner: MemorySink,
    fail: AtomicBool,
    /// Calls of `record_operation`, whether they failed or not.
    operation_attempts: AtomicUsize,
    /// Calls of `record` (the signing entries).
    sign_attempts: AtomicUsize,
    gate: Mutex<Option<Gate>>,
}

struct Gate {
    entered: Sender<()>,
    release: Receiver<()>,
}

impl TestSink {
    fn failing(&self, on: bool) {
        self.fail.store(on, Ordering::SeqCst);
    }

    /// The next `record_operation` stores its entry, announces it on the returned receiver and
    /// blocks until the returned sender is used.
    fn arm_gate(&self) -> (Receiver<()>, Sender<()>) {
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release) = std::sync::mpsc::channel();
        *self.gate.lock().unwrap_or_else(PoisonError::into_inner) = Some(Gate { entered, release });
        (entered_rx, release_tx)
    }

    fn attempts(&self) -> usize {
        self.operation_attempts.load(Ordering::SeqCst)
    }

    fn deleted(&self) -> usize {
        self.inner
            .operation_entries()
            .iter()
            .filter(|e| e.outcome_name() == "deleted")
            .count()
    }
}

impl AuditSink for TestSink {
    fn record(&self, entry: &Entry) -> Result<(), AuditError> {
        self.sign_attempts.fetch_add(1, Ordering::SeqCst);
        self.inner.record(entry)
    }

    fn record_operation(&self, entry: &OperationEntry) -> Result<(), AuditError> {
        self.operation_attempts.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuditError::Io(std::io::ErrorKind::Other));
        }
        self.inner.record_operation(entry)?;
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(gate) = gate {
            let _ = gate.entered.send(());
            let _ = gate.release.recv();
        }
        Ok(())
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

async fn listed(c: &Connection) -> Result<Vec<String>, Box<dyn Error>> {
    let keys: Vec<(String, String, Vec<u8>)> =
        call(c, "ListKeys", &()).await?.body().deserialize()?;
    Ok(keys.into_iter().map(|k| k.0).collect())
}

fn area(f: &Fixture) -> PathBuf {
    f.store_dir().join(uid().to_string())
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
        uid(),
        id,
        RSA_P12,
        &secrecy::SecretString::from(PASSWORD.to_owned()),
    )?;
    Ok(())
}

/// The polkit requests made under the delete action.
fn delete_asks(f: &Fixture) -> usize {
    f.requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|r| r.0 == custodiod::polkit::DELETE_ACTION_ID)
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
        operation: Operation::Delete,
        outcome,
        caller,
        key_id: "k".to_owned(),
    }
}

#[test]
fn delete_entry_per_outcome() -> TestResult {
    // (polkit answer, expected reply, expected outcome)
    let cases = [
        (Answer::Yes, Ok(()), "deleted"),
        (Answer::No, Err(ERROR_POLKIT_DENIED), "denied"),
        (Answer::Challenge, Err(ERROR_POLKIT_DENIED), "denied"),
        (
            Answer::Fail,
            Err(ERROR_AUTHORIZATION_UNAVAILABLE),
            "authorization_unavailable",
        ),
    ];
    block_on(async {
        for (answer, reply, outcome) in cases {
            let (f, sink) = start(answer).await?;
            put_rsa(&f, "k")?;
            let got = delete(&f.client, "k").await;
            assert_eq!(got, reply.map_err(str::to_owned), "{outcome}");
            let entries = sink.inner.operation_entries();
            assert_eq!(entries.len(), 1, "{outcome}");
            let first = entries.first().ok_or("no entry")?;
            assert_eq!(seen(first), expected(outcome, Some(me())), "{outcome}");
            assert_eq!(f.asked().len(), 1);
            assert_eq!(sink.attempts(), 1);
            assert_eq!(sink.sign_attempts.load(Ordering::SeqCst), 0);
            assert_eq!(
                snapshot(&area(&f)).is_ok_and(|s| s.is_empty()),
                reply.is_ok()
            );
        }
        Ok(())
    })
}

#[test]
fn delete_without_caller_leaves_unavailable_entry() -> TestResult {
    block_on(async {
        let sink = Arc::new(TestSink::default());
        let f = Fixture::start(Answer::Yes, |_: &Connection| NoCredentials, sink.clone()).await?;
        put_rsa(&f, "k")?;
        let before = snapshot(&area(&f))?;
        assert_eq!(
            delete(&f.client, "k").await,
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
            delete(&f.client, "k").await,
            Err(ERROR_AUDIT_UNAVAILABLE.to_owned())
        );
        assert_eq!(snapshot(&area(&f))?, before);
        Ok(())
    })
}

#[test]
fn delete_refusals_leave_no_entry() -> TestResult {
    block_on(async {
        let (f, sink) = start(Answer::Yes).await?;
        put_rsa(&f, "k")?;
        // Another uid's key with the id `other`.
        custodiod::import::import_p12(
            &f.store,
            uid() + 1,
            "other",
            RSA_P12,
            &secrecy::SecretString::from(PASSWORD.to_owned()),
        )?;
        for failing in [false, true] {
            sink.failing(failing);
            for (id, want) in [
                ("", ERROR_INVALID_ARGS),
                ("a b", ERROR_INVALID_ARGS),
                ("k-cert", ERROR_INVALID_ARGS),
                ("missing", ERROR_NO_SUCH_KEY),
                ("other", ERROR_NO_SUCH_KEY),
            ] {
                assert_eq!(
                    delete(&f.client, id).await,
                    Err(want.to_owned()),
                    "{id} failing={failing}"
                );
            }
        }
        assert_eq!(sink.attempts(), 0);
        assert_eq!(sink.inner.operation_entries().len(), 0);
        assert_eq!(f.asked().len(), 0);
        assert_eq!(snapshot(&area(&f))?.len(), 2);
        Ok(())
    })
}

#[test]
fn delete_failing_sink_restores_key() -> TestResult {
    block_on(async {
        let public = rsa_public()?;
        // approved, denied, unavailable: the reply is `AuditUnavailable` and the key is untouched.
        for (answer, outcome) in [
            (Answer::Yes, "deleted"),
            (Answer::No, "denied"),
            (Answer::Fail, "authorization_unavailable"),
        ] {
            let (f, sink) = start(answer).await?;
            put_rsa(&f, "k")?;
            let before = snapshot(&area(&f))?;
            sink.failing(true);
            assert_eq!(
                delete(&f.client, "k").await,
                Err(ERROR_AUDIT_UNAVAILABLE.to_owned()),
                "{outcome}"
            );
            assert_eq!(sink.attempts(), 1, "{outcome}");
            assert_eq!(sink.inner.operation_entries().len(), 0);
            assert_eq!(snapshot(&area(&f))?, before, "{outcome}");
            assert_eq!(listed(&f.client).await?, ["k"], "{outcome}");
            f.set_answer(Answer::Yes);
            let sig = sign_rsa(&f.client, "k").await?;
            verifies(&public, &sig)?;
            // The id is still taken after the restore.
            let again = call(&f.client, "ImportP12", &("k", RSA_P12.to_vec(), PASSWORD)).await;
            assert_eq!(
                again.map_err(|e| error_name(&e)).err(),
                Some(custodio_client::ERROR_KEY_ID_TAKEN.to_owned()),
                "{outcome}"
            );
            // Later, with a working sink, the delete succeeds with its one entry.
            sink.failing(false);
            delete(&f.client, "k").await?;
            assert_eq!(sink.inner.operation_entries().len(), 1, "{outcome}");
            assert_eq!(sink.deleted(), 1);
            assert_eq!(snapshot(&area(&f))?.len(), 0);
        }
        Ok(())
    })
}

#[test]
fn delete_removal_failure_keeps_key_unusable() -> TestResult {
    if running_as_root() {
        eprintln!("skipped: needs a user that mode bits bind");
        return Ok(());
    }
    block_on(async {
        // (i) only the certificate cannot be removed: it is replaced by a directory while polkit
        // answers, so the key file goes (first) and `k-cert` stays. (ii) neither can: the store
        // directory becomes read-only while polkit answers.
        for neither in [false, true] {
            let (f, sink) = start(Answer::Yes).await?;
            put_rsa(&f, "k")?;
            let dir = area(&f);
            let cert = dir.join("k-cert");
            let hook_dir = dir.clone();
            f.on_request(move || {
                if neither {
                    let _ = set_mode(&hook_dir, 0o500);
                } else {
                    let _ = fs::remove_file(&cert);
                    let _ = fs::create_dir(&cert);
                }
            });
            assert_eq!(
                delete(&f.client, "k").await,
                Err(ERROR_INTERNAL.to_owned()),
                "neither={neither}"
            );
            set_mode(&dir, 0o700)?;
            assert_eq!(sink.inner.operation_entries().len(), 1);
            assert_eq!(sink.deleted(), 1);
            assert_eq!(f.asked().len(), 1);
            assert_eq!(
                sign_rsa(&f.client, "k").await,
                Err(ERROR_NO_SUCH_KEY.to_owned())
            );
            assert_eq!(listed(&f.client).await?.len(), 0);
            // A second delete finds nothing and leaves no second entry.
            assert_eq!(
                delete(&f.client, "k").await,
                Err(ERROR_NO_SUCH_KEY.to_owned())
            );
            assert_eq!(sink.inner.operation_entries().len(), 1);
            assert_eq!(f.asked().len(), 1);
        }
        Ok(())
    })
}

#[test]
fn delete_entries_hold_no_secrets() -> TestResult {
    block_on(async {
        let key = custodiod::import::parse_p12(
            RSA_P12,
            &secrecy::SecretString::from(PASSWORD.to_owned()),
        )?;
        let secrets = [
            key.certificate.clone(),
            secrecy::ExposeSecret::expose_secret(&key.key).to_vec(),
            PASSWORD.as_bytes().to_vec(),
            digest(),
            digest_info(),
        ];
        // The scan can see a leak.
        let leaking = format!("x {}", scan::base64(&key.certificate, false, true));
        assert_ne!(scan::leaks(leaking.as_bytes(), &key.certificate).len(), 0);

        let mut texts = Vec::new();
        for (answer, fail) in [
            (Answer::Yes, false),
            (Answer::No, false),
            (Answer::Yes, true),
        ] {
            let (f, sink) = start(answer).await?;
            put_rsa(&f, "k")?;
            sink.failing(fail);
            let _ = delete(&f.client, "k").await;
            if fail {
                // Nothing recorded; the entry that would have been is built from the same parts.
                continue;
            }
            for e in sink.inner.operation_entries() {
                assert!(
                    e.fields()
                        .contains(&("CUSTODIO_APP_ID", "org.example.App".to_owned())),
                    "the scan sees the app-id"
                );
                texts.push(format!(
                    "{} {e:?} {} {} {:?} {:?}",
                    e.message(),
                    e.outcome_name(),
                    e.key_id().as_str(),
                    e.caller(),
                    e.operation()
                ));
            }
        }
        assert_eq!(texts.len(), 2);
        for text in &texts {
            for secret in &secrets {
                assert_eq!(scan::leaks(text.as_bytes(), secret), Vec::<&str>::new());
            }
        }
        Ok(())
    })
}

#[test]
fn journal_sink_datagram_for_delete() -> TestResult {
    use std::io::ErrorKind;
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;
    block_on(async {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("j.sock");
        let socket = UnixDatagram::bind(&path)?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        let f = Fixture::start(
            Answer::Yes,
            |c: &Connection| BusCredentials::new(c.clone()),
            Arc::new(custodiod::audit::JournalSink::new(&path)),
        )
        .await?;
        put_rsa(&f, "k")?;
        delete(&f.client, "k").await?;
        let mut buf = vec![0u8; 65536];
        let n = socket.recv(&mut buf)?;
        let text = String::from_utf8(buf.get(..n).ok_or("short")?.to_vec())?;
        let lines: Vec<&str> = text.lines().collect();
        for want in [
            format!("CUSTODIO_UID={}", uid()),
            format!("CUSTODIO_PID={}", std::process::id()),
            "CUSTODIO_KEY_ID=k".to_owned(),
            "CUSTODIO_OPERATION=delete".to_owned(),
            "CUSTODIO_OUTCOME=deleted".to_owned(),
            format!("MESSAGE_ID={}", Operation::Delete.message_id()),
        ] {
            assert!(lines.contains(&want.as_str()), "{want} in {lines:?}");
        }
        socket.set_nonblocking(true)?;
        let again = socket.recv(&mut buf).err().ok_or("a second datagram")?;
        assert_eq!(again.kind(), ErrorKind::WouldBlock);
        Ok(())
    })
}
