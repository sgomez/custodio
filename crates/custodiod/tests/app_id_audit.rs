//! The journal entries of sign, import, delete and replace certificate name the flatpak app-id case
//! of the caller (read, none, undetermined) and the case never changes an outcome. Private bus, fake
//! polkit, the fake app-id source.

// The shared helpers are used in full by the audit tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;
#[allow(dead_code, unused_imports)]
#[path = "audit/deadline.rs"]
mod deadline;
#[path = "app_id_audit/outcome.rs"]
mod outcome;
#[path = "app_id_audit/refusals.rs"]
mod refusals;
#[path = "app_id_audit/source.rs"]
mod source;
#[path = "app_id_audit/wire.rs"]
mod wire;

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::future::Future;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use custodiod::app_id::{AppIdOutcome, validate};
use custodiod::app_id_source::{AppIdSource, GuardedSource};
use custodiod::audit::Caller;
use custodiod::audit::{
    AuditError, AuditSink, Entry, MemorySink, Operation, OperationEntry, app_id_state,
};
use custodiod::credentials::{BusCredentials, CallerCredentials, CredentialsError};
use zbus::Connection;

use bus::{Answer, Fixture, TestResult, call, error_name, sign};
use common::{CKM_ECDSA, CKM_RSA_PKCS, PASSWORD, RSA_P12, digest_info, uid};

pub const NEW: &[u8] = include_bytes!("fixtures/cert-rsa2048-recert.der");
pub const OTHER_KEY: &[u8] = include_bytes!("fixtures/cert-rsa2048-other.der");
pub const APP: &str = "org.example.App";

/// A recorded question to a source: the uid and the `Pid:` of the pidfd it was given.
pub type Asked = (u32, Option<u32>);

/// The real credentials without the pinned pidfd: a caller the bus named, no process to look at.
pub(crate) struct NoPidfd(pub BusCredentials);

impl CallerCredentials for NoPidfd {
    fn credentials(
        &self,
        sender: &str,
    ) -> impl Future<Output = Result<Caller, CredentialsError>> + Send {
        self.0.credentials(sender)
    }
}

/// A source that answers as told and records what it was asked.
#[derive(Clone)]
pub struct Probe {
    pub answer: AppIdOutcome,
    pub asked: Arc<Mutex<Vec<Asked>>>,
    /// Blocks the thread of the lookup until the sender is dropped.
    pub hang: Option<Arc<Mutex<std::sync::mpsc::Receiver<()>>>>,
    pub panics: bool,
}

impl Probe {
    pub(crate) fn new(answer: AppIdOutcome) -> Self {
        Self {
            answer,
            asked: Arc::default(),
            hang: None,
            panics: false,
        }
    }

    pub(crate) fn calls(&self) -> Vec<Asked> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The `Pid:` line of a pidfd.
pub(crate) fn pid_of(fd: BorrowedFd<'_>) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?;
    info.lines()
        .find_map(|l| l.strip_prefix("Pid:"))?
        .trim()
        .parse()
        .ok()
}

impl AppIdSource for Probe {
    fn app_id(&self, pidfd: BorrowedFd<'_>, uid: u32) -> impl Future<Output = AppIdOutcome> + Send {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((uid, pid_of(pidfd.as_fd())));
        if let Some(hang) = &self.hang {
            // Returns when the sender is dropped.
            let _ = hang.lock().unwrap_or_else(PoisonError::into_inner).recv();
        }
        if self.panics {
            // The trait promises a source never panics; the service must survive one that does.
            #[allow(clippy::panic)]
            std::panic::panic_any("probe source panics");
        }
        std::future::ready(self.answer.clone())
    }
}

/// The three answers of a source.
pub(crate) fn answers() -> Result<[AppIdOutcome; 3], Box<dyn Error>> {
    let id = validate(APP.as_bytes()).ok_or("app id")?;
    Ok([
        AppIdOutcome::Read(id),
        AppIdOutcome::None,
        AppIdOutcome::Undetermined,
    ])
}

/// A sink that can be told to fail.
#[derive(Default)]
pub struct Sink {
    pub inner: MemorySink,
    pub fail: AtomicBool,
    /// Holds the next operation entry (after recording it) until the sender is used or dropped.
    pub gate: Mutex<Option<Gate>>,
}

/// `entered` tells the test the entry is held; the entry is let go when `release` gets a message.
pub struct Gate {
    pub entered: std::sync::mpsc::Sender<()>,
    pub release: std::sync::mpsc::Receiver<()>,
}

impl Sink {
    /// The wire fields of every entry, in order.
    pub(crate) fn fields(&self) -> Vec<Vec<(&'static str, String)>> {
        let mut all: Vec<_> = self.inner.entries().iter().map(Entry::fields).collect();
        all.extend(
            self.inner
                .operation_entries()
                .iter()
                .map(OperationEntry::fields),
        );
        all
    }
}

impl AuditSink for Sink {
    fn record(&self, entry: &Entry) -> Result<(), AuditError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuditError::Io(std::io::ErrorKind::Other));
        }
        self.inner.record(entry)
    }

    fn record_operation(&self, entry: &OperationEntry) -> Result<(), AuditError> {
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

/// Value of a field of one entry.
pub(crate) fn field<'a>(fields: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.as_str())
}

/// Checks the app-id fields of `fields` against a case.
pub(crate) fn assert_case(fields: &[(&'static str, String)], case: &AppIdOutcome) {
    assert_eq!(
        field(fields, "CUSTODIO_APP_ID_STATE"),
        Some(app_id_state(case)),
        "{fields:?}"
    );
    let want = match case {
        AppIdOutcome::Read(id) => Some(id.as_str()),
        _ => None,
    };
    assert_eq!(field(fields, "CUSTODIO_APP_ID"), want, "{fields:?}");
}

/// How one operation is called.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fail {
    /// The approved call that works.
    No,
    /// An approved call that fails after the approval: a wrong password, a certificate of another
    /// key, an ECDSA mechanism on an RSA key.
    AfterApproval,
}

pub(crate) fn put_rsa(f: &Fixture, id: &str) -> TestResult {
    custodiod::import::import_p12(
        &f.store,
        &custodiod::creds::memory::MemoryCreds::host(),
        uid(),
        id,
        RSA_P12,
        &secrecy::SecretString::from(PASSWORD.to_owned()),
    )?;
    Ok(())
}

/// A fixture with the real credentials, `sink`, and `source` if any; a key `k` unless the operation
/// is an import.
pub(crate) async fn start(
    op: Operation,
    answer: Answer,
    sink: &Arc<Sink>,
    source: Option<GuardedSource>,
) -> Result<Fixture, Box<dyn Error>> {
    let f = Fixture::start_full(
        answer,
        |c: &Connection| BusCredentials::new(c.clone()),
        sink.clone(),
        None,
        source,
    )
    .await?;
    if op != Operation::Import {
        put_rsa(&f, "k")?;
    }
    Ok(f)
}

/// Makes the call of `op`; `Ok` or the error name.
pub(crate) async fn drive(f: &Fixture, op: Operation, fail: Fail) -> Result<(), String> {
    let failing = fail == Fail::AfterApproval;
    let c = &f.client;
    let reply = match op {
        Operation::Sign => {
            let mechanism = if failing { CKM_ECDSA } else { CKM_RSA_PKCS };
            sign(c, "k", mechanism, &digest_info()).await.map(|_| ())
        }
        Operation::Import => {
            let password = if failing { "wrong" } else { PASSWORD };
            call(c, "ImportP12", &("k", RSA_P12.to_vec(), password))
                .await
                .map(|_| ())
        }
        Operation::Delete => call(c, "DeleteKey", &("k",)).await.map(|_| ()),
        Operation::ReplaceCertificate => {
            let cert = if failing { OTHER_KEY } else { NEW };
            call(c, "ReplaceCertificate", &("k", cert.to_vec()))
                .await
                .map(|_| ())
        }
    };
    reply.map_err(|e| error_name(&e))
}

/// Every file below `dir` with its bytes.
pub(crate) fn snapshot(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn Error>> {
    let mut out = BTreeMap::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for entry in fs::read_dir(&d)? {
            let path = entry?.path();
            if path.is_dir() {
                todo.push(path);
            } else {
                out.insert(
                    path.strip_prefix(dir)?.display().to_string(),
                    fs::read(&path)?,
                );
            }
        }
    }
    Ok(out)
}

#[test]
fn app_id_cases_for_every_operation() -> TestResult {
    zbus::block_on(async {
        for op in Operation::all() {
            for case in answers()? {
                let sink = Arc::new(Sink::default());
                let probe = Probe::new(case.clone());
                let f = start(op, Answer::Yes, &sink, Some(GuardedSource::new(probe))).await?;
                drive(&f, op, Fail::No).await?;
                let all = sink.fields();
                assert_eq!(all.len(), 1, "{op:?}");
                let entry = all.first().ok_or("entry")?;
                assert_eq!(field(entry, "CUSTODIO_OPERATION"), Some(op.name()));
                assert_case(entry, &case);
            }
        }
        Ok(())
    })
}

#[test]
fn app_id_without_caller_is_undetermined() -> TestResult {
    use common::NoCredentials;
    zbus::block_on(async {
        for op in Operation::all() {
            let probe = Probe::new(AppIdOutcome::None);
            for variant in 0..2 {
                let sink = Arc::new(Sink::default());
                let source = Some(GuardedSource::new(probe.clone()));
                let f = if variant == 0 {
                    Fixture::start_full(
                        Answer::Yes,
                        |_: &Connection| NoCredentials,
                        sink.clone(),
                        None,
                        source,
                    )
                    .await?
                } else {
                    Fixture::start_full(
                        Answer::Yes,
                        |c: &Connection| NoPidfd(BusCredentials::new(c.clone())),
                        sink.clone(),
                        None,
                        source,
                    )
                    .await?
                };
                if op != Operation::Import {
                    put_rsa(&f, "k")?;
                }
                let _ = drive(&f, op, Fail::No).await;
                let all = sink.fields();
                // Variant 1 has a caller but no pinned process: its entry still carries the caller.
                assert_eq!(all.len(), 1, "{op:?} {variant}");
                let entry = all.first().ok_or("entry")?;
                assert_case(entry, &AppIdOutcome::Undetermined);
                assert_eq!(field(entry, "CUSTODIO_UID").is_none(), variant == 0);
            }
            assert!(probe.calls().is_empty(), "{op:?}");
        }
        Ok(())
    })
}
