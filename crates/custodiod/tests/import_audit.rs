//! `ImportP12` leaves exactly one journal entry once polkit has been asked, and fails closed: an
//! entry that cannot be recorded means the key is not kept. Private bus, fake polkit, in-memory and
//! failing sinks.

// The shared helpers are used in full by the audit tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;
#[allow(dead_code, unused_imports)]
#[path = "audit/scan.rs"]
mod scan;

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use custodio_client::{
    ERROR_AUDIT_UNAVAILABLE, ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_INTERNAL, ERROR_INVALID_ARGS,
    ERROR_KEY_ID_TAKEN, ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED, ERROR_UNSUPPORTED_KEY_TYPE,
    ERROR_WRONG_PASSWORD_OR_BAD_P12, MAX_P12_LEN,
};
use custodiod::audit::{
    AuditError, AuditKeyType, AuditSink, Caller, Entry, FailingSink, ImportOutcome, MemorySink,
    Operation, OperationEntry,
};
use custodiod::credentials::BusCredentials;
use custodiod::import::parse_p12;
use secrecy::{ExposeSecret, SecretString};
use zbus::{Connection, block_on};

use bus::{Answer, Fixture, TestResult, call, error_name, sign};
use common::{
    CKM_ECDSA, EC_P12, EC_SENTINEL_P12, NoCredentials, PASSWORD, RSA_SENTINEL_P12,
    SENTINEL_PASSWORD, digest, uid,
};

fn fixture_file(name: &str) -> Result<Vec<u8>, std::io::Error> {
    fs::read(format!(
        "{}/tests/fixtures/{name}.p12",
        env!("CARGO_MANIFEST_DIR")
    ))
}

async fn import(f: &Fixture, id: &str, p12: &[u8], password: &str) -> Result<String, String> {
    let reply = call(&f.client, "ImportP12", &(id, p12.to_vec(), password))
        .await
        .map_err(|e| error_name(&e))?;
    reply.body().deserialize().map_err(|e| e.to_string())
}

/// The ids in the store area of the test process's uid.
fn stored(f: &Fixture) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(f.store.list(uid())?)
}

/// Every path under `dir`, relative, sorted.
fn tree(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            out.push(path.strip_prefix(base).unwrap_or(&path).to_path_buf());
            if path.is_dir() {
                walk(base, &path, out)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort();
    Ok(out)
}

/// The tests that make writes fail need a user the mode bits bind: root ignores `0500`.
fn running_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

fn set_mode(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// The test client as the entries name it.
fn me() -> Caller {
    Caller {
        uid: uid(),
        pid: std::process::id(),
    }
}

/// What an entry says, in plain values.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    operation: Operation,
    outcome: &'static str,
    caller: Option<Caller>,
    key_id: String,
    key_type: Option<AuditKeyType>,
}

fn seen(e: &OperationEntry) -> Seen {
    Seen {
        operation: e.operation(),
        outcome: e.outcome_name(),
        caller: e.caller(),
        key_id: e.key_id().as_str().to_owned(),
        key_type: e.key_type(),
    }
}

struct Case {
    name: &'static str,
    answer: Answer,
    credentials_work: bool,
    p12: Vec<u8>,
    password: &'static str,
    unwritable: bool,
    polkit_calls: usize,
    reply: Result<&'static str, &'static str>,
    outcome: ImportOutcome,
    key_type: Option<AuditKeyType>,
}

impl Case {
    fn new(name: &'static str, answer: Answer, outcome: ImportOutcome) -> Self {
        Self {
            name,
            answer,
            credentials_work: true,
            p12: EC_SENTINEL_P12.to_vec(),
            password: SENTINEL_PASSWORD,
            unwritable: false,
            polkit_calls: 1,
            reply: Err(""),
            outcome,
            key_type: None,
        }
    }
}

fn cases() -> Result<Vec<Case>, Box<dyn Error>> {
    use ImportOutcome as O;
    let mut stored_rsa = Case::new("stored rsa", Answer::Yes, O::Stored);
    stored_rsa.p12 = RSA_SENTINEL_P12.to_vec();
    stored_rsa.reply = Ok("rsa2048");
    stored_rsa.key_type = Some(AuditKeyType::Rsa2048);
    let mut stored_ec = Case::new("stored ecdsa", Answer::Yes, O::Stored);
    stored_ec.reply = Ok("ecdsa-p256");
    stored_ec.key_type = Some(AuditKeyType::EcdsaP256);
    let mut denied = Case::new("denied", Answer::No, O::Denied);
    denied.reply = Err(ERROR_POLKIT_DENIED);
    let mut unavailable = Case::new("unavailable", Answer::Fail, O::AuthorizationUnavailable);
    unavailable.reply = Err(ERROR_AUTHORIZATION_UNAVAILABLE);
    let mut no_credentials = Case::new(
        "failed credentials",
        Answer::Yes,
        O::AuthorizationUnavailable,
    );
    no_credentials.credentials_work = false;
    no_credentials.polkit_calls = 0;
    no_credentials.reply = Err(ERROR_AUTHORIZATION_UNAVAILABLE);
    let mut wrong_password = Case::new("wrong password", Answer::Yes, O::WrongPassword);
    wrong_password.p12 = EC_P12.to_vec();
    wrong_password.reply = Err(ERROR_WRONG_PASSWORD_OR_BAD_P12);
    let mut unsupported = Case::new("unsupported key", Answer::Yes, O::UnsupportedKey);
    unsupported.p12 = fixture_file("rsa3072")?;
    unsupported.password = PASSWORD;
    unsupported.reply = Err(ERROR_UNSUPPORTED_KEY_TYPE);
    let mut storage = Case::new("storage failure", Answer::Yes, O::StorageFailure);
    storage.unwritable = true;
    storage.reply = Err(ERROR_INTERNAL);
    storage.key_type = Some(AuditKeyType::EcdsaP256);
    Ok(vec![
        stored_rsa,
        stored_ec,
        denied,
        unavailable,
        no_credentials,
        wrong_password,
        unsupported,
        storage,
    ])
}

/// What one run of a case left behind.
struct Run {
    reply: Result<String, String>,
    entries: Vec<OperationEntry>,
    sign_entries: Vec<Entry>,
    polkit_calls: usize,
}

async fn run_case(case: &Case) -> Result<Run, Box<dyn Error>> {
    let sink = Arc::new(MemorySink::default());
    let f = if case.credentials_work {
        common::fixture_reading(case.answer, &sink).await?
    } else {
        Fixture::start_reading(case.answer, |_: &Connection| NoCredentials, sink.clone()).await?
    };
    let root = f.store.dir().to_path_buf();
    if case.unwritable {
        // After the own-id check: the double makes the store unwritable while it answers polkit.
        let root = root.clone();
        f.on_request(move || {
            let _ = set_mode(&root, 0o500);
        });
    }
    let reply = import(&f, "k", &case.p12, case.password).await;
    set_mode(&root, 0o700)?;
    Ok(Run {
        reply,
        entries: sink.operation_entries(),
        sign_entries: sink.entries(),
        polkit_calls: f.asked().len(),
    })
}

#[test]
fn import_entry_per_outcome() -> TestResult {
    if running_as_root() {
        eprintln!("skipped: the storage failure case needs a user that mode 0500 binds");
        return Ok(());
    }
    block_on(async {
        let mut reached = Vec::new();
        for case in cases()? {
            let run = run_case(&case).await?;
            let name = case.name;
            let want_reply = match case.reply {
                Ok(kind) => Ok(kind.to_owned()),
                Err(name) => Err(name.to_owned()),
            };
            assert_eq!(run.reply, want_reply, "{name}");
            assert_eq!(run.polkit_calls, case.polkit_calls, "{name}");
            assert!(run.sign_entries.is_empty(), "{name}");
            assert_eq!(run.entries.len(), 1, "{name}");
            let entry = run.entries.first().ok_or("no entry")?;
            let want = Seen {
                operation: Operation::Import,
                outcome: case.outcome.name(),
                caller: case.credentials_work.then(me),
                key_id: "k".to_owned(),
                key_type: case.key_type,
            };
            assert_eq!(seen(entry), want, "{name}");
            assert_eq!(entry.priority(), case.outcome.priority(), "{name}");
            reached.push(case.outcome);
        }
        for outcome in ImportOutcome::all() {
            assert!(reached.contains(&outcome), "{outcome:?} is never reached");
        }
        Ok(())
    })
}

/// Every place an entry can carry text: its message and its accessors.
fn entry_text(e: &OperationEntry) -> String {
    format!(
        "{} {e:?} {} {} {:?} {:?} {:?}",
        e.message(),
        e.outcome_name(),
        e.key_id().as_str(),
        e.caller(),
        e.key_type(),
        e.operation()
    )
}

/// The values that must never appear in an entry: the password, the `.p12` and what is in it.
fn secrets(case: &Case) -> Vec<Vec<u8>> {
    let mut out = vec![case.password.as_bytes().to_vec(), case.p12.clone()];
    for pw in [PASSWORD, SENTINEL_PASSWORD] {
        if let Ok(parsed) = parse_p12(&case.p12, &SecretString::from(pw.to_owned())) {
            out.push(pw.as_bytes().to_vec());
            out.push(parsed.certificate);
            out.push(parsed.key.expose_secret().to_vec());
        }
    }
    out
}

#[test]
fn import_entries_hold_no_secrets() -> TestResult {
    if running_as_root() {
        eprintln!("skipped: the storage failure case needs a user that mode 0500 binds");
        return Ok(());
    }
    block_on(async {
        // The scan must be able to see a leak: a string that carries the password and the file.
        let case = cases()?.remove(0);
        let leaking = format!(
            "x {} {}",
            case.password,
            String::from_utf8_lossy(&scan::base64(&case.p12, false, true).into_bytes())
        );
        assert!(
            secrets(&case)
                .iter()
                .any(|s| !scan::leaks(leaking.as_bytes(), s).is_empty()),
            "the scan does not find a leak"
        );
        let mut scanned = 0;
        for case in cases()? {
            let run = run_case(&case).await?;
            let entry = run.entries.first().ok_or("no entry")?;
            let text = entry_text(entry);
            // Without credentials there is no pinned process and no id to see.
            assert_eq!(
                entry
                    .fields()
                    .contains(&("CUSTODIO_APP_ID", "org.example.App".to_owned())),
                case.credentials_work,
                "{}",
                case.name
            );
            for secret in secrets(&case) {
                assert_eq!(
                    scan::leaks(text.as_bytes(), &secret),
                    Vec::<&str>::new(),
                    "{}",
                    case.name
                );
            }
            scanned += 1;
        }
        assert_eq!(scanned, cases()?.len());
        Ok(())
    })
}

#[test]
fn failing_sink_rolls_the_import_back() -> TestResult {
    block_on(async {
        let f = Fixture::start(
            Answer::Yes,
            |c: &Connection| BusCredentials::new(c.clone()),
            Arc::new(FailingSink),
        )
        .await?;
        let got = import(&f, "k", EC_P12, PASSWORD).await;
        assert_eq!(got, Err(ERROR_AUDIT_UNAVAILABLE.to_owned()));
        let err = call(&f.client, "ImportP12", &("k2", EC_P12.to_vec(), PASSWORD))
            .await
            .err()
            .ok_or("a reply came back")?;
        assert!(format!("{err}").contains("audit unavailable"), "{err}");
        // Neither the key nor the certificate is kept.
        assert_eq!(stored(&f)?, Vec::<String>::new());
        assert_eq!(tree(f.store.dir())?, [PathBuf::from(uid().to_string())]);
        let got = sign(&f.client, "k", CKM_ECDSA, &digest())
            .await
            .map_err(|e| error_name(&e));
        assert_eq!(got, Err(ERROR_NO_SUCH_KEY.to_owned()));

        // A working sink: the same id can be imported and leaves one `stored` entry.
        let sink = Arc::new(MemorySink::default());
        let g = common::fixture(Answer::Yes, &sink).await?;
        assert_eq!(
            import(&g, "k", EC_P12, PASSWORD).await,
            Ok("ecdsa-p256".to_owned())
        );
        assert_eq!(sink.operation_entries().len(), 1);
        Ok(())
    })
}

/// Switches the failing sink on after the first import, on the same fixture.
struct Switch {
    inner: MemorySink,
    fail: std::sync::atomic::AtomicBool,
}

impl AuditSink for Switch {
    fn record(&self, entry: &Entry) -> Result<(), AuditError> {
        self.inner.record(entry)
    }

    fn record_operation(&self, entry: &OperationEntry) -> Result<(), AuditError> {
        if self.fail.load(Ordering::SeqCst) {
            return FailingSink.record_operation(entry);
        }
        self.inner.record_operation(entry)
    }
}

#[test]
fn a_rolled_back_id_can_be_imported_again_on_the_same_store() -> TestResult {
    block_on(async {
        let sink = Arc::new(Switch {
            inner: MemorySink::default(),
            fail: true.into(),
        });
        let f = Fixture::start(
            Answer::Yes,
            |c: &Connection| BusCredentials::new(c.clone()),
            sink.clone(),
        )
        .await?;
        let got = import(&f, "k", EC_P12, PASSWORD).await;
        assert_eq!(got, Err(ERROR_AUDIT_UNAVAILABLE.to_owned()));
        assert_eq!(stored(&f)?, Vec::<String>::new());
        sink.fail.store(false, Ordering::SeqCst);
        assert_eq!(
            import(&f, "k", EC_P12, PASSWORD).await,
            Ok("ecdsa-p256".to_owned())
        );
        assert_eq!(stored(&f)?, ["k"]);
        let entries = sink.inner.operation_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries.first().map(seen).map(|s| s.outcome), Some("stored"));
        let signature = sign(&f.client, "k", CKM_ECDSA, &digest()).await;
        assert!(signature.is_ok());
        Ok(())
    })
}

#[test]
fn failing_sink_fails_every_outcome() -> TestResult {
    if running_as_root() {
        eprintln!("skipped: the storage failure case needs a user that mode 0500 binds");
        return Ok(());
    }
    block_on(async {
        for case in cases()?
            .into_iter()
            .filter(|c| c.outcome != ImportOutcome::Stored)
        {
            let f = if case.credentials_work {
                Fixture::start(
                    case.answer,
                    |c: &Connection| BusCredentials::new(c.clone()),
                    Arc::new(FailingSink),
                )
                .await?
            } else {
                Fixture::start(
                    case.answer,
                    |_: &Connection| NoCredentials,
                    Arc::new(FailingSink),
                )
                .await?
            };
            let root = f.store.dir().to_path_buf();
            if case.unwritable {
                let root = root.clone();
                f.on_request(move || {
                    let _ = set_mode(&root, 0o500);
                });
            }
            let before = (stored(&f)?, tree(&root)?);
            let got = import(&f, "k", &case.p12, case.password).await;
            set_mode(&root, 0o700)?;
            assert_eq!(
                got,
                Err(ERROR_AUDIT_UNAVAILABLE.to_owned()),
                "{}",
                case.name
            );
            assert_eq!((stored(&f)?, tree(&root)?), before, "{}", case.name);
        }
        Ok(())
    })
}

/// Makes the area unwritable when it is asked to record, so the removal of a rollback fails.
#[derive(Default)]
struct LockWhileRecording {
    inner: MemorySink,
    area: std::sync::Mutex<Option<PathBuf>>,
}

impl AuditSink for LockWhileRecording {
    fn record(&self, entry: &Entry) -> Result<(), AuditError> {
        self.inner.record(entry)
    }

    fn record_operation(&self, entry: &OperationEntry) -> Result<(), AuditError> {
        if let Some(area) = self.area.lock().ok().and_then(|a| a.clone()) {
            set_mode(&area, 0o500).map_err(|e| AuditError::Io(e.kind()))?;
        }
        self.inner.record_operation(entry)?;
        Err(AuditError::Io(std::io::ErrorKind::Other))
    }
}

#[test]
fn rollback_failure_still_reports_audit_unavailable() -> TestResult {
    if running_as_root() {
        eprintln!("skipped: the rollback cannot be made to fail for root");
        return Ok(());
    }
    block_on(async {
        let sink = Arc::new(LockWhileRecording::default());
        let f = Fixture::start(
            Answer::Yes,
            |c: &Connection| BusCredentials::new(c.clone()),
            sink.clone(),
        )
        .await?;
        let area = f.store.dir().join(uid().to_string());
        *sink.area.lock().map_err(|_| "poisoned")? = Some(area.clone());
        let got = import(&f, "k", EC_P12, PASSWORD).await;
        set_mode(&area, 0o700)?;
        // The removal failed, so the files are still there, but the call did not succeed.
        assert_eq!(got, Err(ERROR_AUDIT_UNAVAILABLE.to_owned()));
        assert_eq!(stored(&f)?, ["k"]);
        assert_eq!(sink.inner.operation_entries().len(), 1);
        Ok(())
    })
}

#[test]
fn import_refusals_leave_no_entry() -> TestResult {
    block_on(async {
        let big = vec![0u8; MAX_P12_LEN + 1];
        let long_password = "p".repeat(1025);
        for failing in [false, true] {
            let sink = Arc::new(MemorySink::default());
            let f = if failing {
                Fixture::start(
                    Answer::Yes,
                    |c: &Connection| BusCredentials::new(c.clone()),
                    Arc::new(FailingSink),
                )
                .await?
            } else {
                common::fixture(Answer::Yes, &sink).await?
            };
            // The caller already holds `k`.
            common::import(&f, "k", EC_P12).await?;
            let cases: [(&str, &[u8], &str, &str); 4] = [
                ("bad id!", EC_P12, PASSWORD, ERROR_INVALID_ARGS),
                ("new", &big, PASSWORD, ERROR_INVALID_ARGS),
                ("new", EC_P12, &long_password, ERROR_INVALID_ARGS),
                ("k", EC_P12, PASSWORD, ERROR_KEY_ID_TAKEN),
            ];
            for (id, data, password, want) in cases {
                let got = import(&f, id, data, password).await;
                assert_eq!(got, Err(want.to_owned()), "{id} failing={failing}");
            }
            assert_eq!(f.asked().len(), 0);
            assert_eq!(sink.operation_entries().len(), 0);
            assert_eq!(sink.entries().len(), 0);
        }
        Ok(())
    })
}

#[path = "import_audit/concurrent.rs"]
mod concurrent;
