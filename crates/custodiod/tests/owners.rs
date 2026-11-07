//! Two callers with different uids through the replaceable credentials interface: every call is
//! scoped to the uid the bus reports for its own connection. A private `dbus-daemon`, a fake polkit.

// The shared helpers are used in full by the audit tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;

use std::collections::HashMap;
use std::future::{Future, ready};
use std::sync::{Arc, Mutex, PoisonError};

use custodio_client::{
    ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_INTERNAL, ERROR_KEY_ID_TAKEN, ERROR_NO_SUCH_KEY,
};
use custodiod::audit::{Caller, MemorySink};
use custodiod::credentials::{CallerCredentials, CredentialsError};
use secrecy::SecretString;
use zbus::{Connection, block_on};

use bus::{Answer, Fixture, TestResult, call, sign};
use common::{
    CKM_ECDSA, EC_P12, MissingPid, NoCredentials, PASSWORD, RSA_P12, Reply, digest, import_with,
    uid,
};

const OTHER_EC_P12: &[u8] = include_bytes!("fixtures/p256-other.p12");
/// The pairs of caller uids; the second one has root as one of the two.
const UID_PAIRS: [(u32, u32); 2] = [(1000, 1001), (0, 1000)];

/// The storage kind the fixture's service chooses (no TPM).
const STORAGE_KIND: &str = "encrypted-host";

type Row = (String, String, String, Vec<u8>);
type Listed = Vec<Row>;

/// Credentials from a table: the bus name of a connection gives its caller.
#[derive(Clone, Default)]
struct ByName(Arc<Mutex<HashMap<String, Caller>>>);

impl ByName {
    fn add(&self, connection: &Connection, uid: u32) -> TestResult {
        let name = connection
            .unique_name()
            .ok_or("no unique name")?
            .to_string();
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                name,
                Caller {
                    uid,
                    pid: std::process::id(),
                },
            );
        Ok(())
    }
}

impl CallerCredentials for ByName {
    fn credentials(
        &self,
        sender: &str,
    ) -> impl Future<Output = Result<Caller, CredentialsError>> + Send {
        ready(
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(sender)
                .copied()
                .ok_or(CredentialsError::Bus),
        )
    }
}

/// A service with two callers, `a` and `b`, at the given uids.
struct Two {
    f: Fixture,
    b: Connection,
    sink: Arc<MemorySink>,
}

impl Two {
    async fn start(
        answer: Answer,
        uid_a: u32,
        uid_b: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let creds = ByName::default();
        let sink = Arc::new(MemorySink::default());
        let c = creds.clone();
        let f = Fixture::start(answer, move |_: &Connection| c, sink.clone()).await?;
        let b = f.bus.connect().await?;
        creds.add(&f.client, uid_a)?;
        creds.add(&b, uid_b)?;
        Ok(Self { f, b, sink })
    }

    fn a(&self) -> &Connection {
        &self.f.client
    }
}

fn error_of<T>(r: zbus::Result<T>) -> Result<String, Box<dyn std::error::Error>> {
    match r {
        Err(zbus::Error::MethodError(name, _, _)) => Ok(name.as_str().to_owned()),
        Err(other) => Err(format!("not a method error: {other}").into()),
        Ok(_) => Err("the call succeeded".into()),
    }
}

async fn import(c: &Connection, id: &str, p12: &[u8]) -> zbus::Result<String> {
    call(c, "ImportP12", &(id, p12.to_vec(), PASSWORD))
        .await?
        .body()
        .deserialize::<(String, String)>()
        .map(|(key_type, _kind)| key_type)
}

async fn list(c: &Connection) -> zbus::Result<Listed> {
    let mut keys: Listed = call(c, "ListKeys", &()).await?.body().deserialize()?;
    keys.sort();
    Ok(keys)
}

fn cert_of(p12: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(custodiod::import::parse_p12(p12, &SecretString::from(PASSWORD.to_owned()))?.certificate)
}

fn entry(id: &str, kind: &str, p12: &[u8]) -> Result<Row, Box<dyn std::error::Error>> {
    Ok((
        id.to_owned(),
        kind.to_owned(),
        STORAGE_KIND.to_owned(),
        cert_of(p12)?,
    ))
}

#[test]
fn list_is_scoped_to_the_caller() -> TestResult {
    block_on(async {
        for (ua, ub) in UID_PAIRS {
            let t = Two::start(Answer::Yes, ua, ub).await?;
            assert_eq!(import(t.a(), "r", RSA_P12).await?, "rsa2048");
            assert_eq!(import(t.a(), "e", EC_P12).await?, "ecdsa-p256");
            assert_eq!(import(&t.b, "b1", EC_P12).await?, "ecdsa-p256");
            // B uses A's id for a different key.
            assert_eq!(import(&t.b, "e", OTHER_EC_P12).await?, "ecdsa-p256");
            let mut want_a = vec![
                entry("r", "rsa2048", RSA_P12)?,
                entry("e", "ecdsa-p256", EC_P12)?,
            ];
            want_a.sort();
            let mut want_b = vec![
                entry("b1", "ecdsa-p256", EC_P12)?,
                entry("e", "ecdsa-p256", OTHER_EC_P12)?,
            ];
            want_b.sort();
            assert_ne!(cert_of(EC_P12)?, cert_of(OTHER_EC_P12)?);
            assert_eq!(list(t.a()).await?, want_a, "{ua} {ub}");
            assert_eq!(list(&t.b).await?, want_b, "{ua} {ub}");
            // Listing asks no polkit: only the four imports did.
            assert_eq!(t.f.asked().len(), 4);
        }
        Ok(())
    })
}

/// The credentials that give no uid, as fixtures: `(name, fixture)`.
async fn failing(which: usize) -> Result<Fixture, Box<dyn std::error::Error>> {
    let sink = Arc::new(MemorySink::default());
    match which {
        0 => Fixture::start(Answer::Yes, |_: &Connection| NoCredentials, sink).await,
        1 => Fixture::start(Answer::Yes, |_: &Connection| MissingPid, sink).await,
        // The uid is there but the reply has no `ProcessFD`, so the cross-check fails.
        _ => {
            Fixture::start(
                Answer::Yes,
                |_: &Connection| {
                    Reply(|m: &mut HashMap<_, _>| {
                        m.remove("ProcessFD");
                    })
                },
                sink,
            )
            .await
        }
    }
}

#[test]
fn list_fails_closed_without_credentials() -> TestResult {
    block_on(async {
        for which in 0..3 {
            let f = failing(which).await?;
            // Keys exist for the caller's own uid, so an empty or unfiltered list would show.
            import_with(&f, "e", EC_P12, PASSWORD).await?;
            assert_eq!(f.store.list(uid())?.len(), 1);
            let err = error_of(call(&f.client, "ListKeys", &()).await)?;
            assert_eq!(err, ERROR_AUTHORIZATION_UNAVAILABLE, "case {which}");
            assert_eq!(f.asked().len(), 0);
        }
        Ok(())
    })
}

#[test]
fn import_fails_closed_without_credentials() -> TestResult {
    block_on(async {
        for which in 0..3 {
            let f = failing(which).await?;
            // A malformed `.p12`: the credentials error, not the file error, proves the order.
            let err = error_of(import(&f.client, "k", b"not a p12").await)?;
            assert_eq!(err, ERROR_AUTHORIZATION_UNAVAILABLE, "case {which}");
            let err = error_of(import(&f.client, "k", EC_P12).await)?;
            assert_eq!(err, ERROR_AUTHORIZATION_UNAVAILABLE, "case {which}");
            assert_eq!(f.store.list(uid())?.len(), 0);
            assert_eq!(f.asked().len(), 0);
        }
        Ok(())
    })
}

#[test]
fn list_reports_a_record_that_cannot_be_read() -> TestResult {
    block_on(async {
        let t = Two::start(Answer::Yes, 1000, 1001).await?;
        import(t.a(), "e", EC_P12).await?;
        import(t.a(), "r", RSA_P12).await?;
        assert_eq!(list(t.a()).await?.len(), 2);
        let area = t.f.store_dir().join("1000");
        // The record is cut short (its mode is kept).
        let mut bytes = std::fs::read(area.join("e"))?;
        bytes.truncate(24);
        std::fs::write(area.join("e"), bytes)?;
        // An error, not a shorter list.
        assert_eq!(
            error_of(call(t.a(), "ListKeys", &()).await)?,
            ERROR_INTERNAL
        );
        Ok(())
    })
}

#[test]
fn import_is_per_owner() -> TestResult {
    block_on(async {
        for (ua, ub) in UID_PAIRS {
            let t = Two::start(Answer::Yes, ua, ub).await?;
            import(t.a(), "k", EC_P12).await?;
            // B may use the id A uses.
            import(&t.b, "k", OTHER_EC_P12).await?;
            assert_eq!(list(t.a()).await?, [entry("k", "ecdsa-p256", EC_P12)?]);
            assert_eq!(list(&t.b).await?, [entry("k", "ecdsa-p256", OTHER_EC_P12)?]);
            // Only the caller's own id is taken.
            let err = error_of(import(t.a(), "k", RSA_P12).await)?;
            assert_eq!(err, ERROR_KEY_ID_TAKEN);
            let err = error_of(import(&t.b, "k", RSA_P12).await)?;
            assert_eq!(err, ERROR_KEY_ID_TAKEN);
            // Both keys are as they were, and each is stored under its own uid.
            assert_eq!(list(t.a()).await?, [entry("k", "ecdsa-p256", EC_P12)?]);
            assert_eq!(list(&t.b).await?, [entry("k", "ecdsa-p256", OTHER_EC_P12)?]);
            assert!(t.f.store.get(ua, "k").is_ok() && t.f.store.get(ub, "k").is_ok());
            // A signs with its own key. The two imports asked; the refused ones did not.
            assert_eq!(t.f.asked().len(), 2);
            sign(t.a(), "k", CKM_ECDSA, &digest()).await?;
            assert_eq!(t.f.asked().len(), 3);
        }
        Ok(())
    })
}

#[test]
fn sign_foreign_equals_missing() -> TestResult {
    block_on(async {
        for (ua, ub) in UID_PAIRS {
            for answer in [Answer::Yes, Answer::No] {
                let t = Two::start(Answer::Yes, ua, ub).await?;
                import(t.a(), "k", EC_P12).await?;
                import(&t.b, "own", EC_P12).await?;
                // The imports asked; from here on count only the signatures.
                t.f.asked.lock().map_err(|_| "poisoned")?.clear();
                t.f.set_answer(answer);
                let foreign = error_of(sign(&t.b, "k", CKM_ECDSA, &digest()).await)?;
                let asked_foreign = t.f.asked();
                let entries_foreign = t.sink.entries();
                let missing = error_of(sign(&t.b, "nope", CKM_ECDSA, &digest()).await)?;
                assert_eq!(foreign, ERROR_NO_SUCH_KEY, "{ua} {ub}");
                assert_eq!(missing, foreign);
                // Same polkit calls (none) and same journal (no entry) for both.
                assert_eq!(t.f.asked(), asked_foreign);
                assert_eq!(asked_foreign.len(), 0);
                assert_eq!(t.sink.entries(), entries_foreign);
                assert_eq!(entries_foreign.len(), 0);
                // Control: the owner's own key does ask polkit, once, and is recorded.
                let own = sign(t.a(), "k", CKM_ECDSA, &digest()).await;
                assert_eq!(own.is_ok(), matches!(answer, Answer::Yes));
                assert_eq!(t.f.asked().len(), 1);
                assert_eq!(t.sink.entries().len(), 1);
            }
        }
        Ok(())
    })
}
