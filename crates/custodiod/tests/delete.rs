//! `DeleteKey` over a private bus: the id bound, the caller's own keys only, polkit once under the
//! delete action, and what is left on disk afterwards. Callers have uids through a name table.

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

use custodiod::store::Record;
use std::collections::HashMap;
use std::future::{Future, ready};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};

use custodio_client::{
    ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_INTERNAL, ERROR_INVALID_ARGS, ERROR_KEY_ID_TAKEN,
    ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED,
};
use custodiod::audit::{Caller, MemorySink};
use custodiod::credentials::{CallerCredentials, CredentialsError};
use custodiod::polkit::{ACTION_ID, DELETE_ACTION_ID};
use zbus::{Connection, block_on};

use bus::{Answer, Fixture, TestResult, call, error_name, sign};
use common::{CKM_ECDSA, EC_P12, MissingPid, NoCredentials, PASSWORD, RSA_P12, digest};

const OTHER_EC_P12: &[u8] = include_bytes!("fixtures/p256-other.p12");
const UID_PAIRS: [(u32, u32); 2] = [(1000, 1001), (0, 1000)];
const ALLOW_INTERACTION: u32 = 1;

#[path = "delete/concurrent.rs"]
mod concurrent;

const NONE: [String; 0] = [];
type Listed = Vec<(String, String, String, Vec<u8>)>;

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

/// A service with two callers, `a` (the fixture's client) and `b`, and a second connection `a2` of
/// the uid of `a`.
struct Rig {
    f: Fixture,
    b: Connection,
    a2: Connection,
}

impl Rig {
    async fn start(
        answer: Answer,
        uid_a: u32,
        uid_b: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let creds = ByName::default();
        let c = creds.clone();
        let f = Fixture::start(
            answer,
            move |_: &Connection| c,
            Arc::new(MemorySink::default()),
        )
        .await?;
        let b = f.bus.connect().await?;
        let a2 = f.bus.connect().await?;
        creds.add(&f.client, uid_a)?;
        creds.add(&b, uid_b)?;
        creds.add(&a2, uid_a)?;
        Ok(Self { f, b, a2 })
    }

    fn a(&self) -> &Connection {
        &self.f.client
    }

    fn area(&self, uid: u32) -> PathBuf {
        self.f.store_dir().join(uid.to_string())
    }

    /// Forgets the polkit requests so far (setup imports).
    fn forget_asks(&self) {
        self.f
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.f
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.f.hold.store(0, Ordering::SeqCst);
    }

    /// Imports with the polkit answer `Yes`, then restores `answer` and forgets the asks.
    async fn import(&self, c: &Connection, id: &str, p12: &[u8], answer: Answer) -> TestResult {
        self.f.set_answer(Answer::Yes);
        call(c, "ImportP12", &(id, p12.to_vec(), PASSWORD)).await?;
        self.f.set_answer(answer);
        self.forget_asks();
        Ok(())
    }

    fn requests(&self) -> Vec<(String, u32)> {
        self.f
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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

async fn list(c: &Connection) -> zbus::Result<Listed> {
    let mut keys: Listed = call(c, "ListKeys", &()).await?.body().deserialize()?;
    keys.sort();
    Ok(keys)
}

async fn listed_ids(c: &Connection) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(list(c).await?.into_iter().map(|k| k.0).collect())
}

async fn sign_err(c: &Connection, id: &str) -> String {
    match sign(c, id, CKM_ECDSA, &digest()).await {
        Ok(_) => "ok".to_owned(),
        Err(e) => error_name(&e),
    }
}

/// Every entry of `dir` with its bytes, sorted by name.
fn snapshot(dir: &Path) -> Result<Vec<(String, Vec<u8>)>, std::io::Error> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        // A directory in the area has no bytes to compare.
        let bytes = if entry.path().is_dir() {
            Vec::new()
        } else {
            std::fs::read(entry.path())?
        };
        out.push((entry.file_name().to_string_lossy().into_owned(), bytes));
    }
    out.sort();
    Ok(out)
}

fn names(dir: &Path) -> Result<Vec<String>, std::io::Error> {
    Ok(snapshot(dir)?.into_iter().map(|e| e.0).collect())
}

#[test]
fn delete_rejects_bad_ids() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        r.import(r.a(), "k", EC_P12, Answer::Yes).await?;
        let before = snapshot(&r.area(1000))?;
        let long = "a".repeat(60);
        for id in ["", long.as_str(), "bad id!", "../k", "k-cert", "x-cert"] {
            assert_eq!(
                delete(r.a(), id).await,
                Err(ERROR_INVALID_ARGS.to_owned()),
                "{id:?}"
            );
        }
        assert_eq!(r.f.asked(), NONE);
        assert_eq!(snapshot(&r.area(1000))?, before);
        // A 59-byte id passes the check and is only missing.
        assert_eq!(
            delete(r.a(), &"a".repeat(59)).await,
            Err(ERROR_NO_SUCH_KEY.to_owned())
        );
        assert_eq!(r.f.asked(), NONE);
        Ok(())
    })
}

#[test]
fn delete_missing_equals_foreign() -> TestResult {
    block_on(async {
        for (ua, ub) in UID_PAIRS {
            for answer in [Answer::Yes, Answer::No, Answer::Fail] {
                let r = Rig::start(Answer::Yes, ua, ub).await?;
                r.import(r.a(), "k", EC_P12, answer).await?;
                let before = snapshot(&r.area(ua))?;
                let foreign = delete(&r.b, "k").await;
                let missing_b = delete(&r.b, "absent").await;
                let missing_a = delete(r.a(), "absent").await;
                assert_eq!(foreign, Err(ERROR_NO_SUCH_KEY.to_owned()), "{ua} {ub}");
                assert_eq!(missing_b, foreign);
                assert_eq!(missing_a, foreign);
                assert_eq!(r.f.asked(), NONE);
                assert_eq!(snapshot(&r.area(ua))?, before);
                assert_eq!(listed_ids(r.a()).await?, ["k"]);
            }
        }
        Ok(())
    })
}

#[test]
fn delete_without_credentials_is_unavailable() -> TestResult {
    block_on(async {
        for which in 0..2 {
            let sink = Arc::new(MemorySink::default());
            let f = if which == 0 {
                Fixture::start(Answer::Yes, |_: &Connection| NoCredentials, sink).await?
            } else {
                Fixture::start(Answer::Yes, |_: &Connection| MissingPid, sink).await?
            };
            common::import_with(&f, "k", EC_P12, PASSWORD).await?;
            let before = snapshot(&f.store_dir().join(common::uid().to_string()))?;
            assert_eq!(
                delete(&f.client, "k").await,
                Err(ERROR_AUTHORIZATION_UNAVAILABLE.to_owned()),
                "case {which}"
            );
            assert_eq!(f.asked(), NONE);
            assert_eq!(
                snapshot(&f.store_dir().join(common::uid().to_string()))?,
                before
            );
        }
        Ok(())
    })
}

#[test]
fn delete_asks_polkit_once_with_interaction() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        for id in ["one", "two"] {
            r.import(r.a(), id, EC_P12, Answer::Yes).await?;
        }
        delete(r.a(), "one").await?;
        let name = r.a().unique_name().ok_or("no name")?.to_string();
        assert_eq!(r.f.asked(), std::slice::from_ref(&name));
        assert_eq!(
            r.requests(),
            [(DELETE_ACTION_ID.to_owned(), ALLOW_INTERACTION)]
        );
        // The second delete of the same id finds no key and asks nothing.
        assert_eq!(
            delete(r.a(), "one").await,
            Err(ERROR_NO_SUCH_KEY.to_owned())
        );
        assert_eq!(r.f.asked().len(), 1);
        // A delete of another id asks again: nothing was kept from the first approval.
        delete(r.a(), "two").await?;
        assert_eq!(r.f.asked(), [name.clone(), name.clone()]);
        assert_eq!(r.requests().len(), 2);
        assert!(
            r.requests()
                .iter()
                .all(|q| q.0 == DELETE_ACTION_ID && q.1 == ALLOW_INTERACTION)
        );
        // An approved sign does not approve a later delete.
        r.import(r.a(), "three", EC_P12, Answer::Yes).await?;
        sign(r.a(), "three", CKM_ECDSA, &digest()).await?;
        delete(r.a(), "three").await?;
        let actions: Vec<String> = r.requests().into_iter().map(|q| q.0).collect();
        assert_eq!(actions, [ACTION_ID, DELETE_ACTION_ID]);
        Ok(())
    })
}

#[test]
fn delete_denied_and_unavailable_keep_the_key() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        r.import(r.a(), "k", EC_P12, Answer::Yes).await?;
        let before = snapshot(&r.area(1000))?;
        let cases = [
            (Answer::No, ERROR_POLKIT_DENIED),
            (Answer::Challenge, ERROR_POLKIT_DENIED),
            (Answer::Fail, ERROR_AUTHORIZATION_UNAVAILABLE),
        ];
        for (answer, want) in cases {
            r.f.set_answer(answer);
            assert_eq!(delete(r.a(), "k").await, Err(want.to_owned()));
            assert_eq!(snapshot(&r.area(1000))?, before);
            assert_eq!(listed_ids(r.a()).await?, ["k"]);
        }
        assert_eq!(r.f.asked().len(), 3);
        r.f.set_answer(Answer::Yes);
        assert_eq!(sign_err(r.a(), "k").await, "ok");
        Ok(())
    })
}

#[test]
fn delete_removes_everything() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        r.import(r.a(), "k", EC_P12, Answer::Yes).await?;
        r.import(r.a(), "other", RSA_P12, Answer::Yes).await?;
        let other_files: Vec<_> = snapshot(&r.area(1000))?
            .into_iter()
            .filter(|e| e.0.starts_with("other"))
            .collect();
        let cert_of = |id: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let record = Record::decode(&std::fs::read(r.area(1000).join(id))?)?;
            Ok(record.certificate().to_vec())
        };
        let old_cert = cert_of("k")?;
        let reply = call(r.a(), "DeleteKey", &("k",)).await?;
        assert!(reply.body().deserialize::<()>().is_ok());
        assert_eq!(listed_ids(r.a()).await?, ["other"]);
        let asked = r.f.asked().len();
        assert_eq!(sign_err(r.a(), "k").await, ERROR_NO_SUCH_KEY);
        assert_eq!(r.f.asked().len(), asked);
        assert_eq!(names(&r.area(1000))?, ["other"]);
        assert_eq!(snapshot(&r.area(1000))?, other_files);
        // The id can be imported again, with another certificate.
        call(r.a(), "ImportP12", &("k", OTHER_EC_P12.to_vec(), PASSWORD)).await?;
        assert_eq!(sign_err(r.a(), "k").await, "ok");
        assert_ne!(cert_of("k")?, old_cert);
        Ok(())
    })
}

#[test]
fn delete_leaves_other_uids_alone() -> TestResult {
    block_on(async {
        for (ua, ub) in UID_PAIRS {
            let r = Rig::start(Answer::Yes, ua, ub).await?;
            r.import(r.a(), "my-key", EC_P12, Answer::Yes).await?;
            r.import(&r.b, "my-key", OTHER_EC_P12, Answer::Yes).await?;
            let before_a = snapshot(&r.area(ua))?;
            delete(&r.b, "my-key").await?;
            assert_eq!(listed_ids(r.a()).await?, ["my-key"]);
            assert_eq!(sign_err(r.a(), "my-key").await, "ok");
            assert_eq!(snapshot(&r.area(ua))?, before_a, "{ua} {ub}");
            assert_eq!(listed_ids(&r.b).await?, NONE);
            assert_eq!(names(&r.area(ub))?, NONE);
            assert_eq!(sign_err(&r.b, "my-key").await, ERROR_NO_SUCH_KEY);
        }
        Ok(())
    })
}

#[cfg(unix)]
fn make_area_read_only(area: &Path) -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(area, std::fs::Permissions::from_mode(0o500))?;
    Ok(())
}

fn is_root() -> bool {
    common::uid() == 0
}

#[test]
fn delete_store_failures() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    block_on(async {
        let r = Rig::start(Answer::Yes, common::uid(), common::uid() + 1).await?;
        r.import(r.a(), "k", EC_P12, Answer::Yes).await?;
        let area = r.area(common::uid());
        let before = snapshot(&area)?;
        if !is_root() {
            // The area becomes read-only while polkit answers, after the lookup.
            let a = area.clone();
            r.f.on_request(move || {
                let _ = make_area_read_only(&a);
            });
            assert_eq!(delete(r.a(), "k").await, Err(ERROR_INTERNAL.to_owned()));
            *r.f.hook.lock().unwrap_or_else(PoisonError::into_inner) = None;
            std::fs::set_permissions(&area, std::fs::Permissions::from_mode(0o700))?;
            assert_eq!(snapshot(&area)?, before);
            // The entry already said `deleted`, so the key stays unusable although its files are
            // all still there (`delete_removal_failure_keeps_key_unusable` in `delete_audit.rs`).
            assert_eq!(sign_err(r.a(), "k").await, ERROR_NO_SUCH_KEY);
            assert_eq!(listed_ids(r.a()).await?, NONE);
            // Take the files away by hand, so the next part starts from a clean area.
            std::fs::remove_file(area.join("k"))?;
        }
        r.import(r.a(), "m", EC_P12, Answer::Yes).await?;
        // The record's mode is loosened while polkit answers: the store refuses to remove it.
        let record = area.join("m");
        let c = record.clone();
        r.f.on_request(move || {
            let _ = std::fs::set_permissions(&c, std::fs::Permissions::from_mode(0o644));
        });
        r.forget_asks();
        assert_eq!(delete(r.a(), "m").await, Err(ERROR_INTERNAL.to_owned()));
        *r.f.hook.lock().unwrap_or_else(PoisonError::into_inner) = None;
        assert_eq!(names(&area)?, ["m"]);
        assert_eq!(sign_err(r.a(), "m").await, ERROR_NO_SUCH_KEY);
        assert_eq!(listed_ids(r.a()).await?, NONE);
        // The key is unusable for good (its entry said `deleted`), so a second delete finds
        // nothing. The file is never touched and the id stays taken.
        assert_eq!(delete(r.a(), "m").await, Err(ERROR_NO_SUCH_KEY.to_owned()));
        assert!(record.is_file());
        let again = call(r.a(), "ImportP12", &("m", EC_P12.to_vec(), PASSWORD)).await;
        assert_eq!(
            again.map_err(|e| error_name(&e)).err(),
            Some(ERROR_KEY_ID_TAKEN.to_owned())
        );
        Ok(())
    })
}

#[test]
fn delete_of_a_record_that_vanished_is_no_such_key() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        r.import(r.a(), "k", EC_P12, Answer::Yes).await?;
        r.import(&r.b, "k", EC_P12, Answer::Yes).await?;
        // The record of the first user is taken away by hand: nothing is left of the key.
        std::fs::remove_file(r.area(1000).join("k"))?;
        assert_eq!(listed_ids(r.a()).await?, NONE);
        r.forget_asks();
        assert_eq!(delete(r.a(), "k").await, Err(ERROR_NO_SUCH_KEY.to_owned()));
        assert_eq!(r.f.asked().len(), 0);
        // The other user's record is untouched and deletes normally.
        assert_eq!(delete(&r.b, "k").await, Ok(()));
        assert_eq!(names(&r.area(1001))?, NONE);
        assert_eq!(r.f.asked().len(), 1);
        // The id is free again.
        call(r.a(), "ImportP12", &("k", EC_P12.to_vec(), PASSWORD)).await?;
        assert_eq!(sign_err(r.a(), "k").await, "ok");
        Ok(())
    })
}

#[test]
fn delete_of_a_record_that_does_not_parse_succeeds() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        r.import(r.a(), "k", EC_P12, Answer::Yes).await?;
        let path = r.area(1000).join("k");
        let mut bytes = std::fs::read(&path)?;
        bytes.truncate(20);
        std::fs::write(&path, bytes)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        delete(r.a(), "k").await?;
        assert_eq!(names(&r.area(1000))?, NONE);
        Ok(())
    })
}
