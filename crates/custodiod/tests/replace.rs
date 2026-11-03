//! `ReplaceCertificate` over a private bus: the bounds, the caller's own keys only, polkit once under
//! the replace action, the public-key comparison and what is left on disk. Callers have uids
//! through a name table.

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

use std::collections::HashMap;
use std::future::{Future, ready};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use custodio_client::{
    ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_CERTIFICATE_MISMATCH, ERROR_INTERNAL,
    ERROR_INVALID_ARGS, ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED, MAX_CERT_LEN,
};
use custodiod::audit::{Caller, MemorySink};
use custodiod::credentials::{CallerCredentials, CredentialsError};
use custodiod::polkit::{ACTION_ID, REPLACE_ACTION_ID};
use zbus::{Connection, block_on};

use bus::{Answer, Fixture, TestResult, call, error_name, sign};
use common::{CKM_ECDSA, CKM_RSA_PKCS, EC_P12, MissingPid, PASSWORD, RSA_P12, digest, digest_info};

const OTHER_EC_P12: &[u8] = include_bytes!("fixtures/p256-other.p12");
const OTHER_EC_RECERT: &[u8] = include_bytes!("fixtures/cert-p256-other-recert.der");
const P256_RECERT: &[u8] = include_bytes!("fixtures/cert-p256-recert.der");
const RSA_RECERT: &[u8] = include_bytes!("fixtures/cert-rsa2048-recert.der");
const P256_EXPIRED: &[u8] = include_bytes!("fixtures/cert-p256-expired.der");
const RSA_EXPIRED: &[u8] = include_bytes!("fixtures/cert-rsa2048-expired.der");
const P256_OTHER: &[u8] = include_bytes!("fixtures/cert-p256-other.der");
const RSA_OTHER: &[u8] = include_bytes!("fixtures/cert-rsa2048-other.der");
const P384: &[u8] = include_bytes!("fixtures/cert-p384.der");
const ED25519: &[u8] = include_bytes!("fixtures/cert-ed25519.der");
const UID_PAIRS: [(u32, u32); 2] = [(1000, 1001), (0, 1000)];
const ALLOW_INTERACTION: u32 = 1;
const NONE: [String; 0] = [];

#[path = "replace/concurrent.rs"]
mod concurrent;

type Listed = Vec<(String, String, Vec<u8>)>;

/// Name → caller table; counts the lookups.
#[derive(Clone, Default)]
struct ByName(Arc<Mutex<HashMap<String, Caller>>>, Arc<AtomicUsize>);

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
        self.1.fetch_add(1, Ordering::SeqCst);
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
    lookups: Arc<AtomicUsize>,
}

impl Rig {
    async fn start(
        answer: Answer,
        uid_a: u32,
        uid_b: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let creds = ByName::default();
        let (c, lookups) = (creds.clone(), Arc::clone(&creds.1));
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
        Ok(Self { f, b, a2, lookups })
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

async fn replace(c: &Connection, id: &str, cert: &[u8]) -> Result<(), String> {
    let body = (id, cert.to_vec());
    let pending = call(c, "ReplaceCertificate", &body);
    match deadline::within(std::time::Duration::from_secs(15), pending).await {
        Some(reply) => reply.map(|_| ()).map_err(|e| error_name(&e)),
        None => Err("ReplaceCertificate did not return".to_owned()),
    }
}

async fn list(c: &Connection) -> zbus::Result<Listed> {
    let mut keys: Listed = call(c, "ListKeys", &()).await?.body().deserialize()?;
    keys.sort();
    Ok(keys)
}

async fn certificate_of(c: &Connection, id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = list(c).await?.into_iter().find(|k| k.0 == id);
    Ok(key.ok_or("key not listed")?.2)
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

fn is_root() -> bool {
    common::uid() == 0
}

#[test]
fn replace_rejects_bad_arguments() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        r.import(r.a(), "k", EC_P12, Answer::Yes).await?;
        let before = snapshot(&r.area(1000))?;
        let long = "a".repeat(60);
        let mut trailing = P256_RECERT.to_vec();
        trailing.push(0);
        let mut oversized = P256_RECERT.to_vec();
        oversized.resize(MAX_CERT_LEN + 1, 0);
        let truncated = P256_RECERT
            .get(..P256_RECERT.len() - 1)
            .unwrap_or_default()
            .to_vec();
        let sequence = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        let bad_certs: [&[u8]; 6] = [
            &oversized,
            b"",
            b"random bytes",
            &trailing,
            &truncated,
            &sequence,
        ];
        let lookups = r.lookups.load(Ordering::SeqCst);
        // An existing key and a missing one must both answer `InvalidArgs`.
        for id in ["k", "absent"] {
            for cert in bad_certs {
                assert_eq!(
                    replace(r.a(), id, cert).await,
                    Err(ERROR_INVALID_ARGS.to_owned()),
                    "{id} {} bytes",
                    cert.len()
                );
            }
        }
        for id in ["", long.as_str(), "bad id!", "../k", "k-cert", "x-cert"] {
            assert_eq!(
                replace(r.a(), id, P256_RECERT).await,
                Err(ERROR_INVALID_ARGS.to_owned()),
                "{id:?}"
            );
        }
        assert_eq!(r.f.asked(), NONE);
        assert_eq!(r.lookups.load(Ordering::SeqCst), lookups);
        assert_eq!(snapshot(&r.area(1000))?, before);
        Ok(())
    })
}

#[test]
fn replace_missing_equals_foreign() -> TestResult {
    block_on(async {
        for (ua, ub, answer) in UID_PAIRS
            .iter()
            .flat_map(|&(a, b)| [Answer::Yes, Answer::No, Answer::Fail].map(|n| (a, b, n)))
        {
            let r = Rig::start(Answer::Yes, ua, ub).await?;
            r.import(r.a(), "k", EC_P12, Answer::Yes).await?;
            r.f.set_answer(answer);
            let before = snapshot(&r.area(ua))?;
            let foreign = replace(&r.b, "k", P256_RECERT).await;
            let missing_b = replace(&r.b, "absent", P256_RECERT).await;
            let missing_a = replace(r.a(), "absent", P256_RECERT).await;
            assert_eq!(foreign, Err(ERROR_NO_SUCH_KEY.to_owned()), "{ua} {ub}");
            assert_eq!(missing_b, foreign);
            assert_eq!(missing_a, foreign);
            assert_eq!(r.f.asked(), NONE);
            assert_eq!(snapshot(&r.area(ua))?, before);
            assert_eq!(
                certificate_of(r.a(), "k").await?,
                std::fs::read(r.area(ua).join("k-cert"))?
            );
        }
        Ok(())
    })
}

#[test]
fn replace_without_credentials_is_unavailable() -> TestResult {
    block_on(async {
        let f = Fixture::start(
            Answer::Yes,
            |_: &Connection| MissingPid,
            Arc::new(MemorySink::default()),
        )
        .await?;
        common::import_with(&f, "k", EC_P12, PASSWORD).await?;
        let area = f.store_dir().join(common::uid().to_string());
        let before = snapshot(&area)?;
        assert_eq!(
            replace(&f.client, "k", P256_RECERT).await,
            Err(ERROR_AUTHORIZATION_UNAVAILABLE.to_owned())
        );
        assert_eq!(f.asked(), NONE);
        assert_eq!(snapshot(&area)?, before);
        Ok(())
    })
}

#[test]
fn replace_asks_polkit_once_with_interaction() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        for id in ["one", "two"] {
            r.import(r.a(), id, EC_P12, Answer::Yes).await?;
        }
        replace(r.a(), "one", P256_RECERT).await?;
        let name = r.a().unique_name().ok_or("no name")?.to_string();
        assert_eq!(r.f.asked(), std::slice::from_ref(&name));
        assert_eq!(
            r.requests(),
            [(REPLACE_ACTION_ID.to_owned(), ALLOW_INTERACTION)]
        );
        assert_eq!(REPLACE_ACTION_ID, "com.rfirma.custodio.replace-certificate");
        // The same replace again asks again; so does one of another id.
        replace(r.a(), "one", P256_RECERT).await?;
        assert_eq!(r.f.asked().len(), 2);
        replace(r.a(), "two", P256_RECERT).await?;
        assert_eq!(r.f.asked(), [name.clone(), name.clone(), name.clone()]);
        assert!(
            r.requests()
                .iter()
                .all(|q| q.0 == REPLACE_ACTION_ID && q.1 == ALLOW_INTERACTION)
        );
        // An approved sign does not approve a later replace, nor the other way round.
        r.forget_asks();
        sign(r.a(), "one", CKM_ECDSA, &digest()).await?;
        replace(r.a(), "one", P256_RECERT).await?;
        sign(r.a(), "one", CKM_ECDSA, &digest()).await?;
        let actions: Vec<String> = r.requests().into_iter().map(|q| q.0).collect();
        assert_eq!(actions, [ACTION_ID, REPLACE_ACTION_ID, ACTION_ID]);
        // A mismatch is decided after exactly one ask.
        r.forget_asks();
        assert_eq!(
            replace(r.a(), "one", P256_OTHER).await,
            Err(ERROR_CERTIFICATE_MISMATCH.to_owned())
        );
        assert_eq!(r.f.asked().len(), 1);
        Ok(())
    })
}

#[test]
fn replace_denied_and_unavailable_keep_the_certificate() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        r.import(r.a(), "k", EC_P12, Answer::Yes).await?;
        let before = snapshot(&r.area(1000))?;
        let listed = list(r.a()).await?;
        let cases = [
            (Answer::No, ERROR_POLKIT_DENIED),
            (Answer::Challenge, ERROR_POLKIT_DENIED),
            (Answer::Fail, ERROR_AUTHORIZATION_UNAVAILABLE),
        ];
        for (answer, want) in cases {
            r.f.set_answer(answer);
            assert_eq!(replace(r.a(), "k", P256_RECERT).await, Err(want.to_owned()));
            assert_eq!(snapshot(&r.area(1000))?, before);
            assert_eq!(list(r.a()).await?, listed);
        }
        assert_eq!(r.f.asked().len(), 3);
        r.f.set_answer(Answer::Yes);
        assert_eq!(sign_err(r.a(), "k").await, "ok");
        Ok(())
    })
}

#[test]
fn replace_with_matching_certificate() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        let cases = [
            ("ec", EC_P12, "ecdsa-p256", [P256_RECERT, P256_EXPIRED]),
            ("rsa", RSA_P12, "rsa2048", [RSA_RECERT, RSA_EXPIRED]),
        ];
        for (id, p12, kind, certs) in cases {
            r.import(r.a(), id, p12, Answer::Yes).await?;
            let original = certificate_of(r.a(), id).await?;
            // The same key with a new serial and subject, an expired certificate, and the
            // byte-identical certificate again.
            for cert in [certs[0], certs[1], &original, certs[0]] {
                let key_path = r.area(1000).join(id);
                let (key_bytes, key_meta) =
                    (std::fs::read(&key_path)?, std::fs::metadata(&key_path)?);
                let others = snapshot(&r.area(1000))?
                    .into_iter()
                    .filter(|e| e.0 != format!("{id}-cert") && e.0 != id)
                    .collect::<Vec<_>>();
                replace(r.a(), id, cert).await?;
                let listed: Vec<_> = list(r.a())
                    .await?
                    .into_iter()
                    .filter(|k| k.0 == id)
                    .collect();
                assert_eq!(listed, [(id.to_owned(), kind.to_owned(), cert.to_vec())]);
                assert_eq!(std::fs::read(&key_path)?, key_bytes);
                let after = std::fs::metadata(&key_path)?;
                assert_eq!(after.modified()?, key_meta.modified()?);
                assert_eq!(after.ino(), key_meta.ino());
                let rest = snapshot(&r.area(1000))?
                    .into_iter()
                    .filter(|e| e.0 != format!("{id}-cert") && e.0 != id)
                    .collect::<Vec<_>>();
                assert_eq!(rest, others);
                assert_eq!(
                    std::fs::read(r.area(1000).join(format!("{id}-cert")))?,
                    cert
                );
                for entry in std::fs::read_dir(r.area(1000))? {
                    let m = std::fs::metadata(entry?.path())?;
                    assert_eq!(m.mode() & 0o777, 0o600);
                }
                assert_eq!(std::fs::metadata(r.area(1000))?.mode() & 0o777, 0o700);
            }
        }
        // Both keys and certificates, and no temporary file.
        assert_eq!(names(&r.area(1000))?, ["ec", "ec-cert", "rsa", "rsa-cert"]);
        Ok(())
    })
}

#[path = "replace/outcomes.rs"]
mod outcomes;
