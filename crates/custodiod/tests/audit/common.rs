//! Helpers shared by the audit tests: fixtures, credentials fakes and the entry assertion.

use std::collections::HashMap;
use std::future::{Future, ready};
use std::sync::{Arc, Mutex, PoisonError};

use custodiod::audit::{AuditMechanism, Caller, Entry, MemorySink, Outcome};
use custodiod::credentials::{BusCredentials, CallerCredentials, CredentialsError, caller_from};
use zbus::{Connection, OwnedVariant};

use super::bus::{Answer, Fixture, TestResult, call};

pub const EC_P12: &[u8] = include_bytes!("../fixtures/p256.p12");
pub const RSA_P12: &[u8] = include_bytes!("../fixtures/rsa2048.p12");
pub const PASSWORD: &str = "test-password";
/// The same keys as `EC_P12` and `RSA_P12`, protected by `SENTINEL_PASSWORD`.
pub const EC_SENTINEL_P12: &[u8] = include_bytes!("../fixtures/p256-sentinel.p12");
pub const RSA_SENTINEL_P12: &[u8] = include_bytes!("../fixtures/rsa2048-sentinel.p12");
pub const SENTINEL_PASSWORD: &str = "P@ss-sentinel-7f3a91c4";
pub const CKM_RSA_PKCS: u32 = 0x0001;
pub const CKM_ECDSA: u32 = 0x1041;
pub const ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";

/// SHA-256 `DigestInfo` prefix.
const SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

pub fn digest() -> Vec<u8> {
    (0..32u8).map(|i| 0xA0 + i).collect()
}

pub fn digest_info() -> Vec<u8> {
    let mut v = SHA256_PREFIX.to_vec();
    v.extend(digest());
    v
}

/// The test process's uid, pid and a fixture with the real `BusCredentials`.
pub async fn fixture(
    answer: Answer,
    sink: &Arc<MemorySink>,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    Fixture::start(
        answer,
        |c: &Connection| BusCredentials::new(c.clone()),
        sink.clone(),
    )
    .await
}

pub async fn import(f: &Fixture, id: &str, p12: &[u8]) -> TestResult {
    import_with(f, id, p12, PASSWORD).await
}

pub async fn import_with(f: &Fixture, id: &str, p12: &[u8], password: &str) -> TestResult {
    call(&f.client, "ImportP12", &(id, p12.to_vec(), password)).await?;
    Ok(())
}

pub fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

pub fn assert_entry(e: &Entry, key: &str, mechanism: AuditMechanism, outcome: Outcome) {
    assert_eq!(
        e.caller(),
        Some(Caller {
            uid: uid(),
            pid: std::process::id()
        })
    );
    assert_eq!(e.key_id().as_str(), key);
    assert_eq!(e.mechanism(), Some(mechanism));
    assert_eq!(e.outcome(), outcome);
}

/// Credentials that always fail.
pub struct NoCredentials;

impl CallerCredentials for NoCredentials {
    fn credentials(
        &self,
        _: &str,
    ) -> impl Future<Output = Result<Caller, CredentialsError>> + Send {
        ready(Err(CredentialsError::Bus))
    }
}

/// A bus reply without `ProcessID`, run through `caller_from`.
pub struct MissingPid;

impl CallerCredentials for MissingPid {
    fn credentials(
        &self,
        _: &str,
    ) -> impl Future<Output = Result<Caller, CredentialsError>> + Send {
        let map: HashMap<String, OwnedVariant> =
            HashMap::from([("UnixUserID".to_owned(), OwnedVariant::from(1000u32))]);
        ready(caller_from(&map))
    }
}

/// The real credentials, recording the sender names it was asked about.
pub struct Recording {
    pub inner: BusCredentials,
    pub names: Arc<Mutex<Vec<String>>>,
}

impl CallerCredentials for Recording {
    async fn credentials(&self, sender: &str) -> Result<Caller, CredentialsError> {
        self.names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(sender.to_owned());
        self.inner.credentials(sender).await
    }
}
