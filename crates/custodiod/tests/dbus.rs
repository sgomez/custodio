//! The D-Bus service against a private `dbus-daemon` with a fake polkit authority.

use std::collections::HashMap;
use std::error::Error;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use custodiod::audit::MemorySink;
use custodiod::credentials::BusCredentials;
use custodiod::dbus::{BUS_NAME, CKM_ECDSA, CKM_RSA_PKCS, Custodio, OBJECT_PATH};
use custodiod::polkit::PolkitAuthorizer;
use custodiod::store::KeyStore;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use zbus::connection::Builder;
use zbus::message::Message;
use zbus::{Connection, OwnedVariant, block_on, interface};

type TestResult = Result<(), Box<dyn Error>>;

const P256_P12: &[u8] = include_bytes!("fixtures/p256.p12");
const PASSWORD: &str = "test-password";
const ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";

struct Bus {
    child: Child,
    address: String,
}

impl Bus {
    fn start() -> Result<Self, Box<dyn Error>> {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()?;
        let mut address = String::new();
        BufReader::new(child.stdout.take().ok_or("no stdout")?).read_line(&mut address)?;
        Ok(Self {
            child,
            address: address.trim().to_owned(),
        })
    }

    async fn connect(&self) -> Result<Connection, Box<dyn Error>> {
        Ok(Builder::address(self.address.as_str()).build().await?)
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Fake polkit: approves while `approve` is set, and records the bus name of every subject.
struct FakePolkit {
    approve: Arc<AtomicBool>,
    asked: Arc<Mutex<Vec<String>>>,
}

#[interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl FakePolkit {
    // The `interface` macro needs owned argument types to deserialize the D-Bus message.
    #[allow(clippy::needless_pass_by_value)]
    fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedVariant>),
        action_id: String,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: String,
    ) -> (bool, bool, HashMap<String, String>) {
        let _ = (details, flags, cancellation_id);
        let name = subject
            .1
            .get("name")
            .and_then(|v| <&str>::try_from(v).ok())
            .unwrap_or_default()
            .to_owned();
        if let Ok(mut asked) = self.asked.lock() {
            asked.push(format!("{action_id} {name}"));
        }
        (self.approve.load(Ordering::SeqCst), false, HashMap::new())
    }
}

struct Fixture {
    _bus: Bus,
    _state: tempfile::TempDir,
    polkit: Connection,
    _service: Connection,
    client: Connection,
    approve: Arc<AtomicBool>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Fixture {
    async fn start(approve: bool) -> Result<Self, Box<dyn Error>> {
        let bus = Bus::start()?;
        let approve = Arc::new(AtomicBool::new(approve));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let polkit = bus.connect().await?;
        polkit
            .object_server()
            .at(
                "/org/freedesktop/PolicyKit1/Authority",
                FakePolkit {
                    approve: approve.clone(),
                    asked: asked.clone(),
                },
            )
            .await?;
        polkit.request_name("org.freedesktop.PolicyKit1").await?;

        let state = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(state.path().join("keys"))?);
        let service = bus.connect().await?;
        service
            .object_server()
            .at(
                OBJECT_PATH,
                Custodio::new(
                    store,
                    PolkitAuthorizer::new(service.clone()),
                    BusCredentials::new(service.clone()),
                    Arc::new(MemorySink::default()),
                ),
            )
            .await?;
        service.request_name(BUS_NAME).await?;

        let client = bus.connect().await?;
        Ok(Self {
            _bus: bus,
            _state: state,
            polkit,
            _service: service,
            client,
            approve,
            asked,
        })
    }

    async fn call<B>(&self, method: &str, body: &B) -> zbus::Result<Message>
    where
        B: zbus::export::serde::Serialize + zbus::zvariant::DynamicType,
    {
        self.client
            .call_method(
                Some(BUS_NAME),
                OBJECT_PATH,
                Some("com.rfirma.Custodio1"),
                method,
                body,
            )
            .await
    }

    async fn import(&self, id: &str) -> zbus::Result<String> {
        let reply = self
            .call("ImportP12", &(id, P256_P12.to_vec(), PASSWORD))
            .await?;
        reply.body().deserialize()
    }

    async fn sign(&self, id: &str, mechanism: u32, data: &[u8]) -> zbus::Result<Vec<u8>> {
        let reply = self
            .call("Sign", &(id, mechanism, 0u32, 0u32, data.to_vec()))
            .await?;
        reply.body().deserialize()
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().map(|a| a.clone()).unwrap_or_default()
    }

    fn client_name(&self) -> String {
        self.client
            .unique_name()
            .map(ToString::to_string)
            .unwrap_or_default()
    }
}

fn error_name(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, _, _) => name.as_str().to_owned(),
        // `fdo::Error` displays as "<name>: <message>".
        other => format!("{other}")
            .split(": ")
            .next()
            .unwrap_or_default()
            .to_owned(),
    }
}

fn verify(cert_der: &[u8], digest: &[u8], signature: &[u8]) -> TestResult {
    let cert = Certificate::from_der(cert_der)?;
    let point = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let key = VerifyingKey::from_sec1_bytes(point)?;
    key.verify_prehash(digest, &Signature::from_slice(signature)?)?;
    Ok(())
}

#[test]
fn import_list_and_approved_sign() -> TestResult {
    block_on(async {
        let f = Fixture::start(true).await?;
        let none: Vec<String> = f.call("ListKeys", &()).await?.body().deserialize()?;
        assert_eq!(none, Vec::<String>::new());
        assert_eq!(f.import("alice").await?, "ecdsa-p256");

        let keys: Vec<String> = f.call("ListKeys", &()).await?.body().deserialize()?;
        assert_eq!(keys, ["alice"]);
        let certs: Vec<(String, Vec<u8>)> = f
            .call("ListCertificates", &())
            .await?
            .body()
            .deserialize()?;
        let [(cert_id, cert_der)] = certs.as_slice() else {
            return Err("expected exactly one certificate".into());
        };
        assert_eq!(cert_id, "alice");

        let digest = [7u8; 32];
        let signature = f.sign("alice", CKM_ECDSA, &digest).await?;
        verify(cert_der, &digest, &signature)?;
        assert_eq!(
            f.asked(),
            vec![format!("com.rfirma.custodio.sign {}", f.client_name())]
        );
        Ok(())
    })
}

#[test]
fn denial_returns_an_error_and_no_signature() -> TestResult {
    block_on(async {
        let f = Fixture::start(true).await?;
        f.import("alice").await?;
        f.approve.store(false, Ordering::SeqCst);
        let err = f.sign("alice", CKM_ECDSA, &[7u8; 32]).await.err();
        let err = err.ok_or("denied sign returned a signature")?;
        assert_eq!(error_name(&err), ACCESS_DENIED);
        assert_eq!(f.asked().len(), 1);
        Ok(())
    })
}

#[test]
fn polkit_missing_is_a_refusal() -> TestResult {
    block_on(async {
        let f = Fixture::start(true).await?;
        f.import("alice").await?;
        f.polkit.release_name("org.freedesktop.PolicyKit1").await?;
        let err = f.sign("alice", CKM_ECDSA, &[7u8; 32]).await.err();
        let err = err.ok_or("sign succeeded without polkit")?;
        assert_eq!(error_name(&err), ACCESS_DENIED);
        Ok(())
    })
}

#[test]
fn two_signatures_ask_twice() -> TestResult {
    block_on(async {
        let f = Fixture::start(true).await?;
        f.import("alice").await?;
        f.sign("alice", CKM_ECDSA, &[1u8; 32]).await?;
        f.sign("alice", CKM_ECDSA, &[2u8; 32]).await?;
        assert_eq!(f.asked().len(), 2);
        // Approval of one call does not carry over to the next.
        f.approve.store(false, Ordering::SeqCst);
        assert!(f.sign("alice", CKM_ECDSA, &[3u8; 32]).await.is_err());
        assert_eq!(f.asked().len(), 3);
        Ok(())
    })
}

#[test]
fn bad_arguments_are_rejected_before_polkit() -> TestResult {
    block_on(async {
        let f = Fixture::start(true).await?;
        f.import("alice").await?;
        for (id, mechanism) in [
            ("../etc", CKM_ECDSA),
            ("alice-cert", CKM_ECDSA),
            ("alice", 0x9999),
        ] {
            let err = f.sign(id, mechanism, &[7u8; 32]).await.err();
            let err = err.ok_or("bad request succeeded")?;
            assert_eq!(
                error_name(&err),
                "org.freedesktop.DBus.Error.InvalidArgs",
                "{id}"
            );
        }
        // A mechanism that does not fit the key is refused after approval, with no signature.
        assert!(f.sign("alice", CKM_RSA_PKCS, &[7u8; 32]).await.is_err());
        assert!(f.sign("missing", CKM_ECDSA, &[7u8; 32]).await.is_err());
        assert_eq!(f.asked().len(), 2);
        Ok(())
    })
}

#[test]
fn import_errors_do_not_leak_the_password_or_store() -> TestResult {
    block_on(async {
        let f = Fixture::start(true).await?;
        let err = f
            .call("ImportP12", &("bob", P256_P12.to_vec(), "wrong-password"))
            .await
            .err()
            .ok_or("wrong password imported")?;
        assert!(!format!("{err:?}").contains("wrong-password"));
        let keys: Vec<String> = f.call("ListKeys", &()).await?.body().deserialize()?;
        assert_eq!(keys, Vec::<String>::new());
        f.import("bob").await?;
        assert!(f.import("bob").await.is_err());
        Ok(())
    })
}
