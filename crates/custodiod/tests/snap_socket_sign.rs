//! `Sign` on the snap socket (F176): the peer's key by its kernel uid, one polkit question per call on the peer's
//! pidfd, and the journal fields. In process: a private `dbus-daemon` with a scripted polkit, a listener served by
//! `serve` and the `test-seam` source for the peer's values. Waits are on replies and end of file, never a sleep.

use std::collections::VecDeque;
use std::error::Error;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex, PoisonError};

use custodiod::audit::{AuditSink, FailingSink, MemorySink, Outcome as AuditOutcome};
use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::{Credentials, seal};
use custodiod::dbus::{BUS_NAME, CKM_ECDSA, CKM_RSA_PKCS, OBJECT_PATH};
use custodiod::import::{credential_name, parse_p12};
use custodiod::polkit::PolkitAuthorizer;
use custodiod::snap_socket::peer::{Peer, Source};
use custodiod::snap_socket::{Outcome, Service, Signing, serve};
use custodiod::store::{KeyStore, Kind, Protected, Record};
use custodiod::tpm::open::NoTpm;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use secrecy::SecretString;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};
use zbus::connection::{AuthMechanism, Builder};
use zbus::{Connection, block_on};

type TestResult = Result<(), Box<dyn Error>>;

const GOOD: &str = "snap.firefox.firefox (enforce)";
const P256_P12: &[u8] = include_bytes!("fixtures/p256.p12");
const RSA_P12: &[u8] = include_bytes!("fixtures/rsa2048.p12");
const PASSWORD: &str = "test-password";
const UID: u32 = 4001;
const OTHER_UID: u32 = 4002;
const SENTINEL_P12: &[u8] = include_bytes!("fixtures/p256-sentinel.p12");

use crate::snap_polkit as polkit;
use polkit::{Answer, Bus, Call, FakePolkit, GarbledPolkit};

/// What the seam supplies for the next connection.
struct Creds {
    uid: u32,
    pid: u32,
    pidfd: OwnedFd,
}

fn own_pidfd() -> Result<OwnedFd, Box<dyn Error>> {
    pidfd_of(std::process::id())
}

fn pidfd_of(pid: u32) -> Result<OwnedFd, Box<dyn Error>> {
    let pid = rustix::process::Pid::from_raw(i32::try_from(pid)?).ok_or("pid 0")?;
    Ok(rustix::process::pidfd_open(
        pid,
        rustix::process::PidfdFlags::empty(),
    )?)
}

const SENTINEL_PASSWORD: &str = "P@ss-sentinel-7f3a91c4";

fn p12_record(owner: u32, id: &str, p12: &[u8]) -> Result<Record, Box<dyn Error>> {
    let password = if p12 == SENTINEL_P12 {
        SENTINEL_PASSWORD
    } else {
        PASSWORD
    };
    let parsed = parse_p12(p12, &SecretString::from(password.to_owned()))?;
    let sealed = seal(
        &MemoryCreds::host(),
        &credential_name(owner, id),
        &parsed.key,
    )?;
    Ok(Record::new(
        owner,
        id,
        Kind::EncryptedHost,
        &parsed.certificate,
        Protected::from_sealed(&sealed),
    )?)
}

struct Rig {
    _bus: Bus,
    _tmp: tempfile::TempDir,
    _polkit: Option<Connection>,
    _service_bus: Connection,
    path: PathBuf,
    next: Arc<Mutex<Creds>>,
    script: Arc<Mutex<VecDeque<Answer>>>,
    calls: Arc<Mutex<Vec<Call>>>,
    sink: Arc<MemorySink>,
}

#[derive(Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per variation of the rig"
)]
struct Options {
    no_authority: bool,
    garbled: bool,
    failing_sink: bool,
    rule: Option<bool>,
    sentinel: bool,
}

impl Rig {
    fn start(options: &Options) -> Result<Self, Box<dyn Error>> {
        let bus = Bus::start()?;
        let tmp = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(tmp.path().join("keys"))?);
        store.put(&p12_record(UID, "ec", P256_P12)?)?;
        store.put(&p12_record(UID, "rsa", RSA_P12)?)?;
        store.put(&p12_record(OTHER_UID, "theirs", P256_P12)?)?;
        if options.sentinel {
            store.put(&p12_record(UID, "sentinel", SENTINEL_P12)?)?;
        }
        let script = Arc::new(Mutex::new(VecDeque::new()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::new(MemorySink::default());
        let (polkit, service_bus) = block_on(async {
            let polkit = if options.no_authority {
                None
            } else {
                let c = bus.connect().await?;
                if options.garbled {
                    c.object_server()
                        .at("/org/freedesktop/PolicyKit1/Authority", GarbledPolkit)
                        .await?;
                } else {
                    c.object_server()
                        .at(
                            "/org/freedesktop/PolicyKit1/Authority",
                            FakePolkit {
                                script: Arc::clone(&script),
                                calls: Arc::clone(&calls),
                                rule: options.rule,
                            },
                        )
                        .await?;
                }
                c.request_name("org.freedesktop.PolicyKit1").await?;
                Some(c)
            };
            Ok::<_, Box<dyn Error>>((polkit, bus.connect().await?))
        })?;
        let next = Arc::new(Mutex::new(Creds {
            uid: UID,
            pid: std::process::id(),
            pidfd: own_pidfd()?,
        }));
        let sink_dyn: Arc<dyn AuditSink> = if options.failing_sink {
            Arc::new(FailingSink)
        } else {
            Arc::clone(&sink) as Arc<dyn AuditSink>
        };
        let creds: Arc<dyn Credentials> = Arc::new(MemoryCreds::host());
        let signing = Signing {
            authorizer: Arc::new(PolkitAuthorizer::new(service_bus.clone())),
            sink: sink_dyn,
            key_creds: Some(creds),
            tpm: Arc::new(NoTpm),
        };
        let seam = Arc::clone(&next);
        let service = Service::new(store, Arc::new(|_| {}))
            .with_signing(signing)
            .with_source(Source::Injected(Arc::new(move |_| {
                let c = seam.lock().unwrap_or_else(PoisonError::into_inner);
                Peer {
                    uid: Some(c.uid),
                    pid: Some(c.pid),
                    pidfd: c.pidfd.as_fd().try_clone_to_owned().ok(),
                    label: Some(GOOD.as_bytes().to_vec()),
                }
            })));
        let path = tmp.path().join("custodio.sock");
        let listener = UnixListener::bind(&path)?;
        let mut journal = Vec::new();
        let outcome = serve(
            "snap-firefox",
            listener,
            std::path::Path::new("/usr"),
            &mut journal,
            &service,
        );
        assert!(matches!(outcome, Outcome::Serving));
        Ok(Self {
            _bus: bus,
            _tmp: tmp,
            _polkit: polkit,
            _service_bus: service_bus,
            path,
            next,
            script,
            calls,
            sink,
        })
    }

    fn answers(&self, answers: &[Answer]) {
        self.script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(answers.iter().copied());
    }

    fn peer_is(&self, uid: u32, pid: u32, pidfd: OwnedFd) {
        *self.next.lock().unwrap_or_else(PoisonError::into_inner) = Creds { uid, pid, pidfd };
    }

    fn calls(&self) -> Vec<Call> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// A stock p2p client (`ANONYMOUS`).
    fn client(&self) -> Result<Connection, Box<dyn Error>> {
        let stream = UnixStream::connect(&self.path)?;
        Ok(block_on(
            Builder::unix_stream(stream)
                .p2p()
                .auth_mechanism(AuthMechanism::Anonymous)
                .build(),
        )?)
    }

    /// `Sign`; an error is its D-Bus name.
    #[allow(
        clippy::unused_self,
        reason = "a method of the rig reads better at the call sites"
    )]
    fn sign(
        &self,
        c: &Connection,
        id: &str,
        mechanism: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let reply = block_on(c.call_method(
            None::<&str>,
            OBJECT_PATH,
            Some(BUS_NAME),
            "Sign",
            &(id, mechanism, 0u32, 0u32, data),
        ));
        match reply {
            Ok(m) => m.body().deserialize::<Vec<u8>>().map_err(|e| e.to_string()),
            Err(zbus::Error::MethodError(name, _, _)) => Err(name.as_str().to_owned()),
            Err(other) => Err(other.to_string()),
        }
    }
}

fn spki_of(cert_der: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let cert = Certificate::from_der(cert_der)?;
    Ok(cert.tbs_certificate().subject_public_key_info().to_der()?)
}

fn cert_of(rig: &Rig, c: &Connection, id: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let _ = rig;
    let reply =
        block_on(c.call_method(None::<&str>, OBJECT_PATH, Some(BUS_NAME), "ListKeys", &()))?;
    let keys: Vec<(String, String, String, Vec<u8>)> = reply.body().deserialize()?;
    Ok(keys
        .into_iter()
        .find(|k| k.0 == id)
        .ok_or("no such key listed")?
        .3)
}

const DENIED: &str = "com.rfirma.Custodio1.Error.PolkitDenied";
const UNAVAILABLE: &str = "com.rfirma.Custodio1.Error.AuthorizationUnavailable";
const NO_KEY: &str = "com.rfirma.Custodio1.Error.NoSuchKey";

fn sleeper() -> Result<Child, Box<dyn Error>> {
    Ok(Command::new("sleep").arg("600").spawn()?)
}

#[test]
fn signs_own_key() -> TestResult {
    let rig = Rig::start(&Options::default())?;
    rig.answers(&[Answer::Yes, Answer::Yes]);
    let c = rig.client()?;
    let digest = [7u8; 32];
    let sig = rig.sign(&c, "ec", CKM_ECDSA, &digest)?;
    let cert = cert_of(&rig, &c, "ec")?;
    let point = Certificate::from_der(&cert)?
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes()
        .to_vec();
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)?
        .verify_prehash(&digest, &p256::ecdsa::Signature::from_slice(&sig)?)?;
    let data = [3u8; 40];
    let sig = rig.sign(&c, "rsa", CKM_RSA_PKCS, &data)?;
    let public = RsaPublicKey::from_public_key_der(&spki_of(&cert_of(&rig, &c, "rsa")?)?)?;
    public.verify(Pkcs1v15Sign::new_unprefixed(), &data, &sig)?;
    Ok(())
}

#[test]
fn other_uid_key_is_no_such_key() -> TestResult {
    let rig = Rig::start(&Options::default())?;
    rig.answers(&[Answer::Yes, Answer::Yes]);
    let c = rig.client()?;
    assert_eq!(
        rig.sign(&c, "theirs", CKM_ECDSA, &[1u8; 32]),
        Err(NO_KEY.to_owned())
    );
    assert_eq!(
        rig.sign(&c, "missing", CKM_ECDSA, &[1u8; 32]),
        Err(NO_KEY.to_owned())
    );
    assert!(rig.calls().is_empty());
    assert_eq!(rig.sink.entries().len(), 0);
    Ok(())
}

#[test]
fn claimed_uid_is_ignored() -> TestResult {
    // Another uid's key id and its own uid in the id text are just ids: the keys and the subject are the kernel
    // uid's.
    let rig = Rig::start(&Options::default())?;
    rig.answers(&[Answer::Yes]);
    let c = rig.client()?;
    assert_eq!(
        rig.sign(&c, &format!("{OTHER_UID}-theirs"), CKM_ECDSA, &[1u8; 32]),
        Err(NO_KEY.to_owned())
    );
    assert!(rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]).is_ok());
    assert_eq!(
        rig.calls().iter().map(|c| c.uid).collect::<Vec<_>>(),
        [Some(UID)]
    );
    Ok(())
}

#[test]
fn asks_polkit_once_on_the_pidfd_subject() -> TestResult {
    let rig = Rig::start(&Options::default())?;
    let mut child = sleeper()?;
    rig.peer_is(UID, child.id(), pidfd_of(child.id())?);
    rig.answers(&[Answer::Yes]);
    let c = rig.client()?;
    assert!(rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]).is_ok());
    let calls = rig.calls();
    let _ = child.kill();
    let _ = child.wait();
    let [call] = calls.as_slice() else {
        return Err(format!("expected one polkit call, saw {}", calls.len()).into());
    };
    assert_eq!(call.kind, "unix-process");
    assert_eq!(call.keys, ["pidfd", "uid"]);
    assert_eq!(call.uid, Some(UID));
    assert_eq!(call.fd_pid, Some(child.id()));
    assert_ne!(call.fd_pid, Some(std::process::id()));
    assert_eq!(call.action, "com.rfirma.custodio.sign");
    assert_eq!(call.flags, 1);
    Ok(())
}

#[test]
fn denial_is_polkit_denied() -> TestResult {
    let rig = Rig::start(&Options::default())?;
    rig.answers(&[Answer::No]);
    let c = rig.client()?;
    assert_eq!(
        rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]),
        Err(DENIED.to_owned())
    );
    let entries = rig.sink.entries();
    let [entry] = entries.as_slice() else {
        return Err("expected one entry".into());
    };
    assert_eq!(entry.outcome(), AuditOutcome::Denied);
    Ok(())
}

#[test]
fn polkit_errors_are_authorization_unavailable() -> TestResult {
    for case in 0..3 {
        let rig = Rig::start(&Options {
            no_authority: case == 0,
            garbled: case == 2,
            ..Options::default()
        })?;
        rig.answers(&[Answer::Fail]);
        let c = rig.client()?;
        assert_eq!(
            rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]),
            Err(UNAVAILABLE.to_owned()),
            "case {case}"
        );
        let entries = rig.sink.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries.first().map(custodiod::audit::Entry::outcome),
            Some(AuditOutcome::AuthorizationUnavailable)
        );
    }
    Ok(())
}

#[test]
fn old_polkit_fails_closed() -> TestResult {
    let rig = Rig::start(&Options::default())?;
    rig.answers(&[Answer::OldPolkit, Answer::Yes]);
    let c = rig.client()?;
    assert_eq!(
        rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]),
        Err(UNAVAILABLE.to_owned())
    );
    let calls = rig.calls();
    assert_eq!(calls.len(), 1, "no retry with another subject");
    assert_eq!(calls.first().map(|c| c.kind.as_str()), Some("unix-process"));
    Ok(())
}

#[test]
fn exited_peer_is_authorization_unavailable() -> TestResult {
    let rig = Rig::start(&Options::default())?;
    let mut live = sleeper()?;
    rig.peer_is(UID, live.id(), pidfd_of(live.id())?);
    rig.answers(&[Answer::Yes, Answer::Yes]);
    let control = rig.sign(&rig.client()?, "ec", CKM_ECDSA, &[1u8; 32]);
    let mut dead = sleeper()?;
    let dead_fd = pidfd_of(dead.id())?;
    rig.peer_is(UID, dead.id(), dead_fd);
    dead.kill()?;
    dead.wait()?;
    let exited = rig.sign(&rig.client()?, "ec", CKM_ECDSA, &[1u8; 32]);
    let _ = live.kill();
    let _ = live.wait();
    assert!(control.is_ok(), "a live peer signs: {control:?}");
    assert_eq!(exited, Err(UNAVAILABLE.to_owned()));
    assert_eq!(rig.sink.entries().len(), 2);
    assert_eq!(
        rig.sink
            .entries()
            .last()
            .map(custodiod::audit::Entry::outcome),
        Some(AuditOutcome::AuthorizationUnavailable)
    );
    Ok(())
}

#[test]
fn every_call_asks_polkit() -> TestResult {
    let rig = Rig::start(&Options::default())?;
    rig.answers(&[Answer::Yes, Answer::No, Answer::Yes]);
    let c = rig.client()?;
    assert!(rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]).is_ok());
    assert_eq!(
        rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]),
        Err(DENIED.to_owned())
    );
    assert!(rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]).is_ok());
    assert_eq!(rig.calls().len(), 3);
    Ok(())
}

#[test]
fn subject_uid_differs_from_the_callers() -> TestResult {
    // The scripted polkit applies the polkit 127 rule: a subject uid other than the caller's (`OTHER_UID` stands
    // for the service's own) is refused unless the shipped policy carries the owner annotation.
    let policy = std::fs::read_to_string(format!(
        "{}/../../data/com.rfirma.custodio.policy",
        env!("CARGO_MANIFEST_DIR")
    ))?;
    let has_owner = policy.contains("org.freedesktop.policykit.owner");
    let rig = Rig::start(&Options {
        rule: Some(has_owner),
        ..Options::default()
    })?;
    rig.answers(&[Answer::Yes]);
    let c = rig.client()?;
    assert!(rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]).is_ok());
    let uids: Vec<_> = rig.calls().iter().map(|c| c.uid).collect();
    assert_eq!(uids, [Some(UID)]);
    Ok(())
}

#[test]
fn socket_entries_carry_transport_label_and_peer() -> TestResult {
    let rig = Rig::start(&Options::default())?;
    let mut child = sleeper()?;
    rig.peer_is(UID, child.id(), pidfd_of(child.id())?);
    rig.answers(&[Answer::Yes, Answer::No, Answer::Fail, Answer::Yes]);
    let c = rig.client()?;
    let _ = rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]);
    let _ = rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]);
    let _ = rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]);
    // Approved, but the data is not a digest for the key: the signature fails after approval.
    let _ = rig.sign(&c, "ec", CKM_ECDSA, &[]);
    let _ = child.kill();
    let _ = child.wait();
    let entries = rig.sink.entries();
    let outcomes: Vec<_> = entries
        .iter()
        .map(custodiod::audit::Entry::outcome)
        .collect();
    assert_eq!(
        outcomes,
        [
            AuditOutcome::Signed,
            AuditOutcome::Denied,
            AuditOutcome::AuthorizationUnavailable,
            AuditOutcome::SigningFailed
        ]
    );
    for e in &entries {
        let f = e.fields();
        let get = |n: &str| f.iter().find(|(k, _)| *k == n).map(|(_, v)| v.as_str());
        assert_eq!(get("CUSTODIO_TRANSPORT"), Some("socket"));
        assert_eq!(get("CUSTODIO_PEER_LABEL"), Some(GOOD));
        assert_eq!(get("CUSTODIO_UID"), Some(UID.to_string().as_str()));
        assert_eq!(get("CUSTODIO_PID"), Some(child.id().to_string().as_str()));
        assert_eq!(get("CUSTODIO_APP_ID_STATE"), Some("undetermined"));
        assert_ne!(
            get("CUSTODIO_PID"),
            Some(std::process::id().to_string().as_str())
        );
    }
    Ok(())
}

#[test]
fn audit_failure_is_audit_unavailable() -> TestResult {
    let rig = Rig::start(&Options {
        failing_sink: true,
        ..Options::default()
    })?;
    rig.answers(&[Answer::Yes]);
    let c = rig.client()?;
    assert_eq!(
        rig.sign(&c, "ec", CKM_ECDSA, &[1u8; 32]),
        Err("com.rfirma.Custodio1.Error.AuditUnavailable".to_owned())
    );
    Ok(())
}

#[test]
fn no_secret_in_entries_or_errors() -> TestResult {
    let rig = Rig::start(&Options {
        sentinel: true,
        ..Options::default()
    })?;
    rig.answers(&[Answer::Yes, Answer::No]);
    let c = rig.client()?;
    let data = [0x5Au8; 32];
    let signed = rig.sign(&c, "sentinel", CKM_ECDSA, &data)?;
    let denied = rig
        .sign(&c, "sentinel", CKM_ECDSA, &data)
        .err()
        .unwrap_or_default();
    let shown = format!("{:?}{denied}", rig.sink.entries());
    let key = parse_p12(
        SENTINEL_P12,
        &SecretString::from(SENTINEL_PASSWORD.to_owned()),
    )?;
    let hex = |b: &[u8]| {
        b.iter().fold(String::new(), |mut out, x| {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{x:02x}"));
            out
        })
    };
    let secret = secrecy::ExposeSecret::expose_secret(&key.key);
    for needle in [hex(secret), hex(&data), hex(&signed)] {
        assert!(!shown.contains(&needle));
    }
    for (_, v) in rig
        .sink
        .entries()
        .iter()
        .flat_map(custodiod::audit::Entry::fields)
    {
        assert!(!v.contains("sentinel-secret"));
    }
    Ok(())
}
