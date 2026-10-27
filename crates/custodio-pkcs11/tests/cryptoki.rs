//! The built module loaded through the `cryptoki` crate, against the real service on a private
//! `dbus-daemon` with a fake polkit authority.
//!
//! The module reads the bus address from `DBUS_SYSTEM_BUS_ADDRESS`, which cannot be set safely
//! in a running multi-threaded test process. So each scenario runs the `client` test below in a
//! child process (this same test binary) with that variable set; the parent hosts the bus, the
//! fake polkit and the service, and checks what the child printed and what polkit was asked.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as P11Error, RvError};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use cryptoki::types::Ulong;
use custodiod::dbus::{BUS_NAME, Custodio, OBJECT_PATH};
use custodiod::import::import_p12;
use custodiod::polkit::PolkitAuthorizer;
use custodiod::sign::{Mechanism as ServiceMechanism, sign};
use custodiod::store::KeyStore;
use secrecy::SecretString;
use zbus::connection::Builder;
use zbus::{OwnedVariant, block_on, interface};

type TestResult = Result<(), Box<dyn Error>>;

const RSA_P12: &[u8] = include_bytes!("fixtures/rsa2048.p12");
const EC_P12: &[u8] = include_bytes!("fixtures/p256.p12");
const PASSWORD: &str = "test-password";
const DATA: &[u8] = b"data to be signed by the custodio test";
const MODE_VAR: &str = "CUSTODIO_TEST_MODE";
const MODULE_VAR: &str = "CUSTODIO_TEST_MODULE";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

// ---------------------------------------------------------------- the child: a PKCS#11 consumer

fn module() -> Result<Pkcs11, Box<dyn Error>> {
    let pkcs11 = Pkcs11::new(std::env::var(MODULE_VAR)?)?;
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    Ok(pkcs11)
}

fn find(session: &Session, class: ObjectClass) -> Result<ObjectHandle, Box<dyn Error>> {
    let found = session.find_objects(&[Attribute::Class(class)])?;
    assert_eq!(found.len(), 1, "one {class:?} per token");
    Ok(found[0])
}

/// Lists, finds and signs on every token; prints what the parent checks.
fn basic(pkcs11: &Pkcs11) -> TestResult {
    let slots = pkcs11.get_slots_with_token()?;
    assert_eq!(slots.len(), 2, "one token per key");
    for slot in slots {
        let label = pkcs11.get_token_info(slot)?.label().to_owned();
        let session = pkcs11.open_ro_session(slot)?;
        let cert = find(&session, ObjectClass::CERTIFICATE)?;
        let key = find(&session, ObjectClass::PRIVATE_KEY)?;
        let Some(Attribute::Value(der)) = session
            .get_attributes(cert, &[AttributeType::Value])?
            .into_iter()
            .next()
        else {
            return Err("no certificate value".into());
        };
        println!("CERT {label} {}", hex(&der));
        // The key is found by the certificate's id, as NSS does.
        let ids = session.get_attributes(cert, &[AttributeType::Id])?;
        let by_id =
            session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), ids[0].clone()])?;
        assert_eq!(by_id, vec![key]);
        // The private key value is never given out.
        let value = session.get_attributes(key, &[AttributeType::Value]);
        assert!(
            !matches!(value.as_deref(), Ok([Attribute::Value(_)])),
            "{value:?}"
        );
        let mechs = pkcs11.get_mechanism_list(slot)?;
        if label == "ec" {
            assert_eq!(mechs, vec![MechanismType::ECDSA]);
            let sig = session.sign(&Mechanism::Ecdsa, key, &[7; 32])?;
            println!("SIG ec ecdsa {}", hex(&sig));
        } else {
            assert!(mechs.contains(&MechanismType::RSA_PKCS));
            let sig = session.sign(&Mechanism::RsaPkcs, key, DATA)?;
            println!("SIG rsa pkcs {}", hex(&sig));
            let pss = PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: Ulong::from(32),
            };
            let sig = session.sign(&Mechanism::RsaPkcsPss(pss), key, &[9; 32])?;
            println!("SIG rsa pss {}", sig.len());
            // An ECDSA mechanism on an RSA key, and a bad mgf, are refused before the service.
            assert!(session.sign(&Mechanism::Ecdsa, key, DATA).is_err());
            let bad = PkcsPssParams {
                mgf: PkcsMgfType::MGF1_SHA384,
                ..pss
            };
            assert!(
                session
                    .sign(&Mechanism::RsaPkcsPss(bad), key, &[9; 32])
                    .is_err()
            );
        }
    }
    Ok(())
}

fn first_key(pkcs11: &Pkcs11) -> Result<(Session, ObjectHandle), Box<dyn Error>> {
    let slot = *pkcs11.get_slots_with_token()?.first().ok_or("no token")?;
    let session = pkcs11.open_ro_session(slot)?;
    let key = find(&session, ObjectClass::PRIVATE_KEY)?;
    Ok((session, key))
}

fn is_rv(e: &P11Error, rv: RvError) -> bool {
    matches!(e, P11Error::Pkcs11(got, _) if *got == rv)
}

fn denied(pkcs11: &Pkcs11) -> TestResult {
    let (session, key) = first_key(pkcs11)?;
    let err = session
        .sign(&Mechanism::Ecdsa, key, &[1; 32])
        .expect_err("signature must be refused");
    assert!(is_rv(&err, RvError::FunctionFailed), "{err:?}");
    // A refusal ends the operation; the next signature starts from scratch and asks again.
    let err = session
        .sign(&Mechanism::Ecdsa, key, &[1; 32])
        .expect_err("still refused");
    assert!(is_rv(&err, RvError::FunctionFailed), "{err:?}");
    Ok(())
}

fn unsupported(pkcs11: &Pkcs11) -> TestResult {
    let (session, key) = first_key(pkcs11)?;
    for err in [
        session.generate_random_vec(8).expect_err("random"),
        session.destroy_object(key).expect_err("destroy"),
        session
            .login(cryptoki::session::UserType::User, None)
            .expect_err("login"),
    ] {
        assert!(is_rv(&err, RvError::FunctionNotSupported), "{err:?}");
    }
    assert!(
        pkcs11
            .open_rw_session(pkcs11.get_slots_with_token()?[0])
            .is_err(),
        "read-write sessions are refused"
    );
    Ok(())
}

fn no_service(pkcs11: &Pkcs11) -> TestResult {
    assert_eq!(pkcs11.get_slots_with_token()?, vec![]);
    Ok(())
}

/// Many threads, each with its own session, sign at once.
fn threads(pkcs11: &Pkcs11) -> TestResult {
    let pkcs11 = Arc::new(Pkcs11::clone(pkcs11));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let pkcs11 = pkcs11.clone();
            std::thread::spawn(move || -> Result<(), String> {
                for _ in 0..3 {
                    let (session, key) = first_key(&pkcs11).map_err(|e| e.to_string())?;
                    let sig = session
                        .sign(&Mechanism::Ecdsa, key, &[3; 32])
                        .map_err(|e| e.to_string())?;
                    if sig.len() != 64 {
                        return Err("bad length".into());
                    }
                }
                Ok(())
            })
        })
        .collect();
    for w in workers {
        w.join().map_err(|_| "worker panicked")??;
    }
    Ok(())
}

fn task_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir("/proc/self/task")
        .into_iter()
        .flatten()
        .flatten()
        .map(|t| {
            std::fs::read_to_string(t.path().join("comm"))
                .unwrap_or_default()
                .trim()
                .to_owned()
        })
        .collect();
    names.sort();
    names
}

/// OS threads of this process before `C_Sign`, right after it returns and two seconds later: the
/// module must not leave helper threads behind. A thread started and joined inside the call is
/// not seen (NSS initializes the module with `CKF_LIBRARY_CANT_CREATE_OS_THREADS`).
fn tasks(pkcs11: &Pkcs11) -> TestResult {
    let before = task_names();
    let (session, key) = first_key(pkcs11)?;
    session.sign(&Mechanism::Ecdsa, key, &[3; 32])?;
    let after = task_names();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let later = task_names();
    println!("\nTASKS {} {} {}", before.len(), after.len(), later.len());
    println!("NAMES before={before:?} after={after:?} later={later:?}");
    if before.len() != after.len() || before.len() != later.len() {
        return Err("thread count changed around C_Sign".into());
    }
    Ok(())
}

/// `fork` while other threads use the module: the children must not deadlock and can sign.
fn forks(pkcs11: &Pkcs11) -> TestResult {
    let pkcs11 = Arc::new(Pkcs11::clone(pkcs11));
    let stop = Arc::new(AtomicBool::new(false));
    let busy = {
        let (pkcs11, stop) = (pkcs11.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let _ = pkcs11.get_slots_with_token();
            }
        })
    };
    for _ in 0..5 {
        // SAFETY: the child only uses the module (which is fork-safe by design) and leaves with
        // `_exit`; `alarm` turns a deadlock in the child into a failure instead of a hang.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::alarm(60) };
            let ok = first_key(&pkcs11)
                .and_then(|(s, k)| Ok(s.sign(&Mechanism::Ecdsa, k, &[5; 32])?))
                .is_ok();
            unsafe { libc::_exit(i32::from(!ok)) };
        }
        assert!(pid > 0, "fork failed");
        let mut status = 0;
        // SAFETY: `pid` is our child.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child status {status}"
        );
    }
    stop.store(true, Ordering::SeqCst);
    busy.join().map_err(|_| "busy thread panicked")?;
    Ok(())
}

/// Entry point of the child scenarios. Without `MODE_VAR` (a plain `cargo test`) it does nothing.
#[test]
fn client() -> TestResult {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return Ok(());
    };
    let pkcs11 = module()?;
    match mode.as_str() {
        "basic" => basic(&pkcs11),
        "denied" => denied(&pkcs11),
        "unsupported" => unsupported(&pkcs11),
        "no_service" => no_service(&pkcs11),
        "threads" => threads(&pkcs11),
        "forks" => forks(&pkcs11),
        "tasks" => tasks(&pkcs11),
        other => Err(format!("unknown mode {other}").into()),
    }
}

// ---------------------------------------------------------------- the parent: bus and service

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
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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
        if let Ok(mut asked) = self.asked.lock() {
            asked.push(action_id);
        }
        let _ = subject;
        (self.approve.load(Ordering::SeqCst), false, HashMap::new())
    }
}

struct Fixture {
    _bus: Bus,
    state: tempfile::TempDir,
    asked: Arc<Mutex<Vec<String>>>,
    address: String,
}

impl Fixture {
    /// A bus with polkit, and, if `service`, the service holding an RSA and a P-256 key. They
    /// run on their own thread: the connections only make progress while a thread is inside
    /// `block_on`, and the test thread is busy waiting for the child process.
    fn start(approve: bool, service: bool) -> Result<Self, Box<dyn Error>> {
        let bus = Bus::start()?;
        let asked = Arc::new(Mutex::new(Vec::new()));
        let state = tempfile::tempdir()?;
        let (ready, wait) = std::sync::mpsc::channel::<Result<(), String>>();
        let (address, path, log) = (
            bus.address.clone(),
            state.path().join("keys"),
            asked.clone(),
        );
        std::thread::spawn(move || {
            let setup = async {
                let bus = Builder::address(address.as_str());
                let polkit = bus.build().await?;
                polkit
                    .object_server()
                    .at(
                        "/org/freedesktop/PolicyKit1/Authority",
                        FakePolkit {
                            approve: Arc::new(AtomicBool::new(approve)),
                            asked: log,
                        },
                    )
                    .await?;
                polkit.request_name("org.freedesktop.PolicyKit1").await?;
                let mut connections = vec![polkit];
                if service {
                    let store = Arc::new(KeyStore::open(path)?);
                    let password = SecretString::from(PASSWORD);
                    import_p12(&store, "rsa", RSA_P12, &password)?;
                    import_p12(&store, "ec", EC_P12, &password)?;
                    let conn = Builder::address(address.as_str()).build().await?;
                    conn.object_server()
                        .at(
                            OBJECT_PATH,
                            Custodio::new(store, PolkitAuthorizer::new(conn.clone())),
                        )
                        .await?;
                    conn.request_name(BUS_NAME).await?;
                    connections.push(conn);
                }
                Ok::<_, Box<dyn Error>>(connections)
            };
            block_on(async {
                match setup.await {
                    Ok(connections) => {
                        let _ = ready.send(Ok(()));
                        std::future::pending::<()>().await;
                        drop(connections);
                    }
                    Err(e) => {
                        let _ = ready.send(Err(e.to_string()));
                    }
                }
            });
        });
        wait.recv()??;
        Ok(Self {
            address: bus.address.clone(),
            _bus: bus,
            state,
            asked,
        })
    }

    fn store(&self) -> Result<KeyStore, Box<dyn Error>> {
        Ok(KeyStore::open(self.state.path().join("keys"))?)
    }

    fn asked(&self) -> usize {
        self.asked.lock().map(|a| a.len()).unwrap_or_default()
    }

    /// Runs a child scenario; returns whether it passed and its stdout.
    fn run(&self, mode: &str) -> Result<(bool, String), Box<dyn Error>> {
        let out = Command::new(std::env::current_exe()?)
            .args(["--exact", "client", "--nocapture", "--test-threads=1"])
            .env(MODE_VAR, mode)
            .env(MODULE_VAR, module_path()?)
            .env("DBUS_SYSTEM_BUS_ADDRESS", &self.address)
            .output()?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() {
            eprintln!("{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
        }
        Ok((out.status.success(), stdout))
    }
}

/// Builds the module (cargo does not build the `cdylib` of a package for its own tests) and
/// returns `target/<profile>/libcustodio_pkcs11.so`, next to the `deps` directory of this binary.
static BUILT: Once = Once::new();

fn module_path() -> Result<PathBuf, Box<dyn Error>> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .and_then(|d| d.parent())
        .ok_or("no target dir")?
        .to_path_buf();
    // Build into the target directory this binary lives in (`cargo llvm-cov` uses its own).
    let target = dir.parent().ok_or("no target dir")?.to_path_buf();
    BUILT.call_once(|| {
        let mut build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
        build.args(["build", "--quiet", "--locked", "-p", "custodio-pkcs11"]);
        build.arg("--target-dir").arg(&target);
        if !cfg!(debug_assertions) {
            build.arg("--release");
        }
        assert!(
            build.status().is_ok_and(|s| s.success()),
            "building the module failed"
        );
    });
    let path = dir.join("libcustodio_pkcs11.so");
    assert!(path.exists(), "{} was not built", path.display());
    Ok(path)
}

fn lines<'a>(stdout: &'a str, tag: &'a str) -> impl Iterator<Item = Vec<&'a str>> {
    stdout
        .lines()
        .filter(move |l| l.starts_with(tag))
        .map(|l| l.split_whitespace().skip(1).collect())
}

#[test]
fn lists_certificates_and_signs_through_the_service() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, stdout) = f.run("basic")?;
    assert!(ok);
    let store = f.store()?;
    let secret = |id: &str| store.get(id);
    for line in lines(&stdout, "CERT") {
        let cert = store.get(&format!("{}-cert", line[0]))?;
        assert_eq!(line[1], hex(secrecy::ExposeSecret::expose_secret(&cert)));
    }
    let mut seen = 0;
    for line in lines(&stdout, "SIG") {
        seen += 1;
        match (line[0], line[1]) {
            ("ec", _) => {
                let expected = sign(&secret("ec")?, ServiceMechanism::Ecdsa, &[7; 32])?;
                assert_eq!(line[2], hex(&expected));
            }
            ("rsa", "pkcs") => {
                let expected = sign(&secret("rsa")?, ServiceMechanism::RsaPkcs, DATA)?;
                assert_eq!(line[2], hex(&expected));
            }
            _ => assert_eq!(line[2], "256"),
        }
    }
    assert_eq!(seen, 3);
    // Three signatures reached the service; each asked polkit.
    assert_eq!(f.asked(), 3);
    Ok(())
}

#[test]
fn a_refused_signature_fails_and_every_attempt_asks() -> TestResult {
    let f = Fixture::start(false, true)?;
    assert!(f.run("denied")?.0);
    assert_eq!(f.asked(), 2);
    Ok(())
}

#[test]
fn everything_else_is_not_supported() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("unsupported")?.0);
    assert_eq!(f.asked(), 0);
    Ok(())
}

#[test]
fn without_the_service_there_are_no_tokens() -> TestResult {
    let f = Fixture::start(true, false)?;
    assert!(f.run("no_service")?.0);
    Ok(())
}

#[test]
fn threads_can_sign_at_once() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("threads")?.0);
    assert_eq!(f.asked(), 24);
    Ok(())
}

#[test]
fn signing_leaves_no_helper_threads() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("tasks")?;
    assert!(ok);
    let counts = lines(&out, "TASKS").next().ok_or("no TASKS line")?;
    assert_eq!(counts[0], counts[1], "threads left behind by C_Sign: {out}");
    assert_eq!(counts[0], counts[2], "threads linger after C_Sign: {out}");
    Ok(())
}

#[test]
fn fork_while_other_threads_use_the_module() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("forks")?.0);
    assert_eq!(f.asked(), 5);
    Ok(())
}

#[test]
fn bus_names_match_the_service() {
    // The module repeats these constants rather than link the service.
    assert_eq!(BUS_NAME, "com.rfirma.Custodio1");
    assert_eq!(OBJECT_PATH, "/com/rfirma/Custodio1");
}

#[test]
fn p11_kit_module_file_points_at_the_library() -> TestResult {
    let file = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../data/custodio.module"
    ))?;
    let entries: Vec<(&str, &str)> = file
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    let module = entries
        .iter()
        .find(|(k, _)| *k == "module")
        .ok_or("no module entry")?
        .1;
    assert!(
        module.starts_with('/'),
        "p11-kit needs an absolute path or a name in its module dir"
    );
    assert!(module.ends_with("libcustodio_pkcs11.so"), "{module}");
    // The module must not be treated as a trust anchor store or a critical module.
    assert!(entries.contains(&("critical", "no")));
    assert!(entries.contains(&("trust-policy", "no")));
    Ok(())
}
