//! `custodio import` on the documented API: every failure of the service shown as its own message,
//! against the real service on a private `dbus-daemon` with a fake polkit. Needs `dbus-daemon`
//! (`/usr/bin/dbus-daemon` in the dev container); a missing one fails the tests.

use std::error::Error;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};

use custodio_cli::bus::DbusImporter;
use custodio_cli::{
    CliError, ImportArgs, ImportFailure, PasswordPrompt, ServiceFailure, exit_status, finish,
    parse_args, run_import,
};
use custodio_client::{BUS_NAME, OBJECT_PATH};
use custodiod::audit::{AuditSink, FailingSink, MemorySink};
use custodiod::credentials::BusCredentials;
use custodiod::dbus::Custodio;
use custodiod::import::{ImportError, P12Decoder, ParsedP12};
use custodiod::polkit::{AuthError, Authorizer, IMPORT_ACTION_ID};
use custodiod::store::{KeyStore, StoreError};
use secrecy::SecretString;
use zbus::connection::Builder;
use zbus::{block_on, interface};

type TestResult = Result<(), Box<dyn Error>>;

const P256_P12: &[u8] = include_bytes!("fixtures/p256.p12");
const RSA3072_P12: &[u8] = include_bytes!("fixtures/rsa3072.p12");
const PASSWORD: &str = "test-password";
const FREE_TEXT: &str = "SERVICE FREE TEXT";

#[derive(Clone, Copy)]
enum Polkit {
    Approve,
    Deny,
    Unavailable,
}

#[derive(Clone)]
struct FakePolkit {
    mode: Polkit,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Authorizer for FakePolkit {
    fn authorize(
        &self,
        _sender: &str,
        action: &str,
    ) -> impl Future<Output = Result<(), AuthError>> + Send {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(action.to_owned());
        std::future::ready(match self.mode {
            Polkit::Approve => Ok(()),
            Polkit::Deny => Err(AuthError::Denied),
            Polkit::Unavailable => Err(AuthError::Unavailable(FREE_TEXT.into())),
        })
    }
}

/// A decoder that answers one fixed error, for the cases a real `.p12` cannot produce.
struct Failing(fn() -> ImportError);

impl P12Decoder for Failing {
    fn decode(&self, _: &[u8], _: &SecretString) -> Result<ParsedP12, ImportError> {
        Err((self.0)())
    }
}

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

    fn importer(&self) -> Result<DbusImporter, Box<dyn Error>> {
        Ok(DbusImporter::new(block_on(
            Builder::address(self.address.as_str()).build(),
        )?))
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Rig {
    bus: Bus,
    importer: DbusImporter,
    store: Arc<KeyStore>,
    asked: Arc<Mutex<Vec<String>>>,
    dir: tempfile::TempDir,
    _service: zbus::Connection,
}

impl Rig {
    fn start(mode: Polkit) -> Result<Self, Box<dyn Error>> {
        Self::with(mode, Arc::new(MemorySink::default()), None)
    }

    fn with(
        mode: Polkit,
        sink: Arc<dyn AuditSink>,
        decoder: Option<Arc<dyn P12Decoder>>,
    ) -> Result<Self, Box<dyn Error>> {
        let bus = Bus::start()?;
        let dir = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(dir.path().join("state"))?);
        let asked = Arc::new(Mutex::new(Vec::new()));
        let polkit = FakePolkit {
            mode,
            asked: asked.clone(),
        };
        let service = block_on(async {
            let conn = Builder::address(bus.address.as_str()).build().await?;
            let mut object = Custodio::new(
                store.clone(),
                polkit,
                BusCredentials::new(conn.clone()),
                sink,
            )
            .with_key_credentials(std::sync::Arc::new(
                custodiod::creds::memory::MemoryCreds::host(),
            ));
            if let Some(d) = decoder {
                object = object.with_decoder(d);
            }
            conn.object_server().at(OBJECT_PATH, object).await?;
            conn.request_name(BUS_NAME).await?;
            Ok::<_, zbus::Error>(conn)
        })?;
        let importer = bus.importer()?;
        Ok(Self {
            bus,
            importer,
            store,
            asked,
            dir,
            _service: service,
        })
    }

    fn file(&self, name: &str, data: &[u8]) -> Result<PathBuf, io::Error> {
        let path = self.dir.path().join(name);
        std::fs::write(&path, data)?;
        Ok(path)
    }

    fn keys(&self) -> Result<Vec<String>, Box<dyn Error>> {
        Ok(self.store.list(owner()?)?)
    }

    fn polkit_asked(&self) -> Vec<String> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn owner() -> Result<u32, Box<dyn Error>> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata("/proc/self")?.uid())
}

struct Typed(String);

impl PasswordPrompt for Typed {
    fn password(&mut self, _prompt: &str) -> io::Result<SecretString> {
        Ok(SecretString::from(self.0.clone()))
    }
}

struct Run {
    result: Result<(), ImportFailure>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: u8,
}

/// What the person sees: `run_import` and the diagnostic and status `main` derives from it.
fn import(importer: &DbusImporter, file: PathBuf, id: &str, password: &str) -> Run {
    let args = ImportArgs {
        file,
        id: id.to_owned(),
    };
    let mut stdout = Vec::new();
    let result = run_import(
        &args,
        &mut Typed(password.to_owned()),
        importer,
        &mut stdout,
    );
    let cli = result.map_err(CliError::Import);
    let mut stderr = Vec::new();
    let status = finish(&cli, &mut stderr);
    assert_eq!(status, exit_status(&cli));
    let result = cli.map_err(|e| match e {
        CliError::Import(f) => f,
        other => unreachable!("{other:?}"),
    });
    Run {
        result,
        stdout,
        stderr,
        status,
    }
}

fn service_failure(run: &Run) -> Result<&ServiceFailure, Box<dyn Error>> {
    match &run.result {
        Err(ImportFailure::Service(f)) => Ok(f),
        other => Err(format!("not a service failure: {other:?}").into()),
    }
}

/// A failed import: the failure, its message on stderr, status 1, and no secret anywhere.
fn assert_failed(
    run: &Run,
    want: &ServiceFailure,
    file: &std::path::Path,
    password: &str,
    p12: &[u8],
) -> TestResult {
    assert_eq!(service_failure(run)?, want);
    assert_eq!(run.status, 1);
    assert_eq!(run.stdout, b"", "no success text after a failure");
    let err = String::from_utf8(run.stderr.clone())?;
    assert!(err.contains(&want.message()), "{err}");
    let hex = p12.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    let shown = format!(
        "{err}{:?}{}",
        run.result,
        run.result
            .as_ref()
            .err()
            .map_or_else(String::new, ToString::to_string)
    );
    for secret in [password, FREE_TEXT, &hex, file.to_str().ok_or("path")?] {
        assert!(!shown.contains(secret), "{secret} in {shown}");
    }
    Ok(())
}

#[test]
fn approval_imports_and_polkit_is_asked_once() -> TestResult {
    let rig = Rig::start(Polkit::Approve)?;
    let file = rig.file("k.p12", P256_P12)?;
    let run = import(&rig.importer, file.clone(), "k", PASSWORD);
    assert!(run.result.is_ok(), "{:?}", run.result);
    assert_eq!(run.status, 0);
    let out = String::from_utf8(run.stdout)?;
    assert!(out.contains("Imported key 'k' (ecdsa-p256)."), "{out}");
    assert_eq!(rig.keys()?, ["k".to_owned()]);
    assert_eq!(rig.polkit_asked(), [IMPORT_ACTION_ID.to_owned()]);
    drop(rig.bus);
    Ok(())
}

#[test]
fn denial_shows_denied_even_with_a_wrong_password() -> TestResult {
    let rig = Rig::start(Polkit::Deny)?;
    let file = rig.file("k.p12", P256_P12)?;
    for password in [PASSWORD, "not-the-password"] {
        let run = import(&rig.importer, file.clone(), "k", password);
        assert_failed(
            &run,
            &ServiceFailure::PolkitDenied,
            &file,
            password,
            P256_P12,
        )?;
    }
    assert_ne!(
        ServiceFailure::PolkitDenied.message(),
        ServiceFailure::AuthorizationUnavailable.message()
    );
    assert_eq!(rig.keys()?, Vec::<String>::new());
    Ok(())
}

#[test]
fn unavailability_shows_its_own_message() -> TestResult {
    let rig = Rig::start(Polkit::Unavailable)?;
    let file = rig.file("k.p12", P256_P12)?;
    let run = import(&rig.importer, file.clone(), "k", PASSWORD);
    assert_failed(
        &run,
        &ServiceFailure::AuthorizationUnavailable,
        &file,
        PASSWORD,
        P256_P12,
    )?;
    assert_eq!(rig.keys()?, Vec::<String>::new());
    Ok(())
}

#[test]
fn an_id_the_cli_lets_through_but_the_service_refuses_is_invalid_args() -> TestResult {
    let rig = Rig::start(Polkit::Approve)?;
    let file = rig.file("k.p12", P256_P12)?;
    // The CLI does not check the id given with --id, so this reaches the service.
    let long = "a".repeat(200);
    let parsed =
        parse_args(["import", "--id", &long, file.to_str().ok_or("path")?].map(str::to_owned))?;
    assert_eq!(parsed.id, long);
    let run = import(&rig.importer, file.clone(), &parsed.id, PASSWORD);
    assert_failed(
        &run,
        &ServiceFailure::InvalidArgs,
        &file,
        PASSWORD,
        P256_P12,
    )?;
    // An oversized password is refused the same way.
    let run = import(&rig.importer, file.clone(), "k", &"p".repeat(2000));
    assert_failed(
        &run,
        &ServiceFailure::InvalidArgs,
        &file,
        &"p".repeat(2000),
        P256_P12,
    )?;
    assert_eq!(rig.keys()?, Vec::<String>::new());
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    Ok(())
}

#[test]
fn a_second_import_of_an_id_is_id_taken() -> TestResult {
    let rig = Rig::start(Polkit::Approve)?;
    let file = rig.file("k.p12", P256_P12)?;
    assert!(
        import(&rig.importer, file.clone(), "k", PASSWORD)
            .result
            .is_ok()
    );
    let before = rig.keys()?;
    let run = import(&rig.importer, file.clone(), "k", PASSWORD);
    assert_failed(&run, &ServiceFailure::KeyIdTaken, &file, PASSWORD, P256_P12)?;
    assert_eq!(rig.keys()?, before);
    Ok(())
}

#[test]
fn a_wrong_password_is_wrong_password() -> TestResult {
    let rig = Rig::start(Polkit::Approve)?;
    let file = rig.file("k.p12", P256_P12)?;
    let run = import(&rig.importer, file.clone(), "k", "wrong-one");
    assert_failed(
        &run,
        &ServiceFailure::WrongPasswordOrBadP12,
        &file,
        "wrong-one",
        P256_P12,
    )?;
    assert_eq!(rig.keys()?, Vec::<String>::new());
    Ok(())
}

#[test]
fn an_rsa_3072_key_is_unsupported() -> TestResult {
    let rig = Rig::start(Polkit::Approve)?;
    let file = rig.file("rsa3072.p12", RSA3072_P12)?;
    let run = import(&rig.importer, file.clone(), "big", PASSWORD);
    assert_failed(
        &run,
        &ServiceFailure::UnsupportedKeyType,
        &file,
        PASSWORD,
        RSA3072_P12,
    )?;
    assert_eq!(rig.keys()?, Vec::<String>::new());
    Ok(())
}

#[test]
fn a_certificate_for_another_key_is_a_mismatch() -> TestResult {
    let rig = Rig::with(
        Polkit::Approve,
        Arc::new(MemorySink::default()),
        Some(Arc::new(Failing(|| ImportError::CertificateMismatch))),
    )?;
    let file = rig.file("k.p12", P256_P12)?;
    let run = import(&rig.importer, file.clone(), "k", PASSWORD);
    assert_failed(
        &run,
        &ServiceFailure::CertificateMismatch,
        &file,
        PASSWORD,
        P256_P12,
    )?;
    assert_eq!(rig.keys()?, Vec::<String>::new());
    Ok(())
}

#[test]
fn a_failing_audit_log_is_audit_unavailable_and_keeps_no_key() -> TestResult {
    let rig = Rig::with(Polkit::Approve, Arc::new(FailingSink), None)?;
    let file = rig.file("k.p12", P256_P12)?;
    let run = import(&rig.importer, file.clone(), "k", PASSWORD);
    assert_failed(
        &run,
        &ServiceFailure::AuditUnavailable,
        &file,
        PASSWORD,
        P256_P12,
    )?;
    assert_eq!(rig.keys()?, Vec::<String>::new());
    Ok(())
}

#[test]
fn a_store_that_refuses_is_internal() -> TestResult {
    let rig = Rig::with(
        Polkit::Approve,
        Arc::new(MemorySink::default()),
        Some(Arc::new(Failing(|| {
            ImportError::Store(StoreError::BadFileType(PathBuf::from("/secret/path")))
        }))),
    )?;
    let file = rig.file("k.p12", P256_P12)?;
    let run = import(&rig.importer, file.clone(), "k", PASSWORD);
    assert_failed(&run, &ServiceFailure::Internal, &file, PASSWORD, P256_P12)?;
    assert!(!String::from_utf8(run.stderr)?.contains("/secret/path"));
    assert_eq!(rig.keys()?, Vec::<String>::new());
    Ok(())
}

#[test]
fn no_service_on_the_bus_is_not_an_error_name_message() -> TestResult {
    let bus = Bus::start()?;
    let importer = bus.importer()?;
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("k.p12");
    std::fs::write(&file, P256_P12)?;
    let run = import(&importer, file.clone(), "k", PASSWORD);
    assert_failed(
        &run,
        &ServiceFailure::ServiceAbsent,
        &file,
        PASSWORD,
        P256_P12,
    )?;
    assert!(!run.stderr.windows(7).any(|w| w == b"unknown"));
    Ok(())
}

type Call = (String, Vec<u8>, String);

/// The only method of the documented interface; a call to any other member would fail the import.
struct Documented(Arc<Mutex<Vec<Call>>>);

#[interface(name = "com.rfirma.Custodio1")]
impl Documented {
    fn import_p12(&self, id: String, p12: Vec<u8>, password: String) -> (String, String) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((id, p12, password));
        ("ecdsa-p256".to_owned(), "encrypted-host".to_owned())
    }
}

#[test]
fn the_call_is_the_documented_one_with_the_given_arguments() -> TestResult {
    let bus = Bus::start()?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let service = block_on(async {
        let conn = Builder::address(bus.address.as_str()).build().await?;
        conn.object_server()
            .at(OBJECT_PATH, Documented(seen.clone()))
            .await?;
        conn.request_name(BUS_NAME).await?;
        Ok::<_, zbus::Error>(conn)
    })?;
    let importer = bus.importer()?;
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("k.p12");
    std::fs::write(&file, P256_P12)?;
    let run = import(&importer, file, "my-id", "pw 1");
    assert!(run.result.is_ok(), "{:?}", run.result);
    let calls = seen.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(
        *calls,
        [("my-id".to_owned(), P256_P12.to_vec(), "pw 1".to_owned())]
    );
    drop(calls);
    drop(service);
    Ok(())
}
