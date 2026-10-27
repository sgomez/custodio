//! Import CLI: argument rules, password handling, the delete reminder, and a round trip against
//! the real service on a private `dbus-daemon`.

use std::cell::RefCell;
use std::error::Error;
use std::io::{self, BufRead, BufReader, Cursor};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use custodio_cli::bus::DbusImporter;
use custodio_cli::{
    ArgError, ImportArgs, ImportFailure, Importer, PasswordPrompt, parse_args, read_secret_line,
    run_import,
};
use custodiod::dbus::{BUS_NAME, Custodio, OBJECT_PATH};
use custodiod::polkit::{AuthError, Authorizer};
use custodiod::store::KeyStore;
use secrecy::{ExposeSecret, SecretString};
use zbus::block_on;
use zbus::connection::Builder;

type TestResult = Result<(), Box<dyn Error>>;

const P256_P12: &[u8] = include_bytes!("fixtures/p256.p12");
const PASSWORD: &str = "test-password";

fn args(list: &[&str]) -> Result<ImportArgs, ArgError> {
    parse_args(list.iter().map(|s| (*s).to_owned()))
}

struct FixedPrompt(Option<&'static str>);

impl PasswordPrompt for FixedPrompt {
    fn password(&mut self, _prompt: &str) -> io::Result<SecretString> {
        self.0
            .map(SecretString::from)
            .ok_or_else(|| io::Error::other("no terminal"))
    }
}

#[derive(Default)]
struct Recorder {
    calls: RefCell<Vec<(String, usize, String)>>,
    reply: Option<String>,
}

impl Importer for Recorder {
    fn import_p12(&self, id: &str, p12: &[u8], password: &SecretString) -> Result<String, String> {
        self.calls.borrow_mut().push((
            id.to_owned(),
            p12.len(),
            password.expose_secret().to_owned(),
        ));
        self.reply.clone().map_or(Ok("p256".to_owned()), Err)
    }
}

fn p12_file(dir: &tempfile::TempDir) -> Result<std::path::PathBuf, io::Error> {
    let path = dir.path().join("my-key.p12");
    std::fs::write(&path, P256_P12)?;
    Ok(path)
}

#[test]
fn id_defaults_to_file_stem() -> TestResult {
    let a = args(&["import", "/tmp/my-key.p12"])?;
    assert_eq!(a.id, "my-key");
    assert_eq!(a.file.to_str(), Some("/tmp/my-key.p12"));
    Ok(())
}

#[test]
fn id_flag_overrides() -> TestResult {
    assert_eq!(args(&["import", "--id", "work", "a b.p12"])?.id, "work");
    assert_eq!(args(&["import", "a b.p12", "--id", "work"])?.id, "work");
    Ok(())
}

#[test]
fn unusable_stem_needs_explicit_id() {
    assert_eq!(args(&["import", "my cert.p12"]), Err(ArgError::BadId));
    assert_eq!(args(&["import", "x-cert.p12"]), Err(ArgError::BadId));
}

#[test]
fn no_way_to_pass_a_password_on_the_command_line() {
    for bad in [
        &["import", "--password", "x", "a.p12"][..],
        &["import", "--password=x", "a.p12"],
        &["import", "-p", "x", "a.p12"],
        &["import", "a.p12", "extra"],
        &["import"],
        &["import", "--id"],
        &["import", "--id", "a", "--id", "b", "a.p12"],
        &["export", "a.p12"],
        &[],
    ] {
        assert_eq!(args(bad), Err(ArgError::Usage), "{bad:?}");
    }
}

#[test]
fn password_comes_from_the_prompt() -> TestResult {
    let dir = tempfile::tempdir()?;
    let a = ImportArgs {
        file: p12_file(&dir)?,
        id: "k".into(),
    };
    let rec = Recorder::default();
    let mut out = Vec::new();
    let mut prompt = FixedPrompt(Some("from-terminal"));
    run_import(&a, &mut prompt, &rec, &mut out)?;
    let calls = rec.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0],
        ("k".to_owned(), P256_P12.len(), "from-terminal".to_owned())
    );
    Ok(())
}

#[test]
fn success_tells_the_person_to_delete_the_original() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = p12_file(&dir)?;
    let a = ImportArgs {
        file: file.clone(),
        id: "k".into(),
    };
    let mut out = Vec::new();
    run_import(
        &a,
        &mut FixedPrompt(Some("Zq9!secret-pass")),
        &Recorder::default(),
        &mut out,
    )?;
    let text = String::from_utf8(out)?;
    assert!(text.contains("delete the original"), "{text}");
    assert!(text.contains(file.to_str().ok_or("path")?), "{text}");
    assert!(!text.contains("Zq9!secret-pass"), "{text}");
    // The tool must not delete it itself.
    assert!(file.exists());
    Ok(())
}

#[test]
fn failed_import_does_not_say_the_file_is_safe_to_delete() -> TestResult {
    let dir = tempfile::tempdir()?;
    let a = ImportArgs {
        file: p12_file(&dir)?,
        id: "k".into(),
    };
    let rec = Recorder {
        reply: Some("wrong password".into()),
        ..Recorder::default()
    };
    let mut out = Vec::new();
    let err = run_import(&a, &mut FixedPrompt(Some("pw")), &rec, &mut out).err();
    assert!(matches!(err, Some(ImportFailure::Service(ref m)) if m == "wrong password"));
    assert_eq!(out, b"");
    Ok(())
}

#[test]
fn no_terminal_means_no_import() -> TestResult {
    let dir = tempfile::tempdir()?;
    let a = ImportArgs {
        file: p12_file(&dir)?,
        id: "k".into(),
    };
    let rec = Recorder::default();
    let err = run_import(&a, &mut FixedPrompt(None), &rec, &mut Vec::new()).err();
    assert!(matches!(err, Some(ImportFailure::Password(_))));
    assert_eq!(rec.calls.borrow().len(), 0);
    Ok(())
}

#[test]
fn missing_and_oversized_files_are_refused_before_asking() -> TestResult {
    let dir = tempfile::tempdir()?;
    let rec = Recorder::default();
    let missing = ImportArgs {
        file: dir.path().join("nope.p12"),
        id: "k".into(),
    };
    let err = run_import(&missing, &mut FixedPrompt(None), &rec, &mut Vec::new()).err();
    assert!(matches!(err, Some(ImportFailure::Read(_))));

    let big = dir.path().join("big.p12");
    std::fs::write(&big, vec![0_u8; custodiod::import::MAX_P12_LEN + 1])?;
    let big = ImportArgs {
        file: big,
        id: "k".into(),
    };
    let err = run_import(&big, &mut FixedPrompt(None), &rec, &mut Vec::new()).err();
    assert!(matches!(err, Some(ImportFailure::TooLarge)));
    assert_eq!(rec.calls.borrow().len(), 0);
    Ok(())
}

#[test]
fn secret_line_strips_the_newline_only() -> TestResult {
    let mut r = Cursor::new(b" pa ss \r\nrest".to_vec());
    assert_eq!(read_secret_line(&mut r)?.expose_secret(), " pa ss ");
    let mut r = Cursor::new(b"last".to_vec());
    assert_eq!(read_secret_line(&mut r)?.expose_secret(), "last");
    assert!(read_secret_line(&mut Cursor::new(Vec::new())).is_err());
    assert!(read_secret_line(&mut Cursor::new(vec![0xff, b'\n'])).is_err());
    Ok(())
}

// ---- Round trip against the real service. ----

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

struct Deny;

impl Authorizer for Deny {
    fn authorize(&self, _sender: &str) -> impl Future<Output = Result<(), AuthError>> + Send {
        std::future::ready(Err(AuthError::Denied))
    }
}

fn serve(bus: &Bus, store: Arc<KeyStore>) -> Result<zbus::Connection, Box<dyn Error>> {
    Ok(block_on(async {
        let conn = Builder::address(bus.address.as_str()).build().await?;
        conn.object_server()
            .at(OBJECT_PATH, Custodio::new(store, Deny))
            .await?;
        conn.request_name(BUS_NAME).await?;
        Ok::<_, zbus::Error>(conn)
    })?)
}

fn client(bus: &Bus) -> Result<DbusImporter, Box<dyn Error>> {
    let conn = block_on(Builder::address(bus.address.as_str()).build())?;
    Ok(DbusImporter::new(conn))
}

#[test]
fn imports_through_the_service_and_reports_wrong_password() -> TestResult {
    let bus = Bus::start()?;
    let dir = tempfile::tempdir()?;
    let store = Arc::new(KeyStore::open(dir.path().join("state"))?);
    let _service = serve(&bus, store.clone())?;
    let importer = client(&bus)?;
    let file = p12_file(&dir)?;
    let a = ImportArgs {
        file,
        id: "k".into(),
    };

    let mut out = Vec::new();
    let err = run_import(&a, &mut FixedPrompt(Some("wrong")), &importer, &mut out).err();
    assert!(matches!(err, Some(ImportFailure::Service(_))), "{err:?}");
    assert_eq!(out, b"");
    assert_eq!(store.list()?, Vec::<String>::new());

    run_import(&a, &mut FixedPrompt(Some(PASSWORD)), &importer, &mut out)?;
    assert!(String::from_utf8(out)?.contains("delete the original"));
    assert!(store.list()?.contains(&"k".to_owned()));
    Ok(())
}
