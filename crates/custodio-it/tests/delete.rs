//! `custodio delete` as the real binary, on a pseudo-terminal, against the real service on a
//! private `dbus-daemon` with a fake polkit. Needs `dbus-daemon` (`/usr/bin/dbus-daemon` in the
//! dev container); a missing one fails the tests.
//!
//! The binary is run as a child that has the slave end of the pseudo-terminal as its controlling
//! terminal (new session, `TIOCSCTTY`), which is what lets it open `/dev/tty`. In the dev
//! container this works: `/dev/tty` opens, takes the prompt and gives back what the master
//! writes. The "no terminal" child is a new session without one.

use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once, PoisonError};
use std::time::{Duration, Instant};

use custodio_cli::bus::DbusImporter;
use custodio_cli::delete::question;
use custodio_cli::{ImportArgs, KeyLister, PasswordPrompt, ServiceFailure, USAGE, run_import};
use custodio_client::{BUS_NAME, OBJECT_PATH};
use custodiod::audit::{Caller, MemorySink};
use custodiod::credentials::{CallerCredentials, CredentialsError};
use custodiod::dbus::Custodio;
use custodiod::polkit::{AuthError, Authorizer, DELETE_ACTION_ID};
use custodiod::store::KeyStore;
use secrecy::SecretString;
use zbus::connection::Builder;
use zbus::export::futures_core::Stream;
use zbus::{block_on, message::Type};

type TestResult = Result<(), Box<dyn Error>>;

const P256_P12: &[u8] = include_bytes!("fixtures/p256.p12");
const PASSWORD: &str = "test-password";
const FREE_TEXT: &str = "SERVICE FREE TEXT";
const WAIT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy)]
enum Polkit {
    Approve,
    Deny,
}

#[derive(Clone)]
struct FakePolkit {
    mode: Arc<Mutex<Polkit>>,
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
        let mode = *self.mode.lock().unwrap_or_else(PoisonError::into_inner);
        std::future::ready(match mode {
            Polkit::Approve => Ok(()),
            Polkit::Deny => Err(AuthError::Denied),
        })
    }
}

/// The caller is always the same uid, or cannot be identified.
#[derive(Clone)]
struct Caller4001 {
    broken: Arc<AtomicBool>,
}

impl CallerCredentials for Caller4001 {
    fn credentials(
        &self,
        _: &str,
    ) -> impl Future<Output = Result<Caller, CredentialsError>> + Send {
        std::future::ready(if self.broken.load(Ordering::SeqCst) {
            Err(CredentialsError::Missing)
        } else {
            Ok(Caller {
                uid: 4001,
                pid: std::process::id(),
            })
        })
    }
}

struct Typed;

impl PasswordPrompt for Typed {
    fn password(&mut self, _prompt: &str) -> io::Result<SecretString> {
        Ok(SecretString::from(PASSWORD))
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
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// (destination, path, interface, member, signature) of a method call seen on the bus.
type Seen = (String, String, String, String, String);

fn monitor(address: &str, log: Arc<Mutex<Vec<Seen>>>) -> Result<zbus::Connection, Box<dyn Error>> {
    let (conn, stream) = block_on(async {
        let conn = Builder::address(address).build().await?;
        let stream = zbus::MessageStream::from(&conn);
        zbus::fdo::MonitoringProxy::new(&conn)
            .await?
            .become_monitor(&[], 0)
            .await?;
        Ok::<_, zbus::Error>((conn, stream))
    })?;
    std::thread::spawn(move || {
        let mut stream = stream;
        block_on(async {
            while let Some(Ok(msg)) =
                std::future::poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await
            {
                let header = msg.header();
                if msg.message_type() != Type::MethodCall {
                    continue;
                }
                let text = |s: Option<String>| s.unwrap_or_default();
                let seen = (
                    text(header.destination().map(ToString::to_string)),
                    text(header.path().map(ToString::to_string)),
                    text(header.interface().map(ToString::to_string)),
                    text(header.member().map(ToString::to_string)),
                    msg.body().signature().to_string(),
                );
                log.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(seen);
            }
        });
    });
    Ok(conn)
}

struct Rig {
    bus: Bus,
    client: DbusImporter,
    mode: Arc<Mutex<Polkit>>,
    broken: Arc<AtomicBool>,
    polkit: Arc<Mutex<Vec<String>>>,
    seen: Arc<Mutex<Vec<Seen>>>,
    dir: tempfile::TempDir,
    _connections: Vec<zbus::Connection>,
}

impl Rig {
    /// With `service` false nobody owns the service's bus name. Polkit approves until `polkit`.
    fn start(service: bool) -> Result<Self, Box<dyn Error>> {
        let bus = Bus::start()?;
        let dir = tempfile::tempdir()?;
        let mode = Arc::new(Mutex::new(Polkit::Approve));
        let broken = Arc::new(AtomicBool::new(false));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut connections = vec![monitor(&bus.address, seen.clone())?];
        if service {
            let store = Arc::new(KeyStore::open(dir.path().join("state"))?);
            let polkit = FakePolkit {
                mode: mode.clone(),
                asked: asked.clone(),
            };
            let credentials = Caller4001 {
                broken: broken.clone(),
            };
            let address = bus.address.clone();
            connections.push(block_on(async {
                let conn = Builder::address(address.as_str()).build().await?;
                let object =
                    Custodio::new(store, polkit, credentials, Arc::new(MemorySink::default()));
                conn.object_server().at(OBJECT_PATH, object).await?;
                conn.request_name(BUS_NAME).await?;
                Ok::<_, zbus::Error>(conn)
            })?);
        }
        let client = DbusImporter::new(block_on(Builder::address(bus.address.as_str()).build())?);
        Ok(Self {
            bus,
            client,
            mode,
            broken,
            polkit: asked,
            seen,
            dir,
            _connections: connections,
        })
    }

    fn polkit(&self, mode: Polkit) {
        *self.mode.lock().unwrap_or_else(PoisonError::into_inner) = mode;
    }

    fn import(&self, id: &str) -> TestResult {
        let file = self.dir.path().join(format!("{id}.p12"));
        std::fs::write(&file, P256_P12)?;
        let args = ImportArgs {
            file,
            id: id.to_owned(),
        };
        run_import(&args, &mut Typed, &self.client, &mut Vec::new())?;
        Ok(())
    }

    fn keys(&self) -> Result<Vec<String>, ServiceFailure> {
        Ok(self.client.list_keys()?.into_iter().map(|k| k.id).collect())
    }

    /// Forgets the setup: calls and polkit questions so far.
    fn forget(&self) {
        std::thread::sleep(Duration::from_millis(300));
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.polkit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Method calls to the service seen since `forget`, as (path, interface, member, signature).
    fn service_calls(&self) -> Vec<(String, String, String, String)> {
        std::thread::sleep(Duration::from_millis(300));
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(dest, ..)| dest == BUS_NAME)
            .map(|(_, path, iface, member, sig)| {
                (path.clone(), iface.clone(), member.clone(), sig.clone())
            })
            .collect()
    }

    fn polkit_asked(&self) -> Vec<String> {
        self.polkit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Builds the binary (cargo does not build the binary of another package for these tests) and
/// returns `target/<profile>/custodio-cli`, next to the `deps` directory of this test binary.
static BUILT: Once = Once::new();

fn binary() -> Result<PathBuf, Box<dyn Error>> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .and_then(|d| d.parent())
        .ok_or("no target dir")?
        .to_path_buf();
    let target = dir.parent().ok_or("no target dir")?.to_path_buf();
    BUILT.call_once(|| {
        let mut build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
        build.args(["build", "--quiet", "--locked", "-p", "custodio-cli"]);
        build.arg("--target-dir").arg(&target);
        if !cfg!(debug_assertions) {
            build.arg("--release");
        }
        assert!(
            build.status().is_ok_and(|s| s.success()),
            "building custodio-cli failed"
        );
    });
    let path = dir.join("custodio-cli");
    assert!(path.exists(), "{} was not built", path.display());
    Ok(path)
}

/// A running `custodio` and, if it has one, the master end of its controlling terminal.
struct Run {
    child: Child,
    master: Option<File>,
    screen: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    /// Kept open so the terminal does not report a hang-up before the child opens it.
    _slave: Option<OwnedFd>,
}

struct Finished {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl Run {
    /// With `terminal`, the child is a session leader whose controlling terminal is a new
    /// pseudo-terminal; without, a session leader with none. Standard input is a pipe holding
    /// `stdin`, standard output and error are pipes: only `/dev/tty` is the terminal.
    fn start(
        rig: &Rig,
        args: &[&str],
        env: &[(&str, &str)],
        terminal: bool,
        stdin: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        let mut master = None;
        let mut slave_fd = -1;
        let mut slave_keep = None;
        if terminal {
            // SAFETY: plain libc calls on descriptors this function owns.
            unsafe {
                let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
                assert!(m >= 0 && libc::grantpt(m) == 0 && libc::unlockpt(m) == 0);
                let master_file = File::from(OwnedFd::from_raw_fd(m));
                let mut name = [0 as libc::c_char; 128];
                assert_eq!(libc::ptsname_r(m, name.as_mut_ptr(), name.len()), 0);
                let s = libc::open(
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
                );
                assert!(s >= 0);
                slave_keep = Some(OwnedFd::from_raw_fd(s));
                slave_fd = s;
                master = Some(master_file);
            }
        }
        let mut command = Command::new(binary()?);
        command
            .args(args)
            .env_clear()
            .env("DBUS_SYSTEM_BUS_ADDRESS", &rig.bus.address)
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: only async-signal-safe calls (`setsid`, `ioctl`) between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if slave_fd >= 0 && libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let mut pipe = child.stdin.take().ok_or("no stdin")?;
        let _ = pipe.write_all(stdin);
        drop(pipe);
        let screen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        if let Some(master) = &master {
            let mut reader = master.try_clone()?;
            let screen = screen.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 256];
                // Poll, so that a hang-up can make this thread let go of its copy of the master.
                while !stop.load(Ordering::SeqCst) {
                    let mut fd = libc::pollfd {
                        fd: reader.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: one valid `pollfd`.
                    if unsafe { libc::poll(&raw mut fd, 1, 50) } <= 0 {
                        continue;
                    }
                    let Ok(n) = reader.read(&mut buf) else { break };
                    if n == 0 {
                        break;
                    }
                    screen
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .extend_from_slice(&buf[..n]);
                }
            });
        }
        Ok(Self {
            child,
            master,
            screen,
            stop,
            _slave: slave_keep,
        })
    }

    fn screen(&self) -> String {
        String::from_utf8_lossy(&self.screen.lock().unwrap_or_else(PoisonError::into_inner))
            .into_owned()
    }

    /// Waits until the terminal output holds `text`.
    fn wait_for(&mut self, text: &str) -> TestResult {
        let start = Instant::now();
        while !self.screen().contains(text) {
            if start.elapsed() > WAIT {
                return Err(format!("{text:?} never appeared; screen: {:?}", self.screen()).into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    fn send(&mut self, bytes: &[u8]) -> TestResult {
        let master = self.master.as_mut().ok_or("no terminal")?;
        master.write_all(bytes)?;
        Ok(())
    }

    /// Closes the master end: the terminal hangs up.
    fn hang_up(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.master = None;
        std::thread::sleep(Duration::from_millis(300));
    }

    fn finish(mut self) -> Result<Finished, Box<dyn Error>> {
        let start = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if start.elapsed() > WAIT {
                let _ = self.child.kill();
                return Err(format!("did not exit; screen: {:?}", self.screen()).into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stdout.take() {
            pipe.read_to_string(&mut stdout)?;
        }
        if let Some(mut pipe) = self.child.stderr.take() {
            pipe.read_to_string(&mut stderr)?;
        }
        Ok(Finished {
            status,
            stdout,
            stderr,
        })
    }
}

fn delete_args(id: &str) -> [&str; 2] {
    ["delete", id]
}

fn message(failure: &ServiceFailure) -> String {
    format!("custodio: {failure}\n")
}

#[test]
fn the_pseudo_terminal_is_the_controlling_terminal_of_the_child() -> TestResult {
    // The premise of every test below: the child opens `/dev/tty` and the master hears it.
    let rig = Rig::start(true)?;
    let mut run = Run::start(&rig, &["delete", "x"], &[], true, b"")?;
    run.wait_for(&question("x"))?;
    run.send(b"n\n")?;
    run.finish()?;
    Ok(())
}

#[test]
fn confirming_asks_before_the_service_and_deletes_after_the_answer() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("old-key")?;
    rig.import("keep")?;
    rig.forget();
    let mut run = Run::start(&rig, &delete_args("old-key"), &[], true, b"")?;
    run.wait_for(&question("old-key"))?;
    let shown = run.screen();
    assert!(shown.contains("'old-key'") && shown.contains("cannot be recovered"));
    // Nothing reached the service while the question stands.
    assert_eq!(rig.service_calls(), []);
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    assert_eq!(rig.keys()?.len(), 2);
    rig.forget();

    run.send(b"yes\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(0), "{}", done.stderr);
    assert_eq!(done.stdout, "Deleted key 'old-key'.\n");
    assert_eq!(done.stderr, "");
    assert_eq!(rig.polkit_asked(), [DELETE_ACTION_ID.to_owned()]);
    // One call, `DeleteKey(s)` to the documented name, path and interface.
    assert_eq!(
        rig.service_calls(),
        [(
            OBJECT_PATH.to_owned(),
            BUS_NAME.to_owned(),
            "DeleteKey".to_owned(),
            "s".to_owned()
        )]
    );
    assert_eq!(rig.keys()?, ["keep"]);
    Ok(())
}

/// Answers the question with `answer` (or hangs up) and checks that nothing was deleted and
/// nothing was asked of the service or polkit.
fn declined(answer: Option<&[u8]>) -> Result<Finished, Box<dyn Error>> {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.forget();
    let mut run = Run::start(&rig, &delete_args("k"), &[], true, b"")?;
    run.wait_for(&question("k"))?;
    match answer {
        Some(bytes) => run.send(bytes)?,
        None => run.hang_up(),
    }
    let done = run.finish()?;
    assert_ne!(done.status.code(), Some(0), "{}", done.stderr);
    assert_eq!(done.stdout, "");
    assert_eq!(rig.service_calls(), []);
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    assert_eq!(rig.keys()?, ["k"]);
    Ok(done)
}

const DECLINE: &str = "custodio: not confirmed; nothing was deleted\n";

#[test]
fn answering_no_deletes_nothing_and_calls_nothing() -> TestResult {
    let done = declined(Some(b"n\n"))?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stderr, DECLINE);
    Ok(())
}

#[test]
fn end_of_input_declines() -> TestResult {
    let done = declined(Some(b"\x04"))?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stderr, DECLINE);
    Ok(())
}

#[test]
fn a_hangup_of_the_terminal_deletes_nothing() -> TestResult {
    // The session leader gets SIGHUP, or reads the end of input: either way, non-zero.
    declined(None)?;
    Ok(())
}

#[test]
fn a_denied_polkit_deletes_nothing() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.polkit(Polkit::Deny);
    rig.forget();
    let mut run = Run::start(&rig, &delete_args("k"), &[], true, b"")?;
    run.wait_for(&question("k"))?;
    run.send(b"yes\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stdout, "");
    assert_eq!(done.stderr, message(&ServiceFailure::PolkitDenied));
    assert_eq!(rig.polkit_asked(), [DELETE_ACTION_ID.to_owned()]);
    assert_eq!(rig.keys()?, ["k"]);
    Ok(())
}

#[test]
fn a_missing_id_is_no_such_key_without_asking_polkit() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("other")?;
    rig.forget();
    let mut run = Run::start(&rig, &delete_args("missing"), &[], true, b"")?;
    run.wait_for(&question("missing"))?;
    run.send(b"y\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stdout, "");
    assert_eq!(done.stderr, message(&ServiceFailure::NoSuchKey));
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    assert_eq!(rig.service_calls().len(), 1);
    assert_eq!(rig.keys()?, ["other"]);
    Ok(())
}

#[test]
fn without_a_terminal_it_refuses_and_reads_no_answer_from_stdin() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.forget();
    let run = Run::start(&rig, &delete_args("k"), &[], false, b"yes\ny\nyes\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stdout, "");
    assert_eq!(
        done.stderr,
        "custodio: deleting a key must be confirmed on a terminal and there is none; nothing was deleted\n"
    );
    assert_eq!(rig.service_calls(), []);
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    assert_eq!(rig.keys()?, ["k"]);
    Ok(())
}

#[test]
fn no_environment_variable_removes_the_question() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.forget();
    let env = [
        ("CUSTODIO_YES", "1"),
        ("YES", "1"),
        ("FORCE", "1"),
        ("CUSTODIO_FORCE", "yes"),
    ];
    let mut run = Run::start(&rig, &delete_args("k"), &env, true, b"yes\n")?;
    run.wait_for(&question("k"))?;
    assert_eq!(rig.service_calls(), []);
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    run.send(b"no\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stderr, DECLINE);
    assert_eq!(rig.keys()?, ["k"]);
    Ok(())
}

#[test]
fn options_are_usage_errors_before_any_question() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.forget();
    for args in [
        &["delete", "--yes", "k"][..],
        &["delete", "-y", "k"],
        &["delete"],
    ] {
        let run = Run::start(&rig, args, &[], true, b"")?;
        let screen = run.screen.clone();
        let done = run.finish()?;
        let shown = screen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert_eq!(done.status.code(), Some(2), "{args:?}");
        assert_eq!(done.stdout, "");
        assert_eq!(done.stderr.trim_end(), USAGE);
        assert!(shown.is_empty(), "{shown:?}");
    }
    assert_eq!(rig.service_calls(), []);
    assert_eq!(rig.keys()?, ["k"]);
    Ok(())
}

#[test]
fn an_unidentifiable_caller_shows_authorization_unavailable_without_service_text() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.broken.store(true, Ordering::SeqCst);
    rig.forget();
    let mut run = Run::start(&rig, &delete_args("k"), &[], true, b"")?;
    run.wait_for(&question("k"))?;
    run.send(b"yes\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(
        done.stderr,
        message(&ServiceFailure::AuthorizationUnavailable)
    );
    assert!(!done.stderr.contains(FREE_TEXT));
    rig.broken.store(false, Ordering::SeqCst);
    assert_eq!(rig.keys()?, ["k"]);
    Ok(())
}

#[test]
fn an_absent_service_is_status_1_with_the_cannot_talk_message() -> TestResult {
    let rig = Rig::start(false)?;
    let mut run = Run::start(&rig, &delete_args("k"), &[], true, b"")?;
    run.wait_for(&question("k"))?;
    run.send(b"yes\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stdout, "");
    assert_eq!(done.stderr, message(&ServiceFailure::ServiceAbsent));
    assert!(done.status.signal().is_none());
    Ok(())
}
