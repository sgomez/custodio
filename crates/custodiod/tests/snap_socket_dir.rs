//! The snap socket: served only from a directory owned by root and writable by root alone, and then only accepted and
//! closed. In-process tests of `serve`, and the built `custodiod` under `systemd-socket-activate` for the wiring of
//! the descriptor (a refused or unnamed socket never touches the bus).

use std::error::Error;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use custodiod::dbus::{BUS_NAME, OBJECT_PATH};
use std::sync::Arc;

use custodiod::snap_socket::{Outcome, Service, descriptor_name, serve};
use custodiod::store::KeyStore;
use zbus::block_on;
use zbus::connection::Builder;

type TestResult = Result<(), Box<dyn Error>>;

fn none<T>() -> Vec<T> {
    Vec::new()
}

const NAME: &str = "snap-firefox";

fn service(dir: &Path) -> Result<Service, Box<dyn Error>> {
    Ok(Service::new(
        Arc::new(KeyStore::open(dir.join("keys"))?),
        Arc::new(|_| {}),
    ))
}

fn socket(dir: &Path) -> Result<(UnixListener, PathBuf), Box<dyn Error>> {
    let path = dir.join("custodio.sock");
    Ok((UnixListener::bind(&path)?, path))
}

/// The line `serve` journals for a refusal, with the socket and the reason.
fn refused(dir: &Path, expected: &str) -> TestResult {
    let tmp = tempfile::tempdir()?;
    let (listener, path) = socket(tmp.path())?;
    let mut journal = Vec::new();
    let outcome = serve(NAME, listener, dir, &mut journal, &service(tmp.path())?);
    let Outcome::Refused(listener, _) = outcome else {
        return Err("the socket was served".into());
    };
    assert_eq!(
        String::from_utf8(journal)?,
        format!(
            "custodiod: socket {NAME} is not served: {expected} ({})\n",
            dir.display()
        )
    );
    // The journal line is written: whatever happens now to a client is what a refused socket does. It is connected
    // (the backlog takes it) and then nothing comes back, neither a byte nor the end of the stream.
    let client = UnixStream::connect(&path)?;
    client.set_nonblocking(true)?;
    let mut buf = [0u8; 1];
    let err = (&client).read(&mut buf).err().ok_or("read returned")?;
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
    drop(listener);
    drop(client);
    Ok(())
}

#[test]
fn a_served_connection_gets_no_reply_and_the_service_goes_on() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let (listener, path) = socket(tmp.path())?;
    let mut journal = Vec::new();
    assert!(matches!(
        serve(
            NAME,
            listener,
            Path::new("/usr"),
            &mut journal,
            &service(tmp.path())?
        ),
        Outcome::Serving
    ));
    assert_eq!(journal, none());
    let mut first = UnixStream::connect(&path)?;
    // Bytes sent first are neither read nor answered. The peer closed without reading them, so the stream ends with
    // either the end of file or a reset, and in no case with data.
    let _ = first.write_all(b"hello");
    let mut buf = Vec::new();
    match first.read_to_end(&mut buf) {
        Ok(_) => {}
        Err(e) => assert_eq!(e.kind(), ErrorKind::ConnectionReset),
    }
    assert_eq!(buf, none());
    for _ in 0..3 {
        let mut again = UnixStream::connect(&path)?;
        let mut rest = Vec::new();
        again.read_to_end(&mut rest)?;
        assert_eq!(rest, none());
    }
    Ok(())
}

#[test]
fn a_directory_of_another_owner_is_not_served() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("d");
    std::fs::create_dir(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
    if rustix::process::getuid().is_root() {
        eprintln!(
            "skipped: running as root, the directory is owned by root; the mode tests decide"
        );
        return Ok(());
    }
    refused(&dir, "the directory is not owned by root")?;
    Ok(())
}

#[test]
fn a_group_writable_directory_is_not_served() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("d");
    std::fs::create_dir(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775))?;
    refused(&dir, "the directory is writable by its group")?;
    Ok(())
}

#[test]
fn an_other_writable_directory_is_not_served() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("d");
    std::fs::create_dir(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o757))?;
    refused(&dir, "the directory is writable by others")?;
    Ok(())
}

#[test]
fn a_symlink_to_a_good_directory_is_not_served() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink("/usr", &link)?;
    refused(&link, "the directory is a symbolic link")?;
    Ok(())
}

#[test]
fn a_missing_directory_is_not_served() -> TestResult {
    refused(
        Path::new("/nonexistent/snap.firefox"),
        "the directory does not exist",
    )?;
    Ok(())
}

// ---- the built binary, started the way systemd starts it ----

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Run {
    _bus: Proc,
    _service: Proc,
    _state: tempfile::TempDir,
    _dir: tempfile::TempDir,
    socket: PathBuf,
    address: String,
    journal: Receiver<String>,
}

/// Starts `custodiod` under `systemd-socket-activate --fdname=<fdname> -l <socket>` on a private bus. The service
/// runs when the first client connects, so the caller connects after this returns.
fn start(fdname: &str, check_dir: &str) -> Result<Run, Box<dyn Error>> {
    let mut bus = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut address = String::new();
    BufReader::new(bus.stdout.take().ok_or("no stdout")?).read_line(&mut address)?;
    let bus = Proc(bus);
    let address = address.trim().to_owned();
    let state = tempfile::tempdir()?;
    // The store wants exactly 0700; a setgid parent would add a bit.
    std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700))?;
    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("custodio.sock");
    let mut service = Command::new("systemd-socket-activate")
        .arg(format!("--fdname={fdname}"))
        .arg("-l")
        .arg(&socket)
        // The activator passes on only the variables it is told to.
        .arg(format!("-EDBUS_SYSTEM_BUS_ADDRESS={address}"))
        .arg(format!("-ESTATE_DIRECTORY={}", state.path().display()))
        .arg(format!("-ECUSTODIOD_TEST_SNAP_DIR={check_dir}"))
        .arg(env!("CARGO_BIN_EXE_custodiod"))
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    let stderr = service.stderr.take().ok_or("no stderr")?;
    let (tx, journal) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        if Instant::now() > deadline {
            return Err("systemd-socket-activate did not listen".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(Run {
        _bus: bus,
        _service: Proc(service),
        _state: state,
        _dir: dir,
        socket,
        address,
        journal,
    })
}

impl Run {
    /// Waits until the service answers `ListKeys` on the private bus.
    fn wait_for_bus(&self) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(20);
        block_on(async {
            let client = Builder::address(self.address.as_str()).build().await?;
            loop {
                let reply = client
                    .call_method(
                        Some(BUS_NAME),
                        OBJECT_PATH,
                        Some("com.rfirma.Custodio1"),
                        "ListKeys",
                        &(),
                    )
                    .await;
                if reply.is_ok() {
                    return Ok(());
                }
                if Instant::now() > deadline {
                    return Err(format!("the bus never answered: {reply:?}").into());
                }
                // zbus has its own executor; a short blocking pause between polls is all this needs.
                std::thread::sleep(Duration::from_millis(20));
            }
        })
    }

    fn wait_for_journal(&self, needle: &str) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self.journal.recv_timeout(left)?;
            if line.contains(needle) {
                return Ok(());
            }
        }
    }
}

#[test]
fn the_binary_serves_the_socket_named_for_firefox() -> TestResult {
    let run = start(&descriptor_name("firefox"), "/usr")?;
    let mut client = UnixStream::connect(&run.socket)?;
    let mut buf = Vec::new();
    client.read_to_end(&mut buf)?;
    assert_eq!(buf, none());
    run.wait_for_bus()
}

#[test]
fn a_refused_directory_leaves_the_bus_alone_and_the_socket_unserved() -> TestResult {
    let run = start(&descriptor_name("firefox"), "/tmp")?;
    let client = UnixStream::connect(&run.socket)?;
    run.wait_for_journal(
        "socket snap-firefox is not served: the directory is writable by its group",
    )?;
    run.wait_for_bus()?;
    client.set_nonblocking(true)?;
    let mut buf = [0u8; 1];
    let err = (&client).read(&mut buf).err().ok_or("read returned")?;
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
    Ok(())
}

#[test]
fn a_descriptor_with_another_name_is_not_served() -> TestResult {
    let run = start("snap-chromium", "/usr")?;
    let mut client = UnixStream::connect(&run.socket)?;
    run.wait_for_bus()?;
    // The service closed the listener it did not know: the waiting connection is reset, it is not accepted and closed.
    let mut buf = Vec::new();
    let err = client.read_to_end(&mut buf).err().ok_or("end of file")?;
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
    assert_eq!(buf, none());
    Ok(())
}
