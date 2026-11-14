//! The module's transport choice (F178): inside a snap it talks to the snap's socket and never the bus.
//!
//! Arrangement: the service runs in process on a socket in a tempdir (`serve`, with the `test-seam` source giving the
//! Firefox label and a fixed uid; the service's own directory check is given `/usr`). The module runs as a child (this
//! binary re-executed, because the environment cannot be set in a threaded process) through `unshare -Ur`, in which the
//! test user is root, so a directory the test made is root-owned for the module's check. Only the child is namespaced.
//! The "system bus" is a listener that counts connections and hangs up. The module is exercised through
//! `DbusBackend`, the one place that talks to the service; the PKCS#11 layer shows `Unavailable` as no slots (unit
//! tests of `custodio-pkcs11`). Waits are on the child's exit.

use std::error::Error;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use custodio_pkcs11::backend::{Backend, BackendError, DbusBackend, SignParams};
use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::seal;
use custodiod::snap_socket::peer::{Peer, Source};
use custodiod::snap_socket::{Outcome, Service, serve};
use custodiod::store::{KeyStore, Kind, Protected, Record};
use secrecy::SecretSlice;

type TestResult = Result<(), Box<dyn Error>>;

const CERT: &[u8] = include_bytes!("fixtures/cert-p256-other.der");
const UID: u32 = 4001;
const MODE_VAR: &str = "SNAP_TRANSPORT_CHILD";
const BASE_VAR: &str = "CUSTODIO_TEST_SOCKET_BASE_DIR";

/// Serves a store with one key on `<base>/snap.<name>/custodio.sock`, counting accepted connections of the bus double.
struct Rig {
    base: tempfile::TempDir,
    _store: tempfile::TempDir,
    bus: PathBuf,
    bus_connections: Arc<AtomicUsize>,
}

fn dir_mode(path: &Path, mode: u32) -> TestResult {
    Ok(std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(mode),
    )?)
}

impl Rig {
    /// `name`: the instance name the directory is made for; `mode` its permissions.
    fn start(name: &str, mode: u32) -> Result<Self, Box<dyn Error>> {
        let base = tempfile::tempdir()?;
        let store_dir = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(store_dir.path().join("keys"))?);
        let key = SecretSlice::from(b"a-key-that-is-not-in-the-clear".to_vec());
        let sealed = seal(&MemoryCreds::host(), &format!("{UID}-ec"), &key)?;
        store.put(&Record::new(
            UID,
            "ec",
            Kind::EncryptedHost,
            CERT,
            Protected::from_sealed(&sealed),
        )?)?;
        let dir = base.path().join(format!("snap.{name}"));
        std::fs::create_dir(&dir)?;
        dir_mode(&dir, mode)?;
        let listener = UnixListener::bind(dir.join("custodio.sock"))?;
        let service =
            Service::new(store, Arc::new(|_| {})).with_source(Source::Injected(Arc::new(|_| {
                Peer {
                    uid: Some(UID),
                    pid: Some(4242),
                    pidfd: File::open("/dev/null").ok().map(OwnedFd::from),
                    label: Some(b"snap.firefox.firefox (enforce)".to_vec()),
                }
            })));
        let mut journal = Vec::new();
        let outcome = serve(
            "snap-firefox",
            listener,
            Path::new("/usr"),
            &mut journal,
            &service,
        );
        assert!(matches!(outcome, Outcome::Serving));
        let bus = base.path().join("bus");
        let bus_listener = UnixListener::bind(&bus)?;
        let bus_connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&bus_connections);
        thread::spawn(move || {
            // Counts and hangs up at once, so a client that reaches it fails instead of waiting.
            for stream in bus_listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        Ok(Self {
            base,
            _store: store_dir,
            bus,
            bus_connections,
        })
    }

    fn bus_connections(&self) -> usize {
        self.bus_connections.load(Ordering::SeqCst)
    }

    /// The module as a child. `instance`: the value of `SNAP_INSTANCE_NAME`, unset for `None`. `namespaced`: root-mapped.
    fn child(
        &self,
        mode: &str,
        instance: Option<&str>,
        namespaced: bool,
    ) -> Result<Output, Box<dyn Error>> {
        let exe = std::env::current_exe()?;
        let mut cmd = if namespaced {
            let mut c = Command::new("unshare");
            c.arg("-Ur").arg(&exe);
            c
        } else {
            Command::new(&exe)
        };
        cmd.args(["--exact", "module_child", "--nocapture", "--test-threads=1"])
            .env(MODE_VAR, mode)
            .env(BASE_VAR, self.base.path())
            .env(
                "DBUS_SYSTEM_BUS_ADDRESS",
                format!("unix:path={}", self.bus.display()),
            )
            .env_remove("SNAP_INSTANCE_NAME");
        if let Some(name) = instance {
            cmd.env("SNAP_INSTANCE_NAME", name);
        }
        Ok(cmd.output()?)
    }

    fn lines(
        &self,
        mode: &str,
        instance: Option<&str>,
        namespaced: bool,
    ) -> Result<String, Box<dyn Error>> {
        let out = self.child(mode, instance, namespaced)?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.find("RESULT ").map(|at| &l[at..]))
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

/// The child: calls the backend as the module does and prints one `RESULT` line per call.
#[test]
fn module_child() {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return;
    };
    let params = SignParams {
        mechanism: 0x1041,
        hash: 0,
        salt_len: 0,
    };
    let show = |what: &str, r: Result<String, BackendError>| match r {
        Ok(v) => println!("RESULT {what} ok {v}"),
        Err(e) => println!("RESULT {what} {e:?}"),
    };
    let list = || {
        DbusBackend.list_certificates().map(|k| {
            format!(
                "{:?}",
                k.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>()
            )
        })
    };
    match mode.as_str() {
        "list" => show("list", list()),
        "sign" => show(
            "sign",
            DbusBackend
                .sign("ec", params, &[7; 32])
                .map(|s| s.len().to_string()),
        ),
        "threads" => {
            let handles: Vec<_> = (0..8).map(|_| thread::spawn(list)).collect();
            for h in handles {
                show("list", h.join().unwrap_or(Err(BackendError::Unavailable)));
            }
        }
        _ => println!("RESULT unknown mode"),
    }
}

#[test]
fn socket_is_used_and_the_bus_is_never_touched() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    assert_eq!(
        rig.lines("list", Some("firefox"), true)?,
        "RESULT list ok [\"ec\"]"
    );
    // No signing is configured on the service: it fails closed, which the module maps as on the bus (a refusal).
    assert_eq!(
        rig.lines("sign", Some("firefox"), true)?,
        "RESULT sign Denied"
    );
    assert_eq!(rig.bus_connections(), 0);
    Ok(())
}

#[test]
fn unset_uses_the_bus() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    assert_eq!(rig.lines("list", None, true)?, "RESULT list Unavailable");
    assert_eq!(rig.bus_connections(), 1);
    Ok(())
}

#[test]
fn an_invalid_instance_name_gives_no_slots() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    for name in [
        "",
        "../firefox",
        "Firefox",
        "fire/fox",
        "firefox_",
        "-firefox",
    ] {
        assert_eq!(
            rig.lines("list", Some(name), true)?,
            "RESULT list Unavailable",
            "{name:?}"
        );
    }
    assert_eq!(rig.bus_connections(), 0);
    Ok(())
}

#[test]
fn a_missing_socket_gives_no_slots() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    assert_eq!(
        rig.lines("list", Some("chromium"), true)?,
        "RESULT list Unavailable"
    );
    let dir = rig.base.path().join("snap.chromium");
    std::fs::create_dir(&dir)?;
    dir_mode(&dir, 0o700)?;
    assert_eq!(
        rig.lines("list", Some("chromium"), true)?,
        "RESULT list Unavailable"
    );
    assert_eq!(rig.bus_connections(), 0);
    Ok(())
}

#[test]
fn a_stale_socket_file_gives_no_slots() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    let dir = rig.base.path().join("snap.chromium");
    std::fs::create_dir(&dir)?;
    dir_mode(&dir, 0o700)?;
    drop(UnixListener::bind(dir.join("custodio.sock"))?);
    assert_eq!(
        rig.lines("list", Some("chromium"), true)?,
        "RESULT list Unavailable"
    );
    assert_eq!(rig.bus_connections(), 0);
    Ok(())
}

#[test]
fn a_directory_that_is_not_root_owned_and_root_only_writable_gives_no_slots() -> TestResult {
    // Group- and other-writable, even though root-owned in the namespace.
    for mode in [0o770, 0o707, 0o777] {
        let rig = Rig::start("firefox", mode)?;
        assert_eq!(
            rig.lines("list", Some("firefox"), true)?,
            "RESULT list Unavailable",
            "{mode:o}"
        );
        assert_eq!(rig.bus_connections(), 0);
    }
    // Owned by the test user, outside the namespace.
    let rig = Rig::start("firefox", 0o700)?;
    assert_eq!(
        rig.lines("list", Some("firefox"), false)?,
        "RESULT list Unavailable"
    );
    // A symbolic link to a good directory.
    let link = rig.base.path().join("snap.linked");
    std::os::unix::fs::symlink(rig.base.path().join("snap.firefox"), &link)?;
    assert_eq!(
        rig.lines("list", Some("linked"), true)?,
        "RESULT list Unavailable"
    );
    // A file in place of the directory.
    File::create(rig.base.path().join("snap.afile"))?;
    assert_eq!(
        rig.lines("list", Some("afile"), true)?,
        "RESULT list Unavailable"
    );
    assert_eq!(rig.bus_connections(), 0);
    Ok(())
}

#[test]
fn a_root_owned_root_only_directory_serves() -> TestResult {
    let rig = Rig::start("firefox_work1", 0o755)?;
    assert_eq!(
        rig.lines("list", Some("firefox_work1"), true)?,
        "RESULT list ok [\"ec\"]"
    );
    Ok(())
}

#[test]
fn concurrent_calls_use_separate_connections() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    let lines = rig.lines("threads", Some("firefox"), true)?;
    assert_eq!(
        lines
            .lines()
            .filter(|l| *l == "RESULT list ok [\"ec\"]")
            .count(),
        8,
        "{lines}"
    );
    assert_eq!(rig.bus_connections(), 0);
    Ok(())
}
