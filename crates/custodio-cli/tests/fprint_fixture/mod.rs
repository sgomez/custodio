//! The fixture of the `custodio fingerprint` and `custodio doctor` tests: a temporary root with a Debian-family
//! system, the files the commands read under it, and a private bus with a fake `net.reactivated.Fprint`.
//! The fake records every call, with the D-Bus header flag that allows interactive authorization.
#![allow(
    dead_code,
    reason = "each test crate that includes this fixture uses a different part of it"
)]
#![allow(
    clippy::needless_pass_by_value,
    clippy::used_underscore_binding,
    reason = "zbus's interface macro needs owned arguments and takes the D-Bus argument names from the parameter names"
)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zbus::{OwnedObjectPath, block_on};

/// The CLI under test. Cargo sets the variable for integration tests; the documents' fake service (an example of
/// `custodio-it`) includes this file only for the fake and never starts the CLI.
const CLI_BIN: &str = match option_env!("CARGO_BIN_EXE_custodio-cli") {
    Some(path) => path,
    None => "custodio-cli",
};

pub const POLKIT: &str = "etc/pam.d/polkit-1";
pub const MULTIARCH: &str = "usr/lib/x86_64-linux-gnu/security";
pub const OMARCHY: &str = "#%PAM-1.0\nauth sufficient pam_fprintd.so\nauth include system-auth\n";
pub const GLOBAL_PAM: &str = "auth sufficient pam_fprintd.so\nauth required pam_unix.so\n";

/// The forms of "fingerprint is on for the whole system", one per family: (os-release, file, content).
pub const GLOBAL_FORMS: [(&str, &str, &str); 4] = [
    ("ID=debian\n", "etc/pam.d/common-auth", GLOBAL_PAM),
    (
        "ID=fedora\n",
        "etc/authselect/authselect.conf",
        "sssd\nwith-fingerprint\n",
    ),
    ("ID=arch\n", "etc/pam.d/system-auth", GLOBAL_PAM),
    ("ID=arch\n", "etc/pam.d/sudo", GLOBAL_PAM),
];

pub struct Fx {
    dir: tempfile::TempDir,
}

pub type Tree = BTreeMap<String, (String, Vec<u8>, u32)>;

impl Fx {
    /// A Debian-family system with polkit's vendor file, the module (multiarch), fprintd and no override.
    pub fn new() -> Self {
        let fx = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        fx.put("etc/os-release", "ID=debian\n");
        fx.put("etc/pam.d/.keep", "");
        fx.put("usr/lib/pam.d/polkit-1", "auth include system-auth\n");
        fx.put(&format!("{MULTIARCH}/pam_fprintd.so"), "module");
        fx.put(
            "usr/share/dbus-1/system-services/net.reactivated.Fprint.service",
            "[D-BUS Service]\n",
        );
        // Checks 4 and 5 of doctor are satisfied: no browser profile (an empty home), a persistent journal.
        fs::create_dir_all(fx.home()).unwrap();
        fx.put(
            "etc/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n",
        );
        fx
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// The home directory of the person doctor runs for.
    pub fn home(&self) -> PathBuf {
        self.root().join("home/person")
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root().join(rel)
    }

    pub fn put(&self, rel: &str, text: &str) {
        let p = self.path(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    pub fn remove(&self, rel: &str) {
        fs::remove_file(self.path(rel)).unwrap();
    }

    pub fn tree(&self) -> Tree {
        let mut tree = Tree::new();
        walk(self.root(), self.root(), &mut tree);
        tree
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, &[("DBUS_SYSTEM_BUS_ADDRESS", &self.no_bus())])
    }

    pub fn no_bus(&self) -> String {
        format!("unix:path={}", self.path("no-bus").display())
    }

    pub fn run_with(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut c = Command::new(CLI_BIN);
        c.arg("fingerprint")
            .args(args)
            .env("CUSTODIO_FIXTURE_ROOT", self.root())
            .env("CUSTODIO_FIXTURE_EUID", "0");
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    }
}

fn walk(root: &Path, dir: &Path, tree: &mut Tree) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
        let m = fs::symlink_metadata(&p).unwrap();
        let mode = m.permissions().mode();
        if m.is_dir() {
            tree.insert(rel, ("dir".into(), vec![], mode));
            walk(root, &p, tree);
        } else if m.file_type().is_symlink() {
            let to = fs::read_link(&p).unwrap();
            tree.insert(
                rel,
                (
                    "link".into(),
                    to.as_os_str().as_encoded_bytes().to_vec(),
                    mode,
                ),
            );
        } else {
            tree.insert(rel, ("file".into(), fs::read(&p).unwrap(), mode));
        }
    }
}

pub fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

pub struct Bus {
    child: Child,
    pub address: String,
}

impl Bus {
    pub fn new() -> Self {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut address = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Self {
            child,
            address: address.trim().to_owned(),
        }
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What `ListEnrolledFingers` answers.
#[derive(Clone)]
pub enum Fingers {
    List(&'static [&'static str]),
    /// `net.reactivated.Fprint.Error.NoEnrolledPrints`.
    NoPrints,
    /// The refusal of an ssh session: `PermissionDenied`, "Not Authorized: net.reactivated.fprint.device.verify".
    Refused,
    Other,
}

/// How the fake Custodio service answers `StateStorage` and `StateStorageReason`.
#[derive(Clone)]
pub struct Svc {
    /// The wire value of `StateStorage`.
    pub storage: &'static str,
    /// `StateStorageReason`; `None`: the method does not exist (a service that predates it).
    pub reason: Option<&'static str>,
    /// Wait before `StateStorage` answers.
    pub delay: Duration,
    /// `StateStorage` answers with an error.
    pub error: bool,
}

impl Svc {
    pub fn answering(storage: &'static str, reason: Option<&'static str>) -> Self {
        Self {
            storage,
            reason,
            delay: Duration::ZERO,
            error: false,
        }
    }
}

/// How the fake answers.
#[derive(Clone)]
pub struct Fake {
    /// Whether `net.reactivated.Fprint` is served at all.
    pub fprintd: bool,
    /// The Custodio service on the same bus; `None`: nothing owns its name.
    pub service: Option<Svc>,
    pub devices: usize,
    /// `GetDevices` answers with an error.
    pub devices_error: bool,
    /// Wait before `GetDevices` answers.
    pub delay: Duration,
    pub fingers: Fingers,
    /// Wait before `ListEnrolledFingers` answers.
    pub fingers_delay: Duration,
}

impl Fake {
    pub fn new(devices: usize) -> Self {
        Self {
            fprintd: true,
            service: Some(Svc::answering("encrypted", Some(""))),
            devices,
            devices_error: false,
            delay: Duration::ZERO,
            fingers: Fingers::NoPrints,
            fingers_delay: Duration::ZERO,
        }
    }
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "net.reactivated.Fprint.Error")]
enum FprintError {
    #[zbus(error)]
    ZBus(zbus::Error),
    NoEnrolledPrints(String),
    PermissionDenied(String),
    Internal(String),
}

type Calls = Arc<Mutex<Vec<String>>>;

/// Records `method`, with ` interactive` when the message allows interactive authorization.
fn record(calls: &Calls, method: &str, header: &zbus::message::Header<'_>) {
    let interactive = header
        .primary()
        .flags()
        .contains(zbus::message::Flags::ALLOW_INTERACTIVE_AUTH);
    let suffix = if interactive { " interactive" } else { "" };
    calls.lock().unwrap().push(format!("{method}{suffix}"));
}

struct Manager {
    calls: Calls,
    fake: Fake,
}

#[zbus::interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    fn get_devices(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<Vec<OwnedObjectPath>, FprintError> {
        record(&self.calls, "GetDevices", &header);
        std::thread::sleep(self.fake.delay);
        if self.fake.devices_error {
            return Err(FprintError::Internal("the manager is broken".into()));
        }
        Ok((0..self.fake.devices).map(device_path).collect())
    }

    fn get_default_device(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> OwnedObjectPath {
        record(&self.calls, "GetDefaultDevice", &header);
        device_path(0)
    }
}

fn device_path(i: usize) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("/net/reactivated/Fprint/Device/{i}")).unwrap()
}

struct Device {
    calls: Calls,
    fake: Fake,
}

#[zbus::interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    fn list_enrolled_fingers(
        &self,
        _username: String,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<Vec<String>, FprintError> {
        record(&self.calls, "ListEnrolledFingers", &header);
        std::thread::sleep(self.fake.fingers_delay);
        match &self.fake.fingers {
            Fingers::List(l) => Ok(l.iter().map(|f| (*f).to_owned()).collect()),
            Fingers::NoPrints => Err(FprintError::NoEnrolledPrints(
                "Fingerprint not enrolled".into(),
            )),
            Fingers::Refused => Err(FprintError::PermissionDenied(
                "Not Authorized: net.reactivated.fprint.device.verify".into(),
            )),
            Fingers::Other => Err(FprintError::Internal("the device is broken".into())),
        }
    }

    fn claim(&self, _username: String, #[zbus(header)] header: zbus::message::Header<'_>) {
        record(&self.calls, "Claim", &header);
    }

    fn verify_start(&self, _finger: String, #[zbus(header)] header: zbus::message::Header<'_>) {
        record(&self.calls, "VerifyStart", &header);
    }
}

/// Serves the fake on `address`; returns the calls it records.
pub fn fake_fprintd(address: &str, devices: usize, delay: Duration) -> Calls {
    serve(
        address,
        Fake {
            delay,
            ..Fake::new(devices)
        },
    )
}

/// What the fakes on the bus recorded.
#[derive(Clone, Default)]
pub struct Served {
    pub fprintd: Calls,
    pub service: Calls,
    /// Every call to the fake polkit authority, by method name.
    pub polkit: Calls,
}

struct Custodio {
    calls: Calls,
    svc: Svc,
}

#[zbus::interface(name = "com.rfirma.Custodio1")]
impl Custodio {
    fn state_storage(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<String, FprintError> {
        record(&self.calls, "StateStorage", &header);
        std::thread::sleep(self.svc.delay);
        if self.svc.error {
            return Err(FprintError::Internal("the service is broken".into()));
        }
        Ok(self.svc.storage.to_owned())
    }

    fn state_storage_reason(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let Some(reason) = self.svc.reason else {
            // A service that predates the method.
            return Err(zbus::fdo::Error::UnknownMethod(
                "Unknown method 'StateStorageReason'".into(),
            ));
        };
        record(&self.calls, "StateStorageReason", &header);
        Ok(reason.to_owned())
    }
}

/// The polkit authority: it records every `CheckAuthorization` (and says no).
struct Authority {
    calls: Calls,
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl Authority {
    fn check_authorization(
        &self,
        _subject: (
            String,
            std::collections::HashMap<String, zbus::OwnedVariant>,
        ),
        action_id: String,
        _details: std::collections::HashMap<String, String>,
        _flags: u32,
        _cancellation_id: String,
    ) -> (bool, bool, std::collections::HashMap<String, String>) {
        self.calls
            .lock()
            .unwrap()
            .push(format!("CheckAuthorization {action_id}"));
        (false, false, std::collections::HashMap::new())
    }
}

/// Serves `fake` on `address`; returns the calls it records.
pub fn serve(address: &str, fake: Fake) -> Calls {
    serve_all(address, fake).fprintd
}

/// Serves `fake`, the Custodio service and a polkit authority on `address`; returns what each recorded.
pub fn serve_all(address: &str, fake: Fake) -> Served {
    let served = Served::default();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let manager = Manager {
        calls: served.fprintd.clone(),
        fake: fake.clone(),
    };
    let address_again = address.to_owned();
    let service = fake.service.clone();
    let address = address.to_owned();
    let all = served.clone();
    std::thread::spawn(move || {
        block_on(async {
            let mut builder = zbus::connection::Builder::address(address.as_str())
                .name("org.freedesktop.PolicyKit1")
                .serve_at(
                    "/org/freedesktop/PolicyKit1/Authority",
                    Authority {
                        calls: all.polkit.clone(),
                    },
                );
            if fake.fprintd {
                builder = builder
                    .name("net.reactivated.Fprint")
                    .serve_at("/net/reactivated/Fprint/Manager", manager);
                for i in 0..fake.devices {
                    let device = Device {
                        calls: all.fprintd.clone(),
                        fake: fake.clone(),
                    };
                    builder = builder.serve_at(device_path(i), device);
                }
            }
            let _connection = builder.build().await.unwrap();
            ready_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
    });
    ready_rx.recv().unwrap();
    // The service has its own connection: a slow answer of it must not hold up fprintd's.
    if let Some(svc) = service {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let calls = served.service.clone();
        let address = address_again;
        std::thread::spawn(move || {
            block_on(async {
                let _connection = zbus::connection::Builder::address(address.as_str())
                    .name("com.rfirma.Custodio1")
                    .serve_at("/com/rfirma/Custodio1", Custodio { calls, svc })
                    .build()
                    .await
                    .unwrap();
                ready_tx.send(()).unwrap();
                std::future::pending::<()>().await;
            });
        });
        ready_rx.recv().unwrap();
    }
    served
}

// ---- `custodio doctor` ----

impl Fx {
    /// `custodio doctor` as the person (uid 1000) on this root and this bus: no terminal, an empty `PATH` (no browser,
    /// no `pkttyagent`), nothing else of the environment.
    pub fn doctor(&self, bus: &str) -> Output {
        self.doctor_as(bus, "1000")
    }

    pub fn doctor_as(&self, bus: &str, euid: &str) -> Output {
        let empty = self.path("empty-path");
        Command::new(CLI_BIN)
            .arg("doctor")
            .env_clear()
            // Under cargo llvm-cov the instrumented binary writes its profile where this says.
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
            .env("PATH", &empty)
            .env("CUSTODIO_FIXTURE_ROOT", self.root())
            .env("CUSTODIO_FIXTURE_EUID", euid)
            .env("DBUS_SYSTEM_BUS_ADDRESS", bus)
            .env("HOME", self.home())
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}

/// An address nothing listens on.
pub const NO_BUS: &str = "unix:path=/nonexistent/custodio-bus";

mod report;
#[allow(unused_imports)] // Each test binary uses its own part of the reader.
pub use report::{FINGER, Line, POLKIT_CHECK, READER, check, checks, fixes, report, state};
