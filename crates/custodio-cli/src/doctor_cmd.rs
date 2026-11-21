//! `custodio doctor`: observes the system (files under the fixture root, `fprintd` on the system bus),
//! asks [`crate::doctor_decide`] for the report and prints it. It changes nothing, and asks nothing
//! that could raise a polkit dialog, a password prompt or a browser.
//!
//! What it asks `fprintd`: `GetDevices`, then `ListEnrolledFingers` on the first device with an empty user name
//! (fprintd takes the caller's). Neither call sets the interactive-authorization flag, so a session that may not
//! answer (ssh) gets a refusal, never a dialog. It never claims a device. Each question waits at most
//! [`ASK_LIMIT`]; D-Bus's own 25 s is never waited for.
//!
//! "Not installed" and "not answering" are told apart by two signs: not installed is no service file **and** the
//! bus saying the name has no owner (`ServiceUnknown`); a name that is there and times out, an error, a
//! service file with no owner and a bus that cannot be reached are all "could not check".

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use custodio_client::{BUS_NAME, OBJECT_PATH};
use zbus::{Connection, OwnedObjectPath, block_on};

use crate::browser_files::{local_address, read_bounded};
use crate::doctor_decide::{
    Copy, Entry, Facts, Fingers, Firefox, ProfileFact, Reader, Service, decide,
};
use crate::fingerprint_cmd::{env, observe};
use crate::journald_conf;
use crate::register_discover::{Environment, Profile, discover};
use crate::register_modutil::nss_loads_p11_kit;
use crate::register_native::{INSTALLED_MODULE, MODUTIL, Plan, parse_entries, plan};
use crate::register_snap::copy_path;
use crate::storage::StateStorage;

/// How long each question to `fprintd` is waited for.
pub const ASK_LIMIT: Duration = Duration::from_millis(1500);

const DESTINATION: &str = "net.reactivated.Fprint";
const NO_PRINTS: &str = "net.reactivated.Fprint.Error.NoEnrolledPrints";
const DENIED: &str = "net.reactivated.Fprint.Error.PermissionDenied";

/// Why the command did not succeed.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// Run as root: the answers are about the person, not about root.
    Root,
    /// A polkit include is broken; the report is on standard output.
    BrokenInclude,
    /// These checks that decide the exit status are not `ok`; the report is on standard output.
    Unsatisfied(Vec<&'static str>),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => f.write_str("custodio doctor: refused to run as root"),
            Self::BrokenInclude => f.write_str("custodio doctor: a polkit include is broken"),
            Self::Unsatisfied(names) => {
                write!(f, "custodio doctor: did not pass: {}", names.join(", "))
            }
        }
    }
}

impl std::error::Error for Failure {}

enum Answer {
    Reader(Reader, Option<OwnedObjectPath>),
    Fingers(Fingers),
}

fn ask_reader(connection: &Connection) -> Answer {
    let reply = block_on(connection.call_method(
        Some(DESTINATION),
        "/net/reactivated/Fprint/Manager",
        Some("net.reactivated.Fprint.Manager"),
        "GetDevices",
        &(),
    ));
    match reply {
        Err(e) if is_service_unknown(&e) => Answer::Reader(Reader::NoOwner, None),
        Err(e) => Answer::Reader(Reader::Failed(e.to_string()), None),
        Ok(reply) => match reply.body().deserialize::<Vec<OwnedObjectPath>>() {
            Ok(devices) => {
                Answer::Reader(Reader::Devices(devices.len()), devices.into_iter().next())
            }
            Err(e) => Answer::Reader(Reader::Failed(e.to_string()), None),
        },
    }
}

/// The bus says nothing owns the name (zbus turns the well-known bus errors into [`zbus::fdo::Error`]).
fn is_service_unknown(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::FDO(e) if matches!(**e, zbus::fdo::Error::ServiceUnknown(_)))
}

fn ask_fingers(connection: &Connection, device: &OwnedObjectPath) -> Answer {
    let reply = block_on(connection.call_method(
        Some(DESTINATION),
        device.as_str(),
        Some("net.reactivated.Fprint.Device"),
        "ListEnrolledFingers",
        &"",
    ));
    Answer::Fingers(match reply {
        Err(zbus::Error::MethodError(name, text, _)) => {
            let text = text.unwrap_or_default();
            match name.as_str() {
                NO_PRINTS => Fingers::NoPrints,
                DENIED => Fingers::Refused(text),
                other => Fingers::Failed(format!("{other}: {text}")),
            }
        }
        Err(e) => Fingers::Failed(e.to_string()),
        Ok(reply) => match reply.body().deserialize::<Vec<String>>() {
            Ok(list) => Fingers::Listed(list.len()),
            Err(e) => Fingers::Failed(e.to_string()),
        },
    })
}

/// Asks `fprintd` in a thread, so that the wait is ours and not D-Bus's.
fn ask() -> (Reader, Fingers) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let connection = match block_on(Connection::system()) {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(Answer::Reader(Reader::Failed(e.to_string()), None));
                return;
            }
        };
        let Answer::Reader(reader, device) = ask_reader(&connection) else {
            return;
        };
        let _ = tx.send(Answer::Reader(reader, None));
        if let Some(device) = device {
            let _ = tx.send(ask_fingers(&connection, &device));
        }
    });
    let timed_out = || format!("no answer within {} ms", ASK_LIMIT.as_millis());
    let Ok(Answer::Reader(reader, _)) = rx.recv_timeout(ASK_LIMIT) else {
        return (Reader::Failed(timed_out()), Fingers::NotAsked);
    };
    if !matches!(reader, Reader::Devices(n) if n > 0) {
        return (reader, Fingers::NotAsked);
    }
    let fingers = match rx.recv_timeout(ASK_LIMIT) {
        Ok(Answer::Fingers(f)) => f,
        _ => Fingers::Failed(timed_out()),
    };
    (reader, fingers)
}

/// Check 4, read-only: the discovery and the decisions of `custodio setup browsers enable`, without its writes.
fn observe_firefox(root: &Path) -> Firefox {
    let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) else {
        return Firefox::CouldNot("HOME is not set".to_owned());
    };
    let env = Environment {
        home: home.into(),
        xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
        local_address: local_address(),
    };
    let profiles = match discover(&env) {
        Ok(p) => p,
        Err(e) => return Firefox::CouldNot(e.to_string()),
    };
    if profiles.is_empty() {
        return Firefox::NoProfile;
    }
    let installed = root.join(INSTALLED_MODULE.trim_start_matches('/'));
    let mut p11_kit = None;
    let facts = profiles
        .iter()
        .map(|p| profile_fact(p, &env, &installed, &mut p11_kit))
        .collect();
    Firefox::Profiles(facts)
}

fn profile_fact(
    profile: &Profile,
    env: &Environment,
    installed: &Path,
    p11_kit: &mut Option<bool>,
) -> ProfileFact {
    let copy_file = copy_path(&env.home);
    let module = if profile.snap { &copy_file } else { installed };
    let mut entry = entry_of(profile, module);
    if matches!(entry, Entry::Missing | Entry::Stale) && !profile.snap {
        // `register` skips native profiles where the system NSS loads the p11-kit proxy; it decides with a scratch database.
        let on = *p11_kit.get_or_insert_with(|| nss_loads_p11_kit(OsStr::new(MODUTIL)) == Ok(true));
        if on {
            entry = Entry::P11Kit;
        }
    }
    ProfileFact {
        browser: profile.browser,
        path: crate::report::tilde(&profile.path, Some(&env.home)),
        copy: profile.snap.then(|| copy_state(&copy_file, installed)),
        entry,
    }
}

fn entry_of(profile: &Profile, module: &Path) -> Entry {
    let bytes = match read_bounded(&profile.path.join("pkcs11.txt")) {
        Ok(b) => b.unwrap_or_default(),
        Err(e) => return Entry::CouldNot(e.to_string()),
    };
    let entries = parse_entries(&String::from_utf8_lossy(&bytes));
    let Some(module) = module.to_str() else {
        return Entry::CouldNot("the module path is not valid UTF-8".to_owned());
    };
    match plan(&entries, module, |l| Path::new(l).exists()) {
        Plan::Present(name) => Entry::Present(name),
        Plan::PresentElsewhere(name) => Entry::PresentElsewhere(name),
        Plan::Refresh { .. } => Entry::Stale,
        Plan::Add(_) | Plan::NameTaken => Entry::Missing,
    }
}

fn copy_state(copy: &Path, installed: &Path) -> Copy {
    let meta = match fs::symlink_metadata(copy) {
        Ok(m) => m,
        Err(e) => {
            return if e.kind() == io::ErrorKind::NotFound {
                Copy::Missing
            } else {
                Copy::CouldNot(format!("{}: {e}", copy.display()))
            };
        }
    };
    // `register` replaces a link, never follows it.
    if !meta.file_type().is_file() {
        return Copy::Stale;
    }
    let read = |p: &Path| fs::read(p).map_err(|e| Copy::CouldNot(format!("{}: {e}", p.display())));
    match (read(installed), read(copy)) {
        (Ok(a), Ok(b)) if a == b => Copy::UpToDate,
        (Ok(_), Ok(_)) => Copy::Stale,
        (Err(c), _) | (_, Err(c)) => c,
    }
}

/// Check 5: the files and one `stat`.
fn observe_journal(root: &Path) -> journald_conf::Verdict {
    match journald_conf::read(root) {
        Ok(files) => journald_conf::evaluate(&files, &journald_conf::stat_journal_dir(root)),
        Err(why) => journald_conf::Verdict::CouldNot(why),
    }
}

/// One read-only question to the service, bounded by [`ASK_LIMIT`].
fn ask_service() -> Service {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let connection = match block_on(Connection::system()) {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(Err(e.to_string()));
                return;
            }
        };
        let call = |method: &str| {
            block_on(connection.call_method(
                Some(BUS_NAME),
                OBJECT_PATH,
                Some(BUS_NAME),
                method,
                &(),
            ))
            .map_err(|e| (is_service_unknown(&e), e.to_string()))
            .and_then(|r| {
                r.body()
                    .deserialize::<String>()
                    .map_err(|e| (false, e.to_string()))
            })
        };
        let storage = call("StateStorage");
        let unknown =
            matches!(&storage, Ok(w) if StateStorage::from_wire(w) == StateStorage::Unknown);
        let _ = tx.send(storage.map_err(|(none, why)| {
            if none {
                format!("nothing owns {BUS_NAME} on the system bus")
            } else {
                why
            }
        }));
        if unknown {
            // A service that predates the method answers `UnknownMethod`: no reason, none invented.
            let _ = tx.send(call("StateStorageReason").map_err(|(_, why)| why));
        }
    });
    let timed_out = || format!("no answer within {} ms", ASK_LIMIT.as_millis());
    let wire = match rx.recv_timeout(ASK_LIMIT) {
        Ok(Ok(wire)) => wire,
        Ok(Err(why)) => return Service::Unreachable(why),
        Err(_) => return Service::Unreachable(timed_out()),
    };
    let storage = StateStorage::from_wire(&wire);
    let reason = if storage == StateStorage::Unknown {
        rx.recv_timeout(ASK_LIMIT).ok().and_then(Result::ok)
    } else {
        None
    };
    Service::Answered(storage, reason)
}

/// Run the command, writing the report to `out`; `coloured` colours its marks and headings.
///
/// # Errors
/// [`Failure::Root`] when run as root; [`Failure::BrokenInclude`] or [`Failure::Unsatisfied`] after the report.
pub fn run<W: Write>(out: &mut W, coloured: bool) -> Result<(), Failure> {
    let env = env();
    if env.euid == 0 {
        return Err(Failure::Root);
    }
    let files = observe(&env);
    // The service is asked while fprintd is: each wait is bounded by itself.
    let service = std::thread::spawn(ask_service);
    let (reader, fingers) = ask();
    let service = service
        .join()
        .unwrap_or_else(|_| Service::Unreachable("the question did not finish".to_owned()));
    let report = decide(&Facts {
        files,
        reader,
        fingers,
        firefox: observe_firefox(&env.root),
        journal: observe_journal(&env.root),
        service,
    });
    let _ = out.write_all(report.text(coloured).as_bytes());
    match (report.exit_status(), report.broken_include) {
        (0, _) => Ok(()),
        (_, true) => Err(Failure::BrokenInclude),
        (_, false) => Err(Failure::Unsatisfied(report.failing())),
    }
}
