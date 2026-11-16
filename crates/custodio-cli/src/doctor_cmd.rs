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

use std::fmt;
use std::io::Write;
use std::sync::mpsc;
use std::time::Duration;

use zbus::{Connection, OwnedObjectPath, block_on};

use crate::doctor_decide::{Facts, Fingers, Reader, decide};
use crate::fingerprint_cmd::{env, observe};

/// How long each question to `fprintd` is waited for.
pub const ASK_LIMIT: Duration = Duration::from_millis(1500);

const DESTINATION: &str = "net.reactivated.Fprint";
const SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
const NO_PRINTS: &str = "net.reactivated.Fprint.Error.NoEnrolledPrints";
const DENIED: &str = "net.reactivated.Fprint.Error.PermissionDenied";

/// Why the command did not succeed.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// Run as root: the answers are about the person, not about root.
    Root,
    /// A polkit include is broken; the report is on standard output.
    BrokenInclude,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => f.write_str("custodio doctor: refused to run as root"),
            Self::BrokenInclude => f.write_str("custodio doctor: a polkit include is broken"),
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
    match error {
        zbus::Error::FDO(e) => matches!(**e, zbus::fdo::Error::ServiceUnknown(_)),
        zbus::Error::MethodError(name, _, _) => name.as_str() == SERVICE_UNKNOWN,
        _ => false,
    }
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

/// Run the command, writing the report to `out`.
///
/// # Errors
/// [`Failure::Root`] when run as root; [`Failure::BrokenInclude`] after the report when a polkit include is broken.
pub fn run<W: Write>(out: &mut W) -> Result<(), Failure> {
    let env = env();
    if env.euid == 0 {
        return Err(Failure::Root);
    }
    let files = observe(&env);
    let (reader, fingers) = ask();
    let report = decide(&Facts {
        files,
        reader,
        fingers,
    });
    let _ = out.write_all(report.text().as_bytes());
    match report.exit_status() {
        0 => Ok(()),
        _ => Err(Failure::BrokenInclude),
    }
}
