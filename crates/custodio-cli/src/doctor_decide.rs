//! What `custodio doctor` says, from observed values only: the state of each check, its text and its
//! fix, the warning of the combination F201 found, the text of the report and the exit status.
//!
//! Nothing here reads a file, asks the bus or prints: [`crate::doctor_cmd`] gathers a [`Facts`].
//! Checks 4 to 6 (F203) join [`Report`] and [`exit_status`] without changing this rule.

use std::fmt::Write as _;

use crate::cert_text::escape;
use crate::doctor_later::{firefox, journal, storage};
use crate::fingerprint_decide::{
    FileState, GlobalVia, Observed, POLKIT_FILE, VENDOR_FILE, VendorState, first_fprintd_auth_line,
    global_via, is_custodios, packages, pam_has_fprintd,
};
use crate::journald_conf::Verdict;

/// The state of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Ok,
    NotOk,
    CouldNotCheck,
}

impl State {
    /// The word the line starts with.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotOk => "not ok",
            Self::CouldNotCheck => "could not check",
        }
    }
}

/// What `fprintd` said to `GetDevices`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reader {
    /// It listed this many devices.
    Devices(usize),
    /// The bus says nothing owns the name `net.reactivated.Fprint` (and nothing started it).
    NoOwner,
    /// No answer in time, an error, or a bus that cannot be reached: the reason.
    Failed(String),
}

/// What `fprintd` said to `ListEnrolledFingers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fingers {
    Listed(usize),
    /// `net.reactivated.Fprint.Error.NoEnrolledPrints`.
    NoPrints,
    /// `PermissionDenied`: fprintd would have asked polkit, and nothing was allowed to ask (an ssh session).
    Refused(String),
    /// Any other error, or no answer in time.
    Failed(String),
    /// Nothing was asked: there was no reader to ask.
    NotAsked,
}

/// Everything the report depends on.
#[derive(Debug, Clone)]
pub struct Facts {
    /// The files, read as `custodio fingerprint` reads them (the same global detection).
    pub files: Observed,
    pub reader: Reader,
    pub fingers: Fingers,
    pub firefox: Firefox,
    pub journal: Verdict,
    pub service: Service,
}

/// A line under a check that does not change the exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub text: String,
    pub fix: String,
}

/// One check of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub state: State,
    pub name: &'static str,
    pub text: String,
    /// What to do, for a check that is not `ok`.
    pub fix: Option<String>,
    pub warning: Option<Warning>,
    /// Checks 4 to 6 (F203): the ones the exit status counts.
    pub later: bool,
}

/// The checks in the order they are printed, and whether a polkit include is broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub checks: Vec<Check>,
    pub broken_include: bool,
}

pub const READER: &str = "fingerprint reader";
pub const FINGER: &str = "enrolled finger";
pub const POLKIT: &str = "fingerprint for polkit";

/// The exit status: 0, unless a polkit include is broken or one of the `later` checks (Firefox, journal, storage) is not `ok`.
/// Checks 1 to 3 never count, "could not check" among them: they are the fingerprint's, which is optional; a broken include stops every polkit dialog.
#[must_use]
pub fn exit_status(broken_include: bool, later: &[State]) -> u8 {
    u8::from(broken_include || later.iter().any(|s| *s != State::Ok))
}

impl Report {
    /// [`exit_status`] of this report.
    #[must_use]
    pub fn exit_status(&self) -> u8 {
        let later: Vec<State> = self
            .checks
            .iter()
            .filter(|c| c.later)
            .map(|c| c.state)
            .collect();
        exit_status(self.broken_include, &later)
    }

    /// The names of the checks that make the exit status 1 and are not `ok`, each once, in report order.
    #[must_use]
    pub fn failing(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = Vec::new();
        for c in self
            .checks
            .iter()
            .filter(|c| c.later && c.state != State::Ok)
        {
            if !names.contains(&c.name) {
                names.push(c.name);
            }
        }
        names
    }

    /// One line per check, then its warning and its fix, indented.
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = String::new();
        for c in &self.checks {
            let _ = writeln!(text, "{:<15} {}: {}", c.state.word(), c.name, c.text);
            if let Some(w) = &c.warning {
                let _ = writeln!(
                    text,
                    "{:16}warning: {}\n{:16}fix: {}",
                    "", w.text, "", w.fix
                );
            }
            if let Some(fix) = &c.fix {
                let _ = writeln!(text, "{:16}fix: {fix}", "");
            }
        }
        text
    }
}

pub(crate) fn check(
    state: State,
    name: &'static str,
    text: impl Into<String>,
    fix: Option<String>,
) -> Check {
    Check {
        state,
        name,
        text: text.into(),
        fix,
        warning: None,
        later: false,
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

fn reader(f: &Facts) -> Check {
    let (state, text, fix) = match &f.reader {
        Reader::Devices(0) => (
            State::NotOk,
            "fprintd reports no fingerprint reader".to_owned(),
            Some("Plug the reader in or enable it in the firmware setup, and check that libfprint supports it (https://fprint.freedesktop.org/supported-devices.html).".to_owned()),
        ),
        Reader::Devices(n) => (
            State::Ok,
            format!("fprintd lists {}", plural(*n, "reader", "readers")),
            None,
        ),
        // Not installed: no service file and the bus says the name has no owner. Any other sign (a
        // name that is there and does not answer, an error, a service file with no owner) is "could not check".
        Reader::NoOwner if !f.files.fprintd_present => (
            State::NotOk,
            "fprintd is not installed".to_owned(),
            Some(format!("Install {}.", packages(f.files.family))),
        ),
        Reader::NoOwner => (
            State::CouldNotCheck,
            "fprintd is installed but nothing on the bus answers for it".to_owned(),
            Some("Look at 'systemctl status fprintd', then run 'custodio doctor' again.".to_owned()),
        ),
        Reader::Failed(why) => (
            State::CouldNotCheck,
            format!("could not ask fprintd: {}", escape(why)),
            Some("Check that the system bus and fprintd run (systemctl status dbus fprintd), then run 'custodio doctor' again.".to_owned()),
        ),
    };
    check(state, READER, text, fix)
}

fn finger(f: &Facts) -> Check {
    if !matches!(f.reader, Reader::Devices(n) if n > 0) {
        return check(
            State::CouldNotCheck,
            FINGER,
            "there is no reader to ask (see the line above)",
            Some("Fix the reader first, then run 'custodio doctor' again.".to_owned()),
        );
    }
    let again = "Run 'custodio doctor' again from the desktop session of the person who will use the finger.";
    let (state, text, fix) = match &f.fingers {
        Fingers::Listed(n) if *n > 0 => (
            State::Ok,
            format!("{} enrolled for you", plural(*n, "finger", "fingers")),
            None,
        ),
        Fingers::Listed(_) | Fingers::NoPrints => (
            State::NotOk,
            "no finger is enrolled for you".to_owned(),
            Some("Enrol one in the desktop's settings (GNOME: Settings, Users, Fingerprint Login) or run 'fprintd-enroll'.".to_owned()),
        ),
        Fingers::Refused(why) => (
            State::CouldNotCheck,
            format!("fprintd refused to answer ({}): this is what an ssh session gets", escape(why)),
            Some(again.to_owned()),
        ),
        Fingers::Failed(why) => (
            State::CouldNotCheck,
            format!("could not ask fprintd: {}", escape(why)),
            Some(again.to_owned()),
        ),
        Fingers::NotAsked => (
            State::CouldNotCheck,
            "fprintd was not asked".to_owned(),
            Some(again.to_owned()),
        ),
    };
    check(state, FINGER, text, fix)
}

fn via_text(via: GlobalVia) -> &'static str {
    match via {
        GlobalVia::CommonAuth => "/etc/pam.d/common-auth",
        GlobalVia::Authselect => "authselect (with-fingerprint)",
        GlobalVia::SystemAuth => "/etc/pam.d/system-auth",
        GlobalVia::Sudo => "/etc/pam.d/sudo",
    }
}

/// Whether the file is not Custodio's and has an `auth` line with `pam_fprintd.so`.
fn foreign_with_fingerprint(file: &FileState) -> bool {
    matches!(file, FileState::Regular(b)
        if !is_custodios(b) && first_fprintd_auth_line(&String::from_utf8_lossy(b)).is_some())
}

fn polkit(f: &Facts) -> (Check, bool) {
    let o = &f.files;
    let custodios = matches!(&o.polkit_file, FileState::Regular(b) if is_custodios(b));
    let foreign = foreign_with_fingerprint(&o.polkit_file);
    let mut broken = false;
    let mut c = if custodios && o.vendor != VendorState::Regular {
        broken = true;
        let what = if o.vendor == VendorState::Missing {
            "missing"
        } else {
            "not a regular file"
        };
        check(
            State::NotOk,
            POLKIT,
            format!("Custodio's override {POLKIT_FILE} includes {VENDOR_FILE}, which is {what}: no polkit dialog can authenticate"),
            Some("Reinstall polkit (it ships that file), or remove the override: sudo custodio fingerprint disable".to_owned()),
        )
    } else if custodios {
        check(
            State::Ok,
            POLKIT,
            format!("active through Custodio's override {POLKIT_FILE}"),
            None,
        )
    } else if foreign {
        check(
            State::Ok,
            POLKIT,
            format!(
                "active through {POLKIT_FILE}, which is not Custodio's (it has an auth line with pam_fprintd.so)"
            ),
            None,
        )
    } else if let Some(via) = global_via(o) {
        check(
            State::Ok,
            POLKIT,
            format!(
                "active for the whole system, through {}: sudo uses the finger too",
                via_text(via)
            ),
            None,
        )
    } else if o.polkit_file != FileState::Missing {
        // `enable` refuses a file that is not Custodio's, so it cannot be the fix here.
        check(
            State::NotOk,
            POLKIT,
            format!("fingerprint is not active for polkit, and {POLKIT_FILE} is not Custodio's"),
            Some(format!(
                "Look at who owns {POLKIT_FILE} ('dpkg -S', 'rpm -qf' or 'pacman -Qo'), and remove or merge it yourself before running 'sudo custodio fingerprint enable'."
            )),
        )
    } else {
        check(
            State::NotOk,
            POLKIT,
            "fingerprint is not active for polkit",
            Some("Run: sudo custodio fingerprint enable".to_owned()),
        )
    };
    // F201: an override with its own fingerprint line and `pam_fprintd` in common-auth ask for the finger twice.
    if (custodios || foreign) && o.common_auth.as_deref().is_some_and(pam_has_fprintd) {
        let fix = if custodios {
            "sudo custodio fingerprint disable"
        } else {
            "remove the pam_fprintd.so line of /etc/pam.d/polkit-1, or run 'sudo pam-auth-update --disable fprintd'"
        };
        c.warning = Some(Warning {
            text: "both the polkit file and common-auth ask for the finger: after a wrong finger or no touch it is asked twice (20 s)".to_owned(),
            fix: fix.to_owned(),
        });
    }
    (c, broken)
}

/// The report for the observed state. A broken include comes first: it is the most urgent problem.
#[must_use]
pub fn decide(f: &Facts) -> Report {
    let (polkit, broken_include) = polkit(f);
    let mut checks = vec![reader(f), finger(f)];
    if broken_include {
        checks.insert(0, polkit);
    } else {
        checks.push(polkit);
    }
    checks.extend(firefox(&f.firefox));
    checks.push(journal(&f.journal));
    checks.push(storage(&f.service));
    Report {
        checks,
        broken_include,
    }
}

pub use crate::doctor_later::{
    Copy, Entry, FIREFOX, Firefox, JOURNAL, ProfileFact, STORAGE, Service,
};

#[cfg(test)]
mod tests;
