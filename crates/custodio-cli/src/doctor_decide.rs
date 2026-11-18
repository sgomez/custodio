//! What `custodio doctor` says, from observed values only: the state of each check, its text and its
//! fix, the warning of the combination F201 found, the text of the report and the exit status.
//!
//! Nothing here reads a file, asks the bus or prints: [`crate::doctor_cmd`] gathers a [`Facts`].
//! Checks 4 to 6 (F203) join [`Report`] and [`exit_status`] without changing this rule.

use std::fmt::Write as _;

use crate::cert_text::escape;
use crate::colour::{self, Paint};
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
    /// Works, with a risk the person should know: it counts like `NotOk` for the exit status.
    Warn,
    CouldNotCheck,
}

impl State {
    /// The word the line starts with.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotOk => "FAIL",
            Self::Warn => "warn",
            Self::CouldNotCheck => "?",
        }
    }

    /// [`Self::word`], coloured when `on`, padded to the width of the longest.
    fn painted(self, on: bool) -> String {
        let paint = match self {
            Self::Ok => Paint::Green,
            Self::NotOk => Paint::Red,
            Self::Warn | Self::CouldNotCheck => Paint::Yellow,
        };
        let pad = " ".repeat(4 - self.word().len());
        format!("{}{pad}", colour::paint(self.word(), paint, on))
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

/// The headings of the report.
pub const FINGERPRINT_SECTION: &str = "Fingerprint (optional)";
pub const BROWSERS_SECTION: &str = "Browsers";
pub const SYSTEM_SECTION: &str = "System";

/// One check of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub state: State,
    pub section: &'static str,
    pub name: &'static str,
    pub text: String,
    /// What it means, for a check whose text does not say it.
    pub note: Option<String>,
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

pub const READER: &str = "reader";
pub const FINGER: &str = "finger";
pub const POLKIT: &str = "polkit";

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

    /// One line per check under its section's heading; under it, indented, its note, warning and
    /// fix; last, how many problems there are. `on` colours the words and the headings.
    #[must_use]
    pub fn text(&self, on: bool) -> String {
        let width = self.checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
        let indent = " ".repeat(width + 10);
        let mut text = String::new();
        let mut section = None;
        for c in &self.checks {
            if section != Some(c.section) {
                let _ = writeln!(text, "{}", colour::bold(c.section, on));
                section = Some(c.section);
            }
            let _ = writeln!(
                text,
                "  {}  {:<width$}  {}",
                c.state.painted(on),
                c.name,
                c.text
            );
            if let Some(note) = &c.note {
                let _ = writeln!(text, "{indent}{note}");
            }
            if let Some(w) = &c.warning {
                let _ = writeln!(text, "{indent}Warning: {}\n{indent}Fix: {}", w.text, w.fix);
            }
            if let Some(fix) = &c.fix {
                let _ = writeln!(text, "{indent}Fix: {fix}");
            }
        }
        let problems = self
            .checks
            .iter()
            .filter(|c| c.state != State::Ok || c.warning.is_some())
            .count();
        if problems > 0 {
            let _ = writeln!(text, "\n{}.", plural(problems, "problem", "problems"));
        }
        text
    }
}

pub(crate) fn check(
    state: State,
    name: &'static str,
    text: impl Into<String>,
    fix: Option<&str>,
) -> Check {
    Check {
        state,
        section: FINGERPRINT_SECTION,
        name,
        text: text.into(),
        note: None,
        fix: fix.map(str::to_owned),
        warning: None,
        later: false,
    }
}

pub(crate) fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

fn reader(f: &Facts) -> Check {
    match &f.reader {
        Reader::Devices(0) => check(
            State::NotOk,
            READER,
            "none found",
            Some("plug it in or enable it in the firmware; libfprint must support it"),
        ),
        Reader::Devices(n) => check(State::Ok, READER, plural(*n, "reader", "readers"), None),
        // Not installed: no service file and the bus says the name has no owner. Any other sign (a
        // name that is there and does not answer, an error, a service file with no owner) is "could not check".
        Reader::NoOwner if !f.files.fprintd_present => check(
            State::NotOk,
            READER,
            "fprintd is not installed",
            Some(&format!("install {}", packages(f.files.family))),
        ),
        Reader::NoOwner => check(
            State::CouldNotCheck,
            READER,
            "fprintd does not answer",
            Some("systemctl status fprintd"),
        ),
        Reader::Failed(why) => check(
            State::CouldNotCheck,
            READER,
            format!("cannot ask fprintd: {}", escape(why)),
            Some("systemctl status dbus fprintd"),
        ),
    }
}

fn finger(f: &Facts) -> Check {
    if !matches!(f.reader, Reader::Devices(n) if n > 0) {
        return check(
            State::CouldNotCheck,
            FINGER,
            "no reader to ask",
            Some("fix the reader first"),
        );
    }
    let desktop = Some("run 'custodio doctor' in your desktop session");
    match &f.fingers {
        Fingers::Listed(n) if *n > 0 => check(
            State::Ok,
            FINGER,
            format!("{} enrolled", plural(*n, "finger", "fingers")),
            None,
        ),
        Fingers::Listed(_) | Fingers::NoPrints => check(
            State::NotOk,
            FINGER,
            "none enrolled",
            Some("Settings > Users > Fingerprint Login, or fprintd-enroll"),
        ),
        Fingers::Refused(why) => check(
            State::CouldNotCheck,
            FINGER,
            format!("fprintd refused ({}), as it does over ssh", escape(why)),
            desktop,
        ),
        Fingers::Failed(why) => check(
            State::CouldNotCheck,
            FINGER,
            format!("cannot ask fprintd: {}", escape(why)),
            desktop,
        ),
        Fingers::NotAsked => check(State::CouldNotCheck, FINGER, "not asked", desktop),
    }
}

fn via_text(via: GlobalVia) -> &'static str {
    match via {
        GlobalVia::CommonAuth => "/etc/pam.d/common-auth",
        GlobalVia::Authselect => "authselect with-fingerprint",
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
            format!("{POLKIT_FILE} includes {VENDOR_FILE}, which is {what}"),
            Some("reinstall polkit, or: sudo custodio fingerprint disable"),
        )
    } else if custodios {
        check(State::Ok, POLKIT, "on", None)
    } else if foreign {
        check(
            State::Ok,
            POLKIT,
            format!("on, through {POLKIT_FILE} (not Custodio's)"),
            None,
        )
    } else if let Some(via) = global_via(o) {
        check(
            State::Ok,
            POLKIT,
            format!("on for the whole system ({}), sudo too", via_text(via)),
            None,
        )
    } else if o.polkit_file != FileState::Missing {
        // `enable` refuses a file that is not Custodio's, so it cannot be the fix here.
        check(
            State::NotOk,
            POLKIT,
            format!("off, and {POLKIT_FILE} is not Custodio's"),
            Some(
                "remove or merge it ('dpkg -S', 'rpm -qf' or 'pacman -Qo' name its owner), then: sudo custodio fingerprint enable",
            ),
        )
    } else {
        check(
            State::NotOk,
            POLKIT,
            "off",
            Some("sudo custodio fingerprint enable"),
        )
    };
    if broken {
        c.note = Some("No polkit dialog works, not even with the password.".to_owned());
    }
    // F201: an override with its own fingerprint line and `pam_fprintd` in common-auth ask for the finger twice.
    if (custodios || foreign) && o.common_auth.as_deref().is_some_and(pam_has_fprintd) {
        let fix = if custodios {
            "sudo custodio fingerprint disable"
        } else {
            "remove pam_fprintd.so from /etc/pam.d/polkit-1, or: sudo pam-auth-update --disable fprintd"
        };
        c.warning = Some(Warning {
            text: "polkit-1 and common-auth both ask for the finger, so a failed touch waits twice (20 s)".to_owned(),
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
