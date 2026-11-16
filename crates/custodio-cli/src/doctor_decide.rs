//! What `custodio doctor` says, from observed values only: the state of each check, its text and its
//! fix, the warning of the combination F201 found, the text of the report and the exit status.
//!
//! Nothing here reads a file, asks the bus or prints: [`crate::doctor_cmd`] gathers a [`Facts`].
//! Checks 4 to 6 (F203) join [`Report`] and [`exit_status`] without changing this rule.

use std::fmt::Write as _;

use crate::cert_text::escape;
use crate::delete::RESTART_NOTE;
use crate::fingerprint_decide::{
    FileState, GlobalVia, Observed, POLKIT_FILE, VENDOR_FILE, VendorState, first_fprintd_auth_line,
    global_via, is_custodios, packages, pam_has_fprintd,
};
use crate::journald_conf::{Cause, Verdict};
use crate::storage::{README_ANCHOR, StateStorage};

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

/// What the entries of one profile's `pkcs11.txt` say about the module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// An entry has the module's path, under this name.
    Present(String),
    /// A Custodio module at another path that still exists.
    PresentElsewhere(String),
    /// No Custodio entry.
    Missing,
    /// Custodio entries whose file is gone.
    Stale,
    /// The system NSS loads the p11-kit proxy, which already shows the module.
    P11Kit,
    /// `pkcs11.txt` cannot be read: the reason.
    CouldNot(String),
}

/// The Firefox snap's copy of the module, against the installed module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Copy {
    Missing,
    UpToDate,
    /// Its bytes differ from the module's.
    Stale,
    CouldNot(String),
}

/// One profile of check 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileFact {
    pub browser: &'static str,
    pub path: String,
    /// The snap's copy, for a profile of the Firefox snap.
    pub copy: Option<Copy>,
    pub entry: Entry,
}

/// What check 4 observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Firefox {
    NoProfile,
    Profiles(Vec<ProfileFact>),
    /// Discovery failed: the file and why.
    CouldNot(String),
}

/// What the service said about its state directory (check 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Service {
    /// `StateStorage`, and `StateStorageReason` when it was `unknown` (`None`: not asked, or no such method).
    Answered(StateStorage, Option<String>),
    /// No bus, no owner, no answer in time or an error: the reason.
    Unreachable(String),
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
pub const FIREFOX: &str = "module in Firefox";
pub const JOURNAL: &str = "persistent journal";
pub const STORAGE: &str = "state directory storage";

/// The exit status: 0, unless a polkit include is broken or one of the checks 4 to 6 (`later`) is not `ok`. Checks 1 to 3 never count, "could not check"
/// among them: they are the fingerprint's, which is optional; a broken include stops every polkit dialog.
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

fn check(state: State, name: &'static str, text: impl Into<String>, fix: Option<String>) -> Check {
    Check {
        state,
        name,
        text: text.into(),
        fix,
        warning: None,
        later: false,
    }
}

fn later(state: State, name: &'static str, text: impl Into<String>, fix: Option<String>) -> Check {
    Check {
        later: true,
        ..check(state, name, text, fix)
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

const REGISTER: &str = "Run: custodio register";

fn profile_line(p: &ProfileFact) -> Check {
    let who = format!("{} profile {}", p.browser, escape(&p.path));
    let register = |text: String, fix: &str| {
        later(
            State::NotOk,
            FIREFOX,
            format!("{who}: {text}"),
            Some(fix.to_owned()),
        )
    };
    let snap_fix = format!("{REGISTER}; then restart Firefox. {RESTART_NOTE}");
    let fix = if p.copy.is_some() {
        snap_fix.as_str()
    } else {
        REGISTER
    };
    match &p.copy {
        Some(Copy::CouldNot(why)) => {
            return later(
                State::CouldNotCheck,
                FIREFOX,
                format!(
                    "{who}: cannot compare the snap's copy of the module: {}",
                    escape(why)
                ),
                Some("Fix what is named, then run 'custodio doctor' again.".to_owned()),
            );
        }
        Some(Copy::Missing) => {
            return register("the snap's copy of the module is missing".to_owned(), fix);
        }
        Some(Copy::Stale) => {
            return register(
                "the snap's copy of the module is stale (it differs from the installed module)"
                    .to_owned(),
                fix,
            );
        }
        Some(Copy::UpToDate) | None => {}
    }
    match &p.entry {
        Entry::CouldNot(why) => later(
            State::CouldNotCheck,
            FIREFOX,
            format!("{who}: {}", escape(why)),
            Some("Fix what is named, then run 'custodio doctor' again.".to_owned()),
        ),
        Entry::Present(name) => later(
            State::Ok,
            FIREFOX,
            format!("{who}: the module is registered as \"{}\"", escape(name)),
            None,
        ),
        Entry::PresentElsewhere(name) => later(
            State::Ok,
            FIREFOX,
            format!(
                "{who}: the module is registered as \"{}\", from another path that still exists",
                escape(name)
            ),
            None,
        ),
        Entry::P11Kit => later(
            State::Ok,
            FIREFOX,
            format!(
                "{who}: the system NSS loads the p11-kit proxy, so Firefox sees the module without registration"
            ),
            None,
        ),
        Entry::Stale => register(
            "the module is registered at a path that no longer exists (stale)".to_owned(),
            fix,
        ),
        Entry::Missing => register("the module is not registered".to_owned(), fix),
    }
}

fn firefox(f: &Facts) -> Vec<Check> {
    match &f.firefox {
        Firefox::NoProfile => vec![later(
            State::Ok,
            FIREFOX,
            "no browser profile was found, so there is nothing to register",
            None,
        )],
        Firefox::CouldNot(why) => vec![later(
            State::CouldNotCheck,
            FIREFOX,
            format!("could not look for browser profiles: {}", escape(why)),
            Some("Fix or remove that file, then run 'custodio doctor' again.".to_owned()),
        )],
        Firefox::Profiles(list) => list.iter().map(profile_line).collect(),
    }
}

const DROP_IN: &str = "or create /etc/systemd/journald.conf.d/50-persistent.conf with the lines [Journal] and Storage=persistent, then restart systemd-journald";

fn journal(f: &Facts) -> Check {
    let (state, text, fix) = match &f.journal {
        Verdict::Persistent(why) => (State::Ok, format!("the journal is persistent ({why})"), None),
        Verdict::CouldNot(why) => (
            State::CouldNotCheck,
            format!("could not tell whether the journal is persistent: {}", escape(why)),
            Some("Fix what is named, or look at 'journalctl --header' and 'systemd-analyze cat-config systemd/journald.conf', then run 'custodio doctor' again.".to_owned()),
        ),
        Verdict::NotPersistent(Cause::AutoWithoutDirectory(source)) => {
            let at = source
                .as_ref()
                .map_or_else(String::new, |s| format!(" (set at {s})"));
            (
                State::NotOk,
                format!("Storage=auto{at} and /var/log/journal does not exist: the journal is kept in memory and is lost at reboot"),
                Some(format!("As root: mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal, then journalctl --flush or reboot; {DROP_IN}")),
            )
        }
        Verdict::NotPersistent(Cause::Volatile { source, by_default }) => (
            State::NotOk,
            format!("Storage=volatile{}: the journal is kept in memory and is lost at reboot", set_by(source, *by_default)),
            Some(edit_fix(source, *by_default)),
        ),
        Verdict::NotPersistent(Cause::None { source, by_default }) => (
            State::NotOk,
            format!("Storage=none{}: nothing is stored, every journal entry is lost now, the audit entries of the signatures included", set_by(source, *by_default)),
            Some(edit_fix(source, *by_default)),
        ),
    };
    later(state, JOURNAL, text, fix)
}

fn set_by(source: &crate::journald_conf::Source, by_default: bool) -> String {
    if by_default {
        format!(" (the default, shown by {source})")
    } else {
        format!(" (set at {source})")
    }
}

fn edit_fix(source: &crate::journald_conf::Source, by_default: bool) -> String {
    if by_default {
        format!("As root: {DROP_IN}.")
    } else if source.file.starts_with("/usr/") {
        format!(
            "As root: remove or change that line; {} is shipped by the system, so put a copy with the same name in /etc/systemd/ and edit the copy; then restart systemd-journald.",
            source.file
        )
    } else {
        format!("As root: remove or change the line at {source}, then restart systemd-journald.")
    }
}

const FDE: &str = "Use full-disk encryption (README.md#";

fn reason_fix(reason: &str) -> Option<(&'static str, &'static str)> {
    Some(match reason {
        "no-mount" => (
            "no mount covers the state directory, or the mount table cannot be read",
            "Check that the service runs with its unit and that /proc is available to it.",
        ),
        "not-block-filesystem" => (
            "the state directory is on a filesystem that is not on one block device (tmpfs, overlay, a network filesystem, btrfs or an anonymous device)",
            "Keep the state directory on a local ext4, xfs or similar filesystem.",
        ),
        "sysfs-incomplete" => (
            "the device tree under /sys/dev/block is missing or unreadable for this device",
            "Restart the service and run 'custodio doctor' again; a device that is still being set up shows this.",
        ),
        "layer-not-classified" => (
            "a layer the service does not classify is in the chain (RAID that is not all encrypted, a device-mapper device that is neither LVM nor dm-crypt, a disk with no hardware link)",
            "Put the state directory on a plain dm-crypt (LUKS) device, or on a disk without stacked devices.",
        ),
        "members-disagree" => (
            "the members of an LVM or RAID layer are not all alike (some encrypted, some not)",
            "Encrypt every member, or move the state directory to an encrypted device.",
        ),
        "fscrypt-not-excluded" => (
            "the filesystem may encrypt the directory itself (fscrypt), or the check could not be made",
            "Use dm-crypt (LUKS) under the filesystem; the service cannot tell what fscrypt covers.",
        ),
        "state-dir-unresolved" => (
            "the state directory itself cannot be resolved (the directory is not there)",
            "Check that the service's state directory exists and that its unit started.",
        ),
        _ => return None,
    })
}

fn storage(f: &Facts) -> Check {
    let (state, text, fix) = match &f.service {
        Service::Unreachable(why) => (
            State::CouldNotCheck,
            format!("could not ask the Custodio service: {}", escape(why)),
            Some("Check that the package is installed and the service runs: systemctl status custodiod (and its socket), then run 'custodio doctor' again.".to_owned()),
        ),
        Service::Answered(StateStorage::Encrypted, _) => (
            State::Ok,
            "the service's state directory is on an encrypted device".to_owned(),
            None,
        ),
        Service::Answered(StateStorage::NotEncrypted, _) => (
            State::NotOk,
            "the service's state directory is not on an encrypted device".to_owned(),
            Some(format!("{FDE}{README_ANCHOR}): without it whoever takes this machine can use your keys, though they cannot copy a tpm key.")),
        ),
        Service::Answered(StateStorage::Unknown, reason) => {
            let reason = reason.as_deref().unwrap_or("");
            match reason_fix(reason) {
                Some((what, todo)) => (
                    State::NotOk,
                    format!("the service's state directory is not known to be on an encrypted device (reason {reason}: {what})"),
                    Some(format!("{todo} Or {}{README_ANCHOR}).", FDE.to_lowercase())),
                ),
                None => (
                    State::NotOk,
                    "the service's state directory is not known to be on an encrypted device (the service gave no reason it knows)".to_owned(),
                    Some(format!("Update the service if it is old, and see {FDE}{README_ANCHOR}).")),
                ),
            }
        }
    };
    later(state, STORAGE, text, fix)
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
    checks.extend(firefox(f));
    checks.push(journal(f));
    checks.push(storage(f));
    Report {
        checks,
        broken_include,
    }
}

#[cfg(test)]
mod tests;
