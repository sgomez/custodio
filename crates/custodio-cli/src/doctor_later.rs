//! Checks 4 to 6 of `custodio doctor` (F203): the module in the browsers, the persistent journal and the state directory's
//! storage, from observed values only. Split from [`crate::doctor_decide`], which owns the report and the exit status.

use crate::cert_text::escape;
use crate::doctor_decide::{BROWSERS_SECTION, Check, SYSTEM_SECTION, State, check};
use crate::journald_conf::{Cause, Source, Verdict};
use crate::storage::StateStorage;

pub const FIREFOX: &str = "profiles";
pub const JOURNAL: &str = "journal";
pub const STORAGE: &str = "key storage";

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

fn later(
    section: &'static str,
    state: State,
    name: &'static str,
    text: impl Into<String>,
    fix: Option<&str>,
) -> Check {
    Check {
        section,
        later: true,
        ..check(state, name, text, fix)
    }
}

const AGAIN: &str = "fix what is named, then run 'custodio doctor' again";

/// The state of one profile, what it says and what to do.
fn profile_state(p: &ProfileFact) -> (State, String, Option<&'static str>) {
    let register = Some("custodio register, then restart the browsers");
    match (&p.copy, &p.entry) {
        (Some(Copy::CouldNot(why)), _) => (
            State::CouldNotCheck,
            format!("cannot read the snap's copy of the module: {}", escape(why)),
            Some(AGAIN),
        ),
        (Some(Copy::Missing), _) => (
            State::NotOk,
            "the snap's copy of the module is missing".to_owned(),
            register,
        ),
        (Some(Copy::Stale), _) => (
            State::NotOk,
            "the snap's copy of the module is old".to_owned(),
            register,
        ),
        (_, Entry::CouldNot(why)) => (State::CouldNotCheck, escape(why), Some(AGAIN)),
        (_, Entry::Present(_) | Entry::PresentElsewhere(_)) => (State::Ok, String::new(), None),
        (_, Entry::P11Kit) => (State::Ok, "through p11-kit".to_owned(), None),
        (_, Entry::Stale) => (
            State::NotOk,
            "registered at a path that is gone".to_owned(),
            register,
        ),
        (_, Entry::Missing) => (State::NotOk, "not registered".to_owned(), register),
    }
}

/// Check 4: one line per profile; the fix once, under the last profile that needs it.
#[must_use]
pub fn firefox(f: &Firefox) -> Vec<Check> {
    let list = match f {
        Firefox::NoProfile => {
            return vec![later(
                BROWSERS_SECTION,
                State::Ok,
                FIREFOX,
                "none found, nothing to register",
                None,
            )];
        }
        Firefox::CouldNot(why) => {
            return vec![later(
                BROWSERS_SECTION,
                State::CouldNotCheck,
                FIREFOX,
                format!("cannot look for them: {}", escape(why)),
                Some("fix or remove that file, then run 'custodio doctor' again"),
            )];
        }
        Firefox::Profiles(list) => list,
    };
    let mut checks: Vec<Check> = Vec::new();
    let mut fixes: Vec<(usize, &str)> = Vec::new();
    for p in list {
        let (state, what, fix) = profile_state(p);
        let name = escape(p.path.rsplit('/').next().unwrap_or(&p.path));
        let text = if what.is_empty() {
            name
        } else {
            format!("{name}: {what}")
        };
        if let Some(fix) = fix {
            fixes.retain(|(_, f)| *f != fix);
            fixes.push((checks.len(), fix));
        }
        checks.push(later(BROWSERS_SECTION, state, p.browser, text, None));
    }
    for (at, fix) in fixes {
        checks[at].fix = Some(fix.to_owned());
    }
    checks
}

const RESTART: &str = "sudo systemctl restart systemd-journald";

#[must_use]
pub fn journal(f: &Verdict) -> Check {
    let (state, text, fix) = match f {
        Verdict::Persistent(_) => (State::Ok, "persistent".to_owned(), None),
        Verdict::CouldNot(why) => (
            State::CouldNotCheck,
            format!("cannot tell whether it is persistent: {}", escape(why)),
            Some(AGAIN.to_owned()),
        ),
        Verdict::NotPersistent(Cause::AutoWithoutDirectory(source)) => (
            State::NotOk,
            format!(
                "lost at reboot (Storage=auto{} and no /var/log/journal)",
                source
                    .as_ref()
                    .map_or_else(String::new, |s| format!(" at {s}"))
            ),
            Some(format!("sudo mkdir -p /var/log/journal, then {RESTART}")),
        ),
        Verdict::NotPersistent(Cause::Volatile { source, by_default }) => (
            State::NotOk,
            format!(
                "lost at reboot (Storage=volatile{})",
                at(source, *by_default)
            ),
            Some(edit_fix(source, *by_default)),
        ),
        Verdict::NotPersistent(Cause::None { source, by_default }) => (
            State::NotOk,
            format!("not kept at all (Storage=none{})", at(source, *by_default)),
            Some(edit_fix(source, *by_default)),
        ),
    };
    later(SYSTEM_SECTION, state, JOURNAL, text, fix.as_deref())
}

fn at(source: &Source, by_default: bool) -> String {
    if by_default {
        format!(" by default, see {source}")
    } else {
        format!(" at {source}")
    }
}

fn edit_fix(source: &Source, by_default: bool) -> String {
    if by_default {
        format!(
            "put Storage=persistent under [Journal] in /etc/systemd/journald.conf.d/50-persistent.conf, then {RESTART}"
        )
    } else if source.file.starts_with("/usr/") {
        format!(
            "copy {} to /etc/systemd/ and set Storage=persistent in the copy, then {RESTART}",
            source.file
        )
    } else {
        format!("set Storage=persistent at {source}, then {RESTART}")
    }
}

const LUKS: &str = "disk encryption (LUKS), usually chosen when installing the system";

/// What an `unknown` reason means and what to do, in a few words.
fn reason_fix(reason: &str) -> Option<(&'static str, &'static str)> {
    Some(match reason {
        "no-mount" => (
            "no mount covers it",
            "check that the service runs with its unit and can read /proc",
        ),
        "not-block-filesystem" => (
            "not on a single disk (tmpfs, overlay, btrfs or network)",
            "move it to ext4, xfs or similar, or use disk encryption (LUKS)",
        ),
        "sysfs-incomplete" => (
            "its device is not fully in /sys",
            "restart the service and run 'custodio doctor' again",
        ),
        "layer-not-classified" => (
            "a storage layer the service does not know",
            "use plain LUKS, or a disk without stacked devices",
        ),
        "members-disagree" => (
            "some LVM or RAID members are not encrypted",
            "encrypt every member",
        ),
        "fscrypt-not-excluded" => ("it may use fscrypt", "use LUKS under the filesystem"),
        "state-dir-unresolved" => (
            "the directory is not there",
            "check that the service started",
        ),
        _ => return None,
    })
}

#[must_use]
pub fn storage(f: &Service) -> Check {
    const DIR: &str = "/var/lib/custodio";
    match f {
        Service::Unreachable(why) => later(
            SYSTEM_SECTION,
            State::CouldNotCheck,
            STORAGE,
            format!("cannot ask the Custodio service: {}", escape(why)),
            Some("systemctl status custodio.service"),
        ),
        Service::Answered(StateStorage::Encrypted, _) => later(
            SYSTEM_SECTION,
            State::Ok,
            STORAGE,
            format!("{DIR} is on an encrypted disk"),
            None,
        ),
        Service::Answered(StateStorage::NotEncrypted, _) => Check {
            note: Some("Whoever takes this machine can use your keys.".to_owned()),
            ..later(
                SYSTEM_SECTION,
                State::Warn,
                STORAGE,
                format!("{DIR} is not on an encrypted disk"),
                Some(LUKS),
            )
        },
        Service::Answered(StateStorage::Unknown, reason) => {
            let reason = reason.as_deref().unwrap_or("");
            // Only a reason it knows is printed: anything else came from outside and means nothing here.
            let (text, fix) = reason_fix(reason).map_or_else(
                || {
                    (
                        "the service gave no reason".to_owned(),
                        "update the service, or use disk encryption (LUKS)",
                    )
                },
                |(what, fix)| (format!("{what} ({reason})"), fix),
            );
            later(
                SYSTEM_SECTION,
                State::Warn,
                STORAGE,
                format!("{DIR}: cannot tell if encrypted, {text}"),
                Some(fix),
            )
        }
    }
}
