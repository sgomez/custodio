//! Checks 4 to 6 of `custodio doctor` (F203): the module in Firefox, the persistent journal and the state directory's
//! storage, from observed values only. Split from [`crate::doctor_decide`], which owns the report and the exit status.

use crate::cert_text::escape;
use crate::delete::RESTART_NOTE;
use crate::doctor_decide::{Check, State, check};
use crate::journald_conf::{Cause, Source, Verdict};
use crate::storage::{README_ANCHOR, StateStorage};

pub const FIREFOX: &str = "module in Firefox";
pub const JOURNAL: &str = "persistent journal";
pub const STORAGE: &str = "state directory storage";

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

fn later(state: State, name: &'static str, text: impl Into<String>, fix: Option<String>) -> Check {
    Check {
        later: true,
        ..check(state, name, text, fix)
    }
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

#[must_use]
pub fn firefox(f: &Firefox) -> Vec<Check> {
    match f {
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

#[must_use]
pub fn journal(f: &Verdict) -> Check {
    let (state, text, fix) = match f {
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

fn set_by(source: &Source, by_default: bool) -> String {
    if by_default {
        format!(" (the default, shown by {source})")
    } else {
        format!(" (set at {source})")
    }
}

fn edit_fix(source: &Source, by_default: bool) -> String {
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

const FDE: &str = "full-disk encryption (README.md#";

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

#[must_use]
pub fn storage(f: &Service) -> Check {
    let (state, text, fix) = match f {
        Service::Unreachable(why) => (
            State::CouldNotCheck,
            format!("could not ask the Custodio service: {}", escape(why)),
            Some("Check that the package is installed and the service runs: systemctl status custodio.service (the package is custodio), then run 'custodio doctor' again.".to_owned()),
        ),
        Service::Answered(StateStorage::Encrypted, _) => (
            State::Ok,
            "the service's state directory is on an encrypted device".to_owned(),
            None,
        ),
        Service::Answered(StateStorage::NotEncrypted, _) => (
            State::NotOk,
            "the service's state directory is not on an encrypted device".to_owned(),
            Some(format!("Use {FDE}{README_ANCHOR}): without it whoever takes this machine can use your keys, though they cannot copy a tpm key.")),
        ),
        Service::Answered(StateStorage::Unknown, reason) => {
            let reason = reason.as_deref().unwrap_or("");
            match reason_fix(reason) {
                Some((what, todo)) => (
                    State::NotOk,
                    format!("the service's state directory is not known to be on an encrypted device (reason {reason}: {what})"),
                    Some(format!("{todo} Or use {FDE}{README_ANCHOR}).")),
                ),
                None => (
                    State::NotOk,
                    "the service's state directory is not known to be on an encrypted device (the service gave no reason it knows)".to_owned(),
                    Some(format!("Update the service if it is old, or use {FDE}{README_ANCHOR}).")),
                ),
            }
        }
    };
    later(state, STORAGE, text, fix)
}
