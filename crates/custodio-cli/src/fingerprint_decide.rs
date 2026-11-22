//! What `custodio setup fingerprint enable` and `disable` decide, from observed values only.
//!
//! Nothing here reads a file, asks the bus or prints: the command gathers an [`Observed`] and
//! applies the decision, so every state is tested without a file system.

use crate::doctor_decide::{NO_READER, NO_READER_FIX, POLKIT, READER};
use crate::report::{Line, State};
use std::fmt;

/// The path of the override, as every reader sees it.
pub const POLKIT_FILE: &str = "/etc/pam.d/polkit-1";
/// The vendor file the override includes.
pub const VENDOR_FILE: &str = "/usr/lib/pam.d/polkit-1";

/// What `enable` writes. The comment lines say who wrote the file and how to undo it; none of
/// them names the module, so the first non-comment `auth` line that does is the one of Design 1.
const FILE: &str = "#%PAM-1.0\n\
# Written by 'custodio setup fingerprint enable'. Remove it with 'sudo custodio setup fingerprint disable'.\n\
# If you edit this file, Custodio treats it as yours and will not touch it again.\n\
auth     [success=done default=ignore] pam_fprintd.so max-tries=3 timeout=30\n\
auth     include /usr/lib/pam.d/polkit-1\n\
account  include /usr/lib/pam.d/polkit-1\n\
password include /usr/lib/pam.d/polkit-1\n\
session  include /usr/lib/pam.d/polkit-1\n";

/// The exact bytes of Custodio's file.
#[must_use]
pub const fn file_bytes() -> &'static [u8] {
    FILE.as_bytes()
}

/// The `pam_fprintd` arguments of the file 0.8.0 wrote, and the ones that replaced them.
const OLD_ARGS: &str = "max-tries=1 timeout=10";
const ARGS: &str = "max-tries=3 timeout=30";

/// Whether `bytes` are exactly the file 0.8.0 wrote: one try for the finger.
fn is_custodios_of_0_8(bytes: &[u8]) -> bool {
    bytes.len() == FILE.len() && *bytes == *FILE.replacen(ARGS, OLD_ARGS, 1).as_bytes()
}

/// Whether `bytes` are exactly Custodio's file, this one or the one 0.8.0 wrote.
#[must_use]
pub fn is_custodios(bytes: &[u8]) -> bool {
    bytes == file_bytes() || is_custodios_of_0_8(bytes)
}

/// The first non-comment `auth` line that has `pam_fprintd.so`, as a reader such as Omarchy's
/// polkit agent finds it.
#[must_use]
pub fn first_fprintd_auth_line(text: &str) -> Option<&str> {
    text.lines().find(|l| active_fprintd_auth(l, false))
}

fn active_fprintd_auth(line: &str, bare_name: bool) -> bool {
    // Linux-PAM: a `#` starts a comment that runs to the end of the line.
    let line = line.split('#').next().unwrap_or("").trim();
    let mut tokens = line.split_whitespace();
    let kind = tokens.next().unwrap_or("");
    if kind.strip_prefix('-').unwrap_or(kind) != "auth" {
        return false;
    }
    tokens.any(|t| {
        let base = t.rsplit('/').next().unwrap_or(t);
        base == "pam_fprintd.so" || (bare_name && base == "pam_fprintd")
    })
}

/// Whether a PAM file has an active `auth` line with `pam_fprintd` (`auth`, `-auth`, any control).
#[must_use]
pub fn pam_has_fprintd(text: &str) -> bool {
    text.lines().any(|l| active_fprintd_auth(l, true))
}

/// Whether authselect's configuration (`authselect.conf` or the output of `authselect current`)
/// lists the feature `with-fingerprint`.
#[must_use]
pub fn authselect_has_fingerprint(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim();
        l.strip_prefix("- ").unwrap_or(l) == "with-fingerprint"
    })
}

/// Whether a dconf key file sets `enable-fingerprint-authentication` to false.
#[must_use]
pub fn dconf_disables_fingerprint(text: &str) -> bool {
    text.lines().any(|l| {
        l.split_once('=').is_some_and(|(k, v)| {
            k.trim() == "enable-fingerprint-authentication" && v.trim() == "false"
        })
    })
}

/// The family of the system, which says what "fingerprint is global" means and the package names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Debian,
    Fedora,
    Arch,
    Unknown,
}

/// The family from the contents of `os-release` (`ID`, `ID_LIKE`).
#[must_use]
pub fn family_from_os_release(text: &str) -> Family {
    let mut words = Vec::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=')
            && (k == "ID" || k == "ID_LIKE")
        {
            words.extend(
                v.trim_matches(|c| c == '"' || c == '\'')
                    .split_whitespace()
                    .map(str::to_owned),
            );
        }
    }
    let has = |names: &[&str]| words.iter().any(|w| names.contains(&w.as_str()));
    if has(&["debian", "ubuntu"]) {
        Family::Debian
    } else if has(&["fedora", "rhel", "centos", "almalinux", "rocky"]) {
        Family::Fedora
    } else if has(&["arch"]) {
        Family::Arch
    } else {
        Family::Unknown
    }
}

/// The packages `fprintd` and its PAM module come in, for the family.
#[must_use]
pub fn packages(family: Family) -> &'static str {
    match family {
        Family::Debian => "libpam-fprintd and fprintd",
        Family::Fedora => "fprintd-pam and fprintd",
        Family::Arch => "fprintd",
        Family::Unknown => {
            "libpam-fprintd and fprintd (Debian, Ubuntu), fprintd-pam and fprintd (Fedora, Alma) or fprintd (Arch)"
        }
    }
}

/// What the command saw of a path: nothing, a regular file with its bytes, or anything else
/// (a symlink, a directory, a device).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileState {
    Missing,
    Regular(Vec<u8>),
    NotRegular,
}

/// What the command saw of the vendor file (its content does not matter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorState {
    Missing,
    NotRegular,
    Regular,
}

/// Everything the decisions depend on.
// Each bool is one independent observation the command makes; a state machine or bitset would hide
// which one a decision reads.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct Observed {
    pub euid: u32,
    pub family: Family,
    pub polkit_file: FileState,
    pub vendor: VendorState,
    pub module_present: bool,
    pub fprintd_present: bool,
    /// `fprintd` listed at least one device. An unanswered question is `false`.
    pub reader_present: bool,
    /// Contents of the files that can make fingerprint global, when they exist and are readable.
    pub common_auth: Option<String>,
    pub authselect: Option<String>,
    pub system_auth: Option<String>,
    pub sudo: Option<String>,
    pub gnome_login_schema: bool,
    pub dconf_disables_login_fingerprint: bool,
}

/// A refusal: what is wrong and the next step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    what: String,
    next: String,
}

impl Refusal {
    fn new(what: impl Into<String>, next: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            next: next.into(),
        }
    }

    /// The two lines: what is wrong, and the next step.
    #[must_use]
    pub fn lines(&self) -> (&str, &str) {
        (&self.what, &self.next)
    }

    /// The two lines, without a final newline.
    #[must_use]
    pub fn message(&self) -> String {
        format!("{}\n{}", self.what, self.next)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnableDecision {
    Refuse(Refusal),
    /// Custodio's file is there: nothing to write, success.
    AlreadyEnabled,
    Write {
        warn_no_reader: bool,
        lock_note: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisableDecision {
    Refuse(Refusal),
    NothingToDisable,
    Remove,
}

impl DisableDecision {
    /// The refusal's two lines, if it is one.
    #[must_use]
    pub fn refusal_text(&self) -> Option<String> {
        match self {
            Self::Refuse(r) => Some(r.message()),
            _ => None,
        }
    }
}

/// What a successful `enable` or `disable` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Done {
    /// Wrote the file; `lock_note`: the lock-screen note applies.
    Enabled {
        lock_note: bool,
    },
    AlreadyOn,
    Disabled,
    AlreadyOff,
}

const UNDO_ENABLE: &str = "Undo: sudo custodio setup fingerprint disable";

/// The line `enable` or `disable` prints on success, under the name doctor uses for this check.
#[must_use]
pub fn done_line(done: Done) -> Line {
    let line = |text: &str| Line::new(State::Ok, POLKIT, text);
    match done {
        Done::Enabled { lock_note } => {
            let mut l = line("finger on for every polkit dialog")
                .with("Three wrong fingers, or 30 s without a touch, fall back to the password.")
                .with("sudo and the login are unchanged.");
            if lock_note {
                l = l.with(LOCK_NOTE);
            }
            l.with(UNDO_ENABLE)
        }
        Done::AlreadyOn => line("already on, nothing changed").with(UNDO_ENABLE),
        Done::Disabled => line("off, polkit asks for the password only")
            .with("Undo: sudo custodio setup fingerprint enable"),
        Done::AlreadyOff => line("already off, nothing changed"),
    }
}

/// What `enable` says on standard error when fprintd lists no reader: doctor's reader line, as a
/// warning, since the file is written anyway.
#[must_use]
pub fn no_reader_line() -> Line {
    Line::new(State::Warn, READER, NO_READER)
        .with("Polkit asks for the password until there is a reader and an enrolled finger.")
        .with("Run 'custodio doctor' to see what is missing.")
        .fix(NO_READER_FIX)
}

/// The lock-screen note of the threat model ("Not guaranteed").
pub const LOCK_NOTE: &str = "On GNOME the finger may also unlock the lock screen \
(org.gnome.login-screen enable-fingerprint-authentication); Custodio leaves that setting alone.";

/// Whether the lock-screen note applies: GNOME's login-screen schema is installed, nothing sets
/// the key to false, and the family is not Fedora's (authselect locks the key off there). An
/// unknown family shows the note.
#[must_use]
pub const fn lock_note_shown(schema_present: bool, key_set_false: bool, family: Family) -> bool {
    schema_present && !key_set_false && !matches!(family, Family::Fedora)
}

/// The file that makes fingerprint global, as the person would name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalVia {
    CommonAuth,
    Authselect,
    SystemAuth,
    Sudo,
}

/// How fingerprint is on for the whole system on this family, if it is.
#[must_use]
pub fn global_via(o: &Observed) -> Option<GlobalVia> {
    let pam = |t: &Option<String>| t.as_deref().is_some_and(pam_has_fprintd);
    let select = || {
        o.authselect
            .as_deref()
            .is_some_and(authselect_has_fingerprint)
    };
    let common = || pam(&o.common_auth).then_some(GlobalVia::CommonAuth);
    let chosen = || select().then_some(GlobalVia::Authselect);
    let arch = || {
        pam(&o.system_auth)
            .then_some(GlobalVia::SystemAuth)
            .or_else(|| pam(&o.sudo).then_some(GlobalVia::Sudo))
    };
    match o.family {
        Family::Debian => common(),
        Family::Fedora => chosen(),
        Family::Arch => arch(),
        Family::Unknown => common().or_else(chosen).or_else(arch),
    }
}

fn global_fingerprint(o: &Observed) -> bool {
    global_via(o).is_some()
}

fn not_root() -> Refusal {
    Refusal::new(
        "custodio setup fingerprint: this changes a system file and must run as root",
        "Run it again with sudo: 'sudo custodio setup fingerprint enable' (or 'disable').",
    )
}

fn foreign() -> Refusal {
    Refusal::new(
        format!(
            "custodio setup fingerprint: {POLKIT_FILE} exists and is not Custodio's (or is not a regular file); nothing was changed"
        ),
        "Look at who owns it ('dpkg -S', 'rpm -qf' or 'pacman -Qo' on that path) and remove or merge it yourself, then run 'sudo custodio setup fingerprint enable' again.",
    )
}

/// What `enable` does in the observed state.
#[must_use]
pub fn decide_enable(o: &Observed) -> EnableDecision {
    if o.euid != 0 {
        return EnableDecision::Refuse(not_root());
    }
    match &o.polkit_file {
        FileState::Regular(b) if b == file_bytes() => return EnableDecision::AlreadyEnabled,
        FileState::Regular(b) if is_custodios_of_0_8(b) => {
            return EnableDecision::Refuse(Refusal::new(
                format!(
                    "custodio setup fingerprint: {POLKIT_FILE} is an older Custodio file that gives the finger one try; nothing was changed"
                ),
                "Run 'sudo custodio setup fingerprint disable', then 'sudo custodio setup fingerprint enable' for three tries.",
            ));
        }
        FileState::Missing => {}
        _ => return EnableDecision::Refuse(foreign()),
    }
    if o.vendor != VendorState::Regular {
        return EnableDecision::Refuse(Refusal::new(
            format!(
                "custodio setup fingerprint: {VENDOR_FILE} is missing or is not a regular file, so the override has nothing to include; nothing was changed"
            ),
            "Check that polkit is installed and where its PAM file is ('rpm -ql polkit' or 'dpkg -L polkit'), and report it if it is elsewhere.",
        ));
    }
    let family = o.family;
    if !o.module_present {
        return EnableDecision::Refuse(Refusal::new(
            "custodio setup fingerprint: pam_fprintd.so is not installed; nothing was changed",
            format!(
                "Install {} and run 'sudo custodio setup fingerprint enable' again.",
                packages(family)
            ),
        ));
    }
    if !o.fprintd_present {
        return EnableDecision::Refuse(Refusal::new(
            "custodio setup fingerprint: fprintd is not installed; nothing was changed",
            format!(
                "Install {} and run 'sudo custodio setup fingerprint enable' again.",
                packages(family)
            ),
        ));
    }
    if global_fingerprint(o) {
        return EnableDecision::Refuse(Refusal::new(
            "custodio setup fingerprint: fingerprint is already on for the whole system, so this override would be redundant (and might ask for the finger twice after a mismatch); nothing was changed",
            "Turn the global switch off (pam-auth-update, authselect disable-feature with-fingerprint, or your distribution's tool), then run 'sudo custodio setup fingerprint enable' again.",
        ));
    }
    EnableDecision::Write {
        warn_no_reader: !o.reader_present,
        lock_note: lock_note_shown(
            o.gnome_login_schema,
            o.dconf_disables_login_fingerprint,
            family,
        ),
    }
}

/// What `disable` does in the observed state.
#[must_use]
pub fn decide_disable(o: &Observed) -> DisableDecision {
    if o.euid != 0 {
        return DisableDecision::Refuse(not_root());
    }
    match &o.polkit_file {
        FileState::Missing => DisableDecision::NothingToDisable,
        FileState::Regular(b) if is_custodios(b) => DisableDecision::Remove,
        _ => DisableDecision::Refuse(Refusal::new(
            format!(
                "custodio setup fingerprint: {POLKIT_FILE} is not Custodio's (or is not a regular file); nothing was changed"
            ),
            "Find who owns it with 'dpkg -S', 'rpm -qf' or 'pacman -Qo' on that path, and remove it yourself if you mean to.",
        )),
    }
}

/// Entry point for the fuzz target: any bytes through the PAM, authselect and dconf readers, and
/// the invariants between them. Returns whether the text had an active fingerprint line.
///
/// # Panics
/// When a reader breaks an invariant: that is what the fuzz target looks for.
#[must_use]
pub fn fuzz_pam_file(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    let global = pam_has_fprintd(&text);
    // The line a reader of the override finds is always an active line of the file.
    if let Some(line) = first_fprintd_auth_line(&text) {
        assert!(global && text.contains(line));
    }
    let _ = authselect_has_fingerprint(&text);
    let _ = dconf_disables_fingerprint(&text);
    let _ = family_from_os_release(&text);
    assert!(!is_custodios(data) || global);
    global
}
