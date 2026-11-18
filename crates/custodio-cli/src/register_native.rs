//! `custodio register`: the module in each native browser profile, with NSS's `modutil` (SPEC Design 3).
//!
//! The rules are the `Decision:` lines of `docs/findings/F172.md`. `modutil` is the only writer of module entries; the
//! command only reads `pkcs11.txt` to recognise an entry, and swaps the one file it changed in with `rename(2)`.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::browser_files::{FileError, LockState, read_bounded};
use crate::cert_text::escape;
pub use crate::register_cli::{
    Refusal, RegisterArgs, RegisterError, default_journal_socket, parse_register_args,
    refresh_only_command, refuse_root_and_sudo, register_command,
};
use crate::register_discover::{Environment, Profile, discover};
use crate::register_modutil::{instead_of_registering, modutil};
use crate::register_snap::{copy_path, snap_lines};
use crate::report::{self, State};

/// Where every package installs the module.
pub const INSTALLED_MODULE: &str = "/usr/lib/custodio/libcustodio_pkcs11.so";
/// The file name that makes a library a Custodio module.
pub const MODULE_FILE: &str = "libcustodio_pkcs11.so";
/// The name the entry is added under.
pub const MODULE_NAME: &str = "Custodio";
/// The program that edits the NSS databases, found through `PATH`.
pub const MODUTIL: &str = "modutil";

/// One module entry of `pkcs11.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub library: String,
}

/// The entries of a `pkcs11.txt`: each `library=` line starts one, its `name=` line names it.
#[must_use]
pub fn parse_entries(text: &str) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    for line in text.lines() {
        if let Some(library) = line.strip_prefix("library=") {
            entries.push(Entry {
                name: String::new(),
                library: library.to_owned(),
            });
        } else if let Some(name) = line.strip_prefix("name=")
            && let Some(last) = entries.last_mut()
            && last.name.is_empty()
        {
            name.clone_into(&mut last.name);
        }
    }
    entries
}

/// Whether a library is a Custodio module, by its file name.
#[must_use]
pub fn is_custodio_library(library: &str) -> bool {
    Path::new(library)
        .file_name()
        .is_some_and(|f| f == MODULE_FILE)
}

/// What registration does to one profile, from its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// An entry already has this library (under this name).
    Present(String),
    /// A Custodio module at another path that still exists: left alone, the module is registered once.
    PresentElsewhere(String),
    /// Custodio entries whose file is gone are deleted, and the module is added under the name of the first.
    Refresh { stale: Vec<String>, name: String },
    /// Add the module under this name.
    Add(String),
    /// Every candidate name is taken by another module.
    NameTaken,
}

/// Decide what registration of `module` does. `exists` tells whether a library file exists.
#[must_use]
pub fn plan(entries: &[Entry], module: &str, exists: impl Fn(&str) -> bool) -> Plan {
    if let Some(e) = entries.iter().find(|e| e.library == module) {
        return Plan::Present(e.name.clone());
    }
    let custodio = || entries.iter().filter(|e| is_custodio_library(&e.library));
    if let Some(e) = custodio().find(|e| exists(&e.library)) {
        return Plan::PresentElsewhere(e.name.clone());
    }
    let stale: Vec<String> = custodio().map(|e| e.name.clone()).collect();
    if let Some(first) = stale.first() {
        let name = first.clone();
        return Plan::Refresh { stale, name };
    }
    let taken = |n: &str| entries.iter().any(|e| e.name == n);
    [MODULE_NAME, "Custodio PKCS#11 module"]
        .into_iter()
        .find(|n| !taken(n))
        .map_or(Plan::NameTaken, |n| Plan::Add(n.to_owned()))
}

/// The names of every Custodio entry, for removal.
#[must_use]
pub fn custodio_names(entries: &[Entry]) -> Vec<String> {
    entries
        .iter()
        .filter(|e| is_custodio_library(&e.library))
        .map(|e| e.name.clone())
        .collect()
}

/// What happened to a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Registered,
    AlreadyRegistered(String),
    /// A Custodio module at another path that still exists was left as it is.
    AlreadyRegisteredElsewhere(String),
    Refreshed,
    Removed(usize),
    NothingToRemove,
    /// A browser has the profile open: fixable by the person.
    Held(String),
    /// The system NSS loads the p11-kit proxy, which already shows the module.
    ThroughP11Kit,
    /// Not fixable by the person.
    Skipped(String),
    /// Fixable: the reason.
    Failed(String),
    /// The snap's copy was created.
    CopyPlaced,
    /// The snap's copy was stale and has been replaced.
    CopyRefreshed,
    /// The snap's copy already holds the module's bytes.
    CopyUpToDate,
    /// The snap's copy was deleted.
    CopyRemoved,
    /// The snap's copy stays because a profile that is open may still point to it.
    CopyKept,
    /// The snap's copy could not be replaced or deleted: the reason.
    CopyFailed(String),
}

impl Outcome {
    /// Whether it is about the snap's copy of the module rather than a profile.
    #[must_use]
    pub const fn is_copy(&self) -> bool {
        matches!(
            self,
            Self::CopyPlaced
                | Self::CopyRefreshed
                | Self::CopyUpToDate
                | Self::CopyRemoved
                | Self::CopyKept
                | Self::CopyFailed(_)
        )
    }

    /// Whether the person can fix it, so that the exit status is not zero.
    #[must_use]
    pub const fn is_fixable_skip(&self) -> bool {
        matches!(self, Self::Held(_) | Self::Failed(_) | Self::CopyFailed(_))
    }
}

impl Outcome {
    /// The state and short text of its line.
    #[must_use]
    pub fn state_text(&self) -> (State, String) {
        match self {
            Self::Registered => (State::Ok, "registered".to_owned()),
            Self::AlreadyRegistered(_) => (State::Ok, "already registered".to_owned()),
            Self::AlreadyRegisteredElsewhere(_) => {
                (State::Ok, "already registered from another path".to_owned())
            }
            Self::Refreshed => (
                State::Ok,
                "registered again, the old path was gone".to_owned(),
            ),
            Self::Removed(1) | Self::CopyRemoved => (State::Ok, "removed".to_owned()),
            Self::Removed(n) => (State::Ok, format!("removed {n} entries")),
            Self::NothingToRemove => (State::Ok, "nothing to remove".to_owned()),
            Self::ThroughP11Kit => (State::Ok, P11_KIT.to_owned()),
            Self::Held(why) | Self::Failed(why) | Self::CopyFailed(why) => {
                (State::NotOk, escape(why))
            }
            Self::Skipped(why) => (State::Warn, escape(why)),
            Self::CopyPlaced => (State::Ok, "placed".to_owned()),
            Self::CopyRefreshed => (
                State::Ok,
                "replaced, it differed from the module".to_owned(),
            ),
            Self::CopyUpToDate => (State::Ok, "up to date".to_owned()),
            Self::CopyKept => (
                State::Ok,
                "kept, an open profile may still use it".to_owned(),
            ),
        }
    }

    /// Whether the browsers see something new after a restart.
    #[must_use]
    pub const fn changed_entries(&self) -> bool {
        matches!(self, Self::Registered | Self::Refreshed | Self::Removed(_))
    }
}

/// What the line of a profile says when the system NSS already shows the module.
pub const P11_KIT: &str = "through p11-kit, nothing to register";

/// What the command is asked to do.
#[derive(Debug, Clone)]
pub struct Options {
    /// The library to register.
    pub module: PathBuf,
    /// The `modutil` program: a path, or a name looked up in `PATH`.
    pub modutil: OsString,
    /// Remove every Custodio entry instead of registering.
    pub remove: bool,
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub browser: &'static str,
    pub path: PathBuf,
    pub outcome: Outcome,
}

impl Line {
    /// Its line in the shared format: the browser, then the profile directory (or, for the snap's
    /// copy, `module copy`) and what happened.
    #[must_use]
    pub fn report_line(&self) -> report::Line {
        let (state, what) = self.outcome.state_text();
        let place = if self.outcome.is_copy() {
            "module copy".to_owned()
        } else {
            crate::register_discover::profile_label(&self.path)
        };
        report::Line::new(state, self.browser, format!("{place}: {what}"))
    }
}

/// What a run did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    pub lines: Vec<Line>,
}

impl Report {
    /// Whether any profile has a skip the person can fix.
    #[must_use]
    pub fn has_fixable_skip(&self) -> bool {
        self.lines.iter().any(|l| l.outcome.is_fixable_skip())
    }
}

/// A run that cannot start or go on.
#[derive(Debug)]
pub enum RunError {
    Discover(FileError),
    /// The module to register is not there.
    MissingModule(PathBuf),
    /// `modutil` is not installed.
    NoModutil(OsString),
    /// `$HOME` is not set.
    NoHome,
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discover(e) => write!(f, "custodio: {e}"),
            Self::MissingModule(p) => write!(
                f,
                "custodio: the module {} does not exist; nothing was registered",
                p.display()
            ),
            Self::NoHome => {
                f.write_str("custodio: HOME is not set; cannot find the browser profiles")
            }
            Self::NoModutil(p) => write!(
                f,
                "custodio: {} was not found; install NSS's tools (libnss3-tools or nss-tools) and run this again",
                p.to_string_lossy()
            ),
        }
    }
}

impl std::error::Error for RunError {}

/// Whether `program` is a file in a directory of `PATH` (an absolute `program` is its own path: `join` replaces).
fn program_exists(program: &OsStr) -> bool {
    let p = Path::new(program);
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|d| d.join(p).is_file()))
}

/// One edit of the module list.
enum Step<'a> {
    Delete(&'a str),
    Add(&'a str, &'a Path),
}

fn run_steps(program: &OsStr, dir: &Path, steps: &[Step<'_>]) -> Result<(), String> {
    for step in steps {
        let args = match step {
            Step::Delete(name) => vec![
                OsStr::new("-delete"),
                OsStr::new(name),
                OsStr::new("-force"),
            ],
            Step::Add(name, lib) => vec![
                OsStr::new("-add"),
                OsStr::new(name),
                OsStr::new("-libfile"),
                lib.as_os_str(),
                OsStr::new("-force"),
            ],
        };
        modutil(program, dir, &args)?;
    }
    Ok(())
}

const DB_FILES: [&str; 3] = ["cert9.db", "key4.db", "pkcs11.txt"];

/// The scratch directory beside the profile (same filesystem).
fn scratch_of(profile: &Path) -> Option<PathBuf> {
    let name = profile.file_name()?;
    let mut dir_name = OsString::from(".");
    dir_name.push(name);
    dir_name.push(".custodio-scratch");
    Some(profile.parent()?.join(dir_name))
}

fn remove_scratch(scratch: &Path) {
    let _ = fs::remove_dir_all(scratch);
}

fn writable(dir: &Path) -> bool {
    [rustix::fs::Access::WRITE_OK, rustix::fs::Access::EXEC_OK]
        .into_iter()
        .all(|mode| rustix::fs::access(dir, mode).is_ok())
}

/// Apply the steps to the profile: through a scratch copy and `rename(2)` when the three files exist, else directly.
fn apply(program: &OsStr, profile: &Path, steps: &[Step<'_>]) -> Result<(), String> {
    if !writable(profile) {
        return Err("the profile directory is not writable".to_owned());
    }
    let all_there = DB_FILES.iter().all(|f| profile.join(f).is_file());
    if !all_there {
        return run_steps(program, profile, steps);
    }
    let scratch = scratch_of(profile).ok_or("the profile has no usable directory name")?;
    let result = swap(program, profile, &scratch, steps);
    remove_scratch(&scratch);
    result
}

fn swap(program: &OsStr, profile: &Path, scratch: &Path, steps: &[Step<'_>]) -> Result<(), String> {
    let io_err = |what: &str, e: io::Error| format!("{what}: {e}");
    fs::create_dir(scratch).map_err(|e| io_err("cannot create the scratch directory", e))?;
    for f in DB_FILES {
        fs::copy(profile.join(f), scratch.join(f))
            .map_err(|e| io_err("cannot copy the databases", e))?;
    }
    run_steps(program, scratch, steps)?;
    fs::rename(scratch.join("pkcs11.txt"), profile.join("pkcs11.txt"))
        .map_err(|e| io_err("cannot replace pkcs11.txt", e))
}

fn entries_of(profile: &Path) -> Result<Vec<Entry>, String> {
    let bytes = read_bounded(&profile.join("pkcs11.txt")).map_err(|e| e.to_string())?;
    Ok(bytes
        .map(|b| parse_entries(&String::from_utf8_lossy(&b)))
        .unwrap_or_default())
}

/// Register `module` in one profile directory (the lock and p11-kit checks are the caller's).
#[must_use]
pub fn register_profile(program: &OsStr, profile: &Path, module: &Path) -> Outcome {
    let entries = match entries_of(profile) {
        Ok(e) => e,
        Err(why) => return Outcome::Failed(why),
    };
    let Some(lib) = module.to_str() else {
        return Outcome::Failed("the module path is not valid UTF-8".to_owned());
    };
    match plan(&entries, lib, |l| Path::new(l).exists()) {
        Plan::Present(name) => Outcome::AlreadyRegistered(name),
        Plan::PresentElsewhere(name) => Outcome::AlreadyRegisteredElsewhere(name),
        Plan::NameTaken => Outcome::Failed(format!(
            "the names \"{MODULE_NAME}\" and \"Custodio PKCS#11 module\" are both used by other modules"
        )),
        Plan::Add(name) => match apply(program, profile, &[Step::Add(&name, module)]) {
            Ok(()) => Outcome::Registered,
            Err(why) => Outcome::Failed(why),
        },
        Plan::Refresh { stale, name } => {
            let mut steps: Vec<Step<'_>> = stale.iter().map(|n| Step::Delete(n)).collect();
            steps.push(Step::Add(&name, module));
            match apply(program, profile, &steps) {
                Ok(()) => Outcome::Refreshed,
                Err(why) => Outcome::Failed(why),
            }
        }
    }
}

/// Remove every Custodio entry of one profile directory.
#[must_use]
pub fn remove_profile(program: &OsStr, profile: &Path) -> Outcome {
    let entries = match entries_of(profile) {
        Ok(e) => e,
        Err(why) => return Outcome::Failed(why),
    };
    let names = custodio_names(&entries);
    if names.is_empty() {
        return Outcome::NothingToRemove;
    }
    let steps: Vec<Step<'_>> = names.iter().map(|n| Step::Delete(n)).collect();
    match apply(program, profile, &steps) {
        Ok(()) => Outcome::Removed(names.len()),
        Err(why) => Outcome::Failed(why),
    }
}

/// `instead` replaces registration (not removal) of a profile no browser holds.
pub(crate) fn handle(
    profile: &Profile,
    options: &Options,
    module: &Path,
    instead: Option<&Outcome>,
) -> Outcome {
    if let Some(scratch) = scratch_of(&profile.path) {
        remove_scratch(&scratch);
    }
    if let LockState::Held(reason) = &profile.lock {
        return Outcome::Held(format!("a browser has it open ({reason})"));
    }
    if options.remove {
        return remove_profile(&options.modutil, &profile.path);
    }
    if let Some(outcome) = instead {
        return outcome.clone();
    }
    register_profile(&options.modutil, &profile.path, module)
}

/// Register (or remove) in every native profile found, and keep the Firefox snap's copy of the module.
///
/// # Errors
/// A [`RunError`]: discovery failed, the module to register is missing, or `modutil` is not installed. Nothing has
/// been changed then.
pub fn run(env: &Environment, options: &Options) -> Result<Report, RunError> {
    let profiles = discover(env).map_err(RunError::Discover)?;
    let copy = copy_path(&env.home);
    if profiles.is_empty() && fs::symlink_metadata(&copy).is_err() {
        return Ok(Report::default());
    }
    if !options.remove && !options.module.exists() {
        return Err(RunError::MissingModule(options.module.clone()));
    }
    if !profiles.is_empty() && !program_exists(&options.modutil) {
        return Err(RunError::NoModutil(options.modutil.clone()));
    }
    let (snap, native): (Vec<&Profile>, Vec<&Profile>) = profiles.iter().partition(|p| p.snap);
    let instead = if options.remove || native.is_empty() {
        None
    } else {
        instead_of_registering(options)
    };
    let mut lines: Vec<Line> = native
        .into_iter()
        .map(|p| Line {
            browser: p.browser,
            path: p.path.clone(),
            outcome: handle(p, options, &options.module, instead.as_ref()),
        })
        .collect();
    if !snap.is_empty() || fs::symlink_metadata(&copy).is_ok() {
        lines.extend(snap_lines(&snap, &copy, options));
    }
    Ok(Report { lines })
}
