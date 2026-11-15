//! The command line of `custodio register`: its arguments, refusals, exit reasons and the two entry points.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::register_discover::{Environment, SNAP_NAME};
use crate::register_native::{INSTALLED_MODULE, MODUTIL, Options, RunError, run};
use crate::register_snap::{
    DEFAULT_JOURNAL_SOCKET, Refresh, copy_path, journal_datagram, refresh_only, send_to_journal,
};

/// Why the command refuses to run: it edits the user's own profiles, never root's or a sudo user's.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Root,
    Sudo,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => f.write_str("custodio register: refused to run as root; run it as the user whose browsers should see Custodio"),
            Self::Sudo => f.write_str("custodio register: refused to run under sudo (SUDO_USER or SUDO_UID is set); run it as the user whose browsers should see Custodio"),
        }
    }
}

impl std::error::Error for Refusal {}

/// Refuse effective uid 0 and any `SUDO_USER`/`SUDO_UID`.
///
/// # Errors
/// The [`Refusal`] that applies.
pub fn refuse_root_and_sudo(
    euid: u32,
    var: impl Fn(&str) -> Option<OsString>,
) -> Result<(), Refusal> {
    if euid == 0 {
        return Err(Refusal::Root);
    }
    if var("SUDO_USER").is_some() || var("SUDO_UID").is_some() {
        return Err(Refusal::Sudo);
    }
    Ok(())
}

/// What the command line of `custodio register` asks for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegisterArgs {
    /// `--module PATH`: register this library instead of [`INSTALLED_MODULE`].
    pub module: Option<PathBuf>,
    /// `--remove`: remove every Custodio entry instead.
    pub remove: bool,
    /// `--refresh-only`: only replace a stale copy of the module in the Firefox snap, and log the outcome.
    pub refresh_only: bool,
}

/// Parse the arguments after `register`: `[--module PATH] [--remove | --refresh-only]`, each at most once.
///
/// # Errors
/// `None` for anything else (the caller prints the usage text).
#[must_use]
pub fn parse_register_args<I: IntoIterator<Item = String>>(args: I) -> Option<RegisterArgs> {
    let mut it = args.into_iter();
    let mut parsed = RegisterArgs::default();
    let mut module_seen = false;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--module" => {
                let path = it.next().filter(|p| !p.is_empty())?;
                if std::mem::replace(&mut module_seen, true) {
                    return None;
                }
                parsed.module = Some(PathBuf::from(path));
            }
            "--remove" if !parsed.remove => parsed.remove = true,
            "--refresh-only" if !parsed.refresh_only => parsed.refresh_only = true,
            _ => return None,
        }
    }
    (!(parsed.remove && parsed.refresh_only)).then_some(parsed)
}

/// Why `custodio register` ends without success.
#[derive(Debug)]
pub enum RegisterError {
    Refused(Refusal),
    Run(RunError),
    /// This many profiles were skipped for a reason the person can fix; each was named above.
    Skipped(usize),
    /// Refresh-only mode could not replace the copy.
    Refresh(String),
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "{r}"),
            Self::Run(e) => write!(f, "{e}"),
            Self::Skipped(n) => write!(
                f,
                "custodio: {n} profile(s) skipped; fix what is named above and run this again"
            ),
            Self::Refresh(why) => write!(f, "custodio: {why}"),
        }
    }
}

impl std::error::Error for RegisterError {}

/// `custodio register`: refuse root and sudo, run, print one line per profile on `out` and the fixable skips on `err`.
///
/// # Errors
/// See [`RegisterError`].
pub fn register_command<W: io::Write, E: io::Write>(
    args: &RegisterArgs,
    env: &Environment,
    euid: u32,
    var: impl Fn(&str) -> Option<OsString>,
    out: &mut W,
    err: &mut E,
) -> Result<(), RegisterError> {
    refuse_root_and_sudo(euid, var).map_err(RegisterError::Refused)?;
    let module = args
        .module
        .clone()
        .unwrap_or_else(|| PathBuf::from(INSTALLED_MODULE));
    let options = Options {
        module,
        modutil: OsString::from(MODUTIL),
        remove: args.remove,
    };
    let report = run(env, &options).map_err(RegisterError::Run)?;
    if report.lines.is_empty() {
        let _ = writeln!(out, "No native browser profiles found.");
    }
    let mut skipped = 0;
    for line in &report.lines {
        let _ = writeln!(out, "{line}");
        if line.outcome.is_fixable_skip() {
            skipped += 1;
            let _ = writeln!(err, "custodio: {line}");
        }
    }
    if skipped > 0 {
        return Err(RegisterError::Skipped(skipped));
    }
    Ok(())
}

/// `custodio register --refresh-only`: refuse root and sudo, replace a stale copy, say what happened on `out` and in the
/// journal at `journal`. A journal that cannot be reached is reported on `err` and changes nothing else.
///
/// # Errors
/// [`RegisterError::Refused`], or [`RegisterError::Refresh`] when the copy could not be replaced.
pub fn refresh_only_command<W: io::Write, E: io::Write>(
    args: &RegisterArgs,
    env: &Environment,
    euid: u32,
    var: impl Fn(&str) -> Option<OsString>,
    journal: &Path,
    out: &mut W,
    err: &mut E,
) -> Result<(), RegisterError> {
    refuse_root_and_sudo(euid, var).map_err(RegisterError::Refused)?;
    let module = args
        .module
        .clone()
        .unwrap_or_else(|| PathBuf::from(INSTALLED_MODULE));
    let copy = copy_path(&env.home);
    let outcome = refresh_only(&env.home, &module);
    let _ = writeln!(out, "{SNAP_NAME} {}: {outcome}", copy.display());
    if let Err(e) = send_to_journal(journal, &journal_datagram(&outcome, &copy)) {
        let _ = writeln!(
            err,
            "custodio: {}\ncheck that systemd-journald runs: systemctl status systemd-journald",
            crate::list::escape(&format!(
                "cannot write to the journal at {}: {e}",
                journal.display()
            ))
        );
    }
    match outcome {
        Refresh::Failed(why) => Err(RegisterError::Refresh(format!(
            "cannot replace the copy {}: {why}",
            copy.display()
        ))),
        _ => Ok(()),
    }
}

/// The journal socket `custodio register --refresh-only` writes to.
#[must_use]
pub const fn default_journal_socket() -> &'static str {
    DEFAULT_JOURNAL_SOCKET
}
