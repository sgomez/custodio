//! The command line of `custodio setup browsers enable`: its arguments, refusals, exit reasons and the two entry points.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::doctor_later::FIREFOX;
use crate::help::BROWSERS_PREFIX;
use crate::parse::Wrong;
use crate::register_discover::Environment;
use crate::register_native::{INSTALLED_MODULE, MODUTIL, Options, Outcome, Report, RunError, run};
use crate::register_snap::{
    DEFAULT_JOURNAL_SOCKET, Refresh, copy_path, journal_datagram, refresh_only, send_to_journal,
};
use crate::report::{self, State};

/// Why the command refuses to run: it edits the user's own profiles, never root's or a sudo user's.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Root,
    Sudo,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => write!(
                f,
                "{BROWSERS_PREFIX}: refused to run as root; run it as the user whose browsers should see Custodio"
            ),
            Self::Sudo => write!(
                f,
                "{BROWSERS_PREFIX}: refused to run under sudo (SUDO_USER or SUDO_UID is set); run it as the user whose browsers should see Custodio"
            ),
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

/// What the command line of `custodio setup browsers enable` asks for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegisterArgs {
    /// `--module PATH`: register this library instead of [`INSTALLED_MODULE`].
    pub module: Option<PathBuf>,
    /// `--remove`: remove every Custodio entry instead.
    pub remove: bool,
    /// `--refresh-only`: only replace a stale copy of the module in the Firefox snap, and log the outcome.
    pub refresh_only: bool,
}

/// Parse the arguments after `setup browsers <action>`: `enable` and `refresh` take `[--module PATH]`,
/// `disable` takes nothing. Any other `action` is not a browsers action.
///
/// # Errors
/// What is wrong with the line.
pub fn parse_register_args<I: IntoIterator<Item = String>>(
    action: &str,
    args: I,
) -> Result<RegisterArgs, Wrong> {
    let mut it = args.into_iter();
    let mut parsed = RegisterArgs {
        remove: action == "disable",
        refresh_only: action == "refresh",
        ..RegisterArgs::default()
    };
    while let Some(arg) = it.next() {
        if arg == "--module" && !parsed.remove {
            let path = it
                .next()
                .filter(|p| !p.is_empty())
                .ok_or(Wrong::NoValue("--module"))?;
            if parsed.module.replace(PathBuf::from(path)).is_some() {
                return Err(Wrong::Twice("--module"));
            }
        } else {
            return Err(Wrong::extra(arg));
        }
    }
    Ok(parsed)
}

/// Why `custodio setup browsers enable` ends without success.
#[derive(Debug)]
pub enum RegisterError {
    Refused(Refusal),
    Run(RunError),
    /// This many profiles were skipped for a reason the person can fix; each was named above. `remove`: the run was
    /// `--remove`, so that is the command to run again.
    Skipped {
        count: usize,
        remove: bool,
    },
    /// Refresh-only mode could not replace the copy.
    Refresh(String),
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "{r}"),
            Self::Run(e) => write!(f, "{e}"),
            Self::Skipped { count, .. } => write!(
                f,
                "custodio: {} skipped; fix what is named above and run this again",
                profiles(*count)
            ),
            Self::Refresh(why) => write!(f, "custodio: {why}"),
        }
    }
}

impl std::error::Error for RegisterError {}

/// "1 profile" or "N profiles".
#[must_use]
pub fn profiles(count: usize) -> String {
    if count == 1 {
        "1 profile".to_owned()
    } else {
        format!("{count} profiles")
    }
}

/// `custodio setup browsers enable`: refuse root and sudo, run, print [`register_lines`] on `out`, coloured when `on`.
///
/// # Errors
/// See [`RegisterError`].
pub fn register_command<W: io::Write>(
    args: &RegisterArgs,
    env: &Environment,
    euid: u32,
    var: impl Fn(&str) -> Option<OsString>,
    out: &mut W,
    on: bool,
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
    let _ = write!(
        out,
        "{}",
        report::render(&register_lines(&report, args.remove), on)
    );
    let skipped = report
        .lines
        .iter()
        .filter(|l| l.outcome.is_fixable_skip())
        .count();
    if skipped > 0 {
        return Err(RegisterError::Skipped {
            count: skipped,
            remove: args.remove,
        });
    }
    Ok(())
}

/// The lines of a run: one per profile and one per change to the snap's copy (or one saying that
/// there is no profile), a fix under each profile a browser holds, and the restart once, at the
/// end, when an entry changed.
#[must_use]
pub fn register_lines(report: &Report, remove: bool) -> Vec<report::Line> {
    if report.lines.is_empty() {
        return vec![report::Line::new(State::Ok, FIREFOX, "none found")];
    }
    let again = if remove {
        "custodio setup browsers disable"
    } else {
        "custodio setup browsers enable"
    };
    let mut lines: Vec<report::Line> = report
        .lines
        .iter()
        .map(|l| {
            let line = l.report_line();
            if matches!(l.outcome, Outcome::Held(_)) {
                line.fix(&format!("close the browser, then run '{again}' again"))
            } else {
                line
            }
        })
        .collect();
    if report.lines.iter().any(|l| l.outcome.changed_entries())
        && let Some(last) = lines.last_mut()
    {
        last.under.push(RESTART.to_owned());
    }
    lines
}

/// Under the last line when a run changed an entry.
pub const RESTART: &str = "Restart the browsers to see the change.";

/// The line of `--refresh-only`: the copy, tilde'd, and what happened to it.
#[must_use]
pub fn refresh_line(outcome: &Refresh, copy: &Path, home: &Path) -> report::Line {
    let (state, what) = match outcome {
        Refresh::Refreshed => Outcome::CopyRefreshed.state_text(),
        Refresh::UpToDate => Outcome::CopyUpToDate.state_text(),
        Refresh::NoCopy => (State::Ok, "none, nothing to refresh".to_owned()),
        Refresh::NoModule(m) => (
            State::Warn,
            format!(
                "left as it is, no installed module at {}",
                crate::cert_text::escape(&m.display().to_string())
            ),
        ),
        Refresh::Failed(why) => (State::NotOk, crate::cert_text::escape(why)),
    };
    let copy = crate::cert_text::escape(&report::tilde(copy, Some(home)));
    report::Line::new(state, SNAP_COPY, format!("{copy}: {what}"))
}

/// The name of the `--refresh-only` line.
pub const SNAP_COPY: &str = "snap copy";

/// `custodio setup browsers refresh`: refuse root and sudo, replace a stale copy, say what happened on `out` (coloured
/// when `on`) and in the
/// journal at `journal`. A journal that cannot be reached is reported on `err` and changes nothing else.
///
/// # Errors
/// [`RegisterError::Refused`], or [`RegisterError::Refresh`] when the copy could not be replaced.
#[allow(
    clippy::too_many_arguments,
    reason = "what to run on, who runs it, and where to write: each is an input the tests replace"
)]
pub fn refresh_only_command<W: io::Write, E: io::Write>(
    args: &RegisterArgs,
    env: &Environment,
    euid: u32,
    var: impl Fn(&str) -> Option<OsString>,
    journal: &Path,
    out: &mut W,
    err: &mut E,
    on: bool,
) -> Result<(), RegisterError> {
    refuse_root_and_sudo(euid, var).map_err(RegisterError::Refused)?;
    let module = args
        .module
        .clone()
        .unwrap_or_else(|| PathBuf::from(INSTALLED_MODULE));
    let copy = copy_path(&env.home);
    let outcome = refresh_only(&env.home, &module);
    let _ = write!(
        out,
        "{}",
        report::render(&[refresh_line(&outcome, &copy, &env.home)], on)
    );
    if let Err(e) = send_to_journal(journal, &journal_datagram(&outcome, &copy)) {
        let _ = writeln!(
            err,
            "custodio: {}\ncheck that systemd-journald runs: systemctl status systemd-journald",
            crate::cert_text::escape(&format!(
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

/// The journal socket `custodio setup browsers refresh` writes to.
#[must_use]
pub const fn default_journal_socket() -> &'static str {
    DEFAULT_JOURNAL_SOCKET
}
