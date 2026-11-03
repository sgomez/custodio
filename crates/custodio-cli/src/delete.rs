//! `custodio delete <id>`: asks on the terminal, then makes the single `DeleteKey` call.
//!
//! The confirmation is never skipped: there is no option, environment variable or configuration
//! for it, and nothing but the controlling terminal answers it.

use std::fmt;
use std::io::{self, Write};

use crate::failure::ServiceFailure;
use crate::list::escape;

/// The answers that confirm, exactly as typed (the line ending removed). Everything else, an
/// empty line and the end of input included, declines.
pub const ACCEPTED: [&str; 2] = ["y", "yes"];

/// What `delete` prints once the service has deleted the key.
#[must_use]
pub fn deleted_line(id: &str) -> String {
    format!("Deleted key '{}'.", escape(id))
}

/// The question: names the key and says that it cannot come back.
#[must_use]
pub fn question(id: &str) -> String {
    format!(
        "Delete key '{}'? It cannot be recovered. Type yes to delete it, anything else to cancel: ",
        escape(id)
    )
}

/// Whether `answer` (one line, as typed) confirms.
#[must_use]
pub fn is_yes(answer: &str) -> bool {
    let line = answer.strip_suffix('\n').unwrap_or(answer);
    let line = line.strip_suffix('\r').unwrap_or(line);
    ACCEPTED.contains(&line)
}

/// Where the answer comes from. The real one is the controlling terminal.
pub trait Confirmation {
    /// Shows `question` and returns the line typed, or an empty string at the end of input.
    ///
    /// # Errors
    /// If there is no terminal to ask on.
    fn answer(&mut self, question: &str) -> io::Result<String>;
}

/// The service side of `DeleteKey`.
pub trait KeyDeleter {
    /// # Errors
    /// A [`ServiceFailure`], with a fixed message.
    fn delete_key(&self, id: &str) -> Result<(), ServiceFailure>;
}

/// Why a run of `delete` did not delete.
#[derive(Debug)]
pub enum DeleteFailure {
    /// The person did not answer yes. Nothing was called.
    Declined,
    /// There is no terminal to ask on. Nothing was called.
    NoTerminal,
    Service(ServiceFailure),
    /// The key is gone but the confirmation line could not be written.
    Output(io::Error),
}

impl fmt::Display for DeleteFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declined => f.write_str("not confirmed; nothing was deleted"),
            Self::NoTerminal => f.write_str(
                "deleting a key must be confirmed on a terminal and there is none; nothing was deleted",
            ),
            Self::Service(failure) => write!(f, "{failure}"),
            Self::Output(e) => write!(f, "the key was deleted but the output failed: {e}"),
        }
    }
}

impl std::error::Error for DeleteFailure {}

/// Asks, and only on an explicit yes asks the service to delete the key.
///
/// # Errors
/// See [`DeleteFailure`].
pub fn run_delete<C: Confirmation, D: KeyDeleter, W: Write>(
    id: &str,
    confirmation: &mut C,
    deleter: &D,
    out: &mut W,
) -> Result<(), DeleteFailure> {
    let answer = confirmation
        .answer(&question(id))
        .map_err(|_| DeleteFailure::NoTerminal)?;
    if !is_yes(&answer) {
        return Err(DeleteFailure::Declined);
    }
    deleter.delete_key(id).map_err(DeleteFailure::Service)?;
    writeln!(out, "{}", deleted_line(id)).map_err(DeleteFailure::Output)
}

#[cfg(test)]
mod tests;
