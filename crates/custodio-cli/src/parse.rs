//! The command line, parsed by hand. Nothing here prints or reads the environment: the parser
//! returns a value, so it cannot write anything.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::fingerprint_cmd::Action;
use crate::help;
use crate::register_native;

/// The usage of every command, from the same table as the help, aligned under the first.
#[must_use]
pub fn usage() -> String {
    let mut text = String::new();
    for (i, c) in help::COMMANDS.iter().enumerate() {
        text.push_str(if i == 0 { "usage: " } else { "       " });
        text.push_str(&c.usage_line());
        text.push('\n');
    }
    text.push_str("Run 'custodio --help' for help.");
    text
}

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Import(ImportArgs),
    /// `list [-v] [[--] <id>]`.
    List(crate::list::ListArgs),
    Delete(String),
    Register(register_native::RegisterArgs),
    Fingerprint(crate::fingerprint_cmd::Action),
    Doctor,
    /// `__key-ids`, hidden: the key ids for the shell completions.
    KeyIds,
    /// `--help` or `-h`: the help of a command, or of the whole tool.
    Help(Option<&'static str>),
}

fn is_help(arg: &str) -> bool {
    arg == "--help" || arg == "-h"
}

/// Parse the arguments after the program name.
///
/// # Errors
/// [`ArgError::CommandUsage`] for a wrong command line of a known command, [`ArgError::Usage`] for
/// anything else, and [`ArgError::BadId`] for an `import` without a derivable key id.
pub fn parse_command<I: IntoIterator<Item = String>>(args: I) -> Result<Command, ArgError> {
    let args: Vec<String> = args.into_iter().collect();
    let known = args.first().and_then(|a| help::command(a));
    let help_only = args.len() == 2 && is_help(&args[1]);
    if let Some(spec) = known {
        if help_only {
            return Ok(Command::Help(Some(spec.name)));
        }
        return parse_known(spec.name, args).map_err(|e| match e {
            ArgError::Usage => ArgError::CommandUsage(spec.name),
            other => other,
        });
    }
    if args.len() == 1 && args[0] == "__key-ids" {
        return Ok(Command::KeyIds);
    }
    if args.is_empty() || (args.len() == 1 && is_help(&args[0])) {
        return Ok(Command::Help(None));
    }
    Err(ArgError::Usage)
}

fn parse_known(name: &str, args: Vec<String>) -> Result<Command, ArgError> {
    let mut it = args.into_iter().peekable();
    it.next();
    match name {
        "list" => {
            let mut args = crate::list::ListArgs::default();
            while let Some(arg) = it.next_if(|a| a == "-v" || a == "--verbose") {
                if std::mem::replace(&mut args.verbose, true) {
                    return Err(ArgError::Usage);
                }
                drop(arg);
            }
            // As for `delete`: `--` ends the options, so an id that starts with `-` can be shown.
            if it.next_if(|a| a == "--").is_some() {
                return match (it.next(), it.next()) {
                    (Some(id), None) => Ok(Command::List(crate::list::ListArgs {
                        id: Some(id),
                        ..args
                    })),
                    _ => Err(ArgError::Usage),
                };
            }
            if it.peek().is_some_and(|id| id.starts_with('-')) {
                return Err(ArgError::Usage);
            }
            match (it.next(), it.next()) {
                (id, None) => Ok(Command::List(crate::list::ListArgs { id, ..args })),
                _ => Err(ArgError::Usage),
            }
        }
        "fingerprint" => match (it.next().as_deref(), it.next()) {
            (Some("enable"), None) => Ok(Command::Fingerprint(Action::Enable)),
            (Some("disable"), None) => Ok(Command::Fingerprint(Action::Disable)),
            _ => Err(ArgError::Usage),
        },
        "doctor" => match it.next() {
            None => Ok(Command::Doctor),
            Some(_) => Err(ArgError::Usage),
        },
        "register" => register_native::parse_register_args(it)
            .map(Command::Register)
            .ok_or(ArgError::Usage),
        "delete" => {
            // `--` ends the options, so an id that starts with `-` can still be deleted. It is the
            // only option accepted, and it is not a bypass of the confirmation.
            if it.peek().map(String::as_str) == Some("--") {
                it.next();
            } else if it.peek().is_some_and(|id| id.starts_with('-')) {
                return Err(ArgError::Usage);
            }
            match (it.next(), it.next()) {
                (Some(id), None) => Ok(Command::Delete(id)),
                _ => Err(ArgError::Usage),
            }
        }
        _ => parse_import(it).map(Command::Import),
    }
}

/// Parsed command line.
#[derive(Debug, PartialEq, Eq)]
pub struct ImportArgs {
    pub file: PathBuf,
    pub id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ArgError {
    Usage,
    /// The command line of this known command is wrong.
    CommandUsage(&'static str),
    BadId,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => f.write_str(&usage()),
            Self::CommandUsage(name) => match help::command(name) {
                Some(c) => write!(
                    f,
                    "usage: {}\nRun 'custodio {name} --help' for help.",
                    c.usage_line()
                ),
                None => f.write_str(&usage()),
            },
            Self::BadId => f.write_str("cannot derive a key id from the file name; use --id"),
        }
    }
}

impl std::error::Error for ArgError {}

/// Parse the arguments after the program name. Any option other than `--id` (for example
/// `--password`) is a usage error: secrets must not travel through argv.
///
/// # Errors
/// [`ArgError::Usage`] for anything unexpected, [`ArgError::BadId`] if no id can be derived.
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<ImportArgs, ArgError> {
    let mut it = args.into_iter();
    if it.next().as_deref() != Some("import") {
        return Err(ArgError::Usage);
    }
    parse_import(it)
}

fn parse_import<I: Iterator<Item = String>>(mut it: I) -> Result<ImportArgs, ArgError> {
    let mut file = None;
    let mut id = None;
    while let Some(arg) = it.next() {
        if arg == "--id" {
            if id.replace(it.next().ok_or(ArgError::Usage)?).is_some() {
                return Err(ArgError::Usage);
            }
        } else if arg.starts_with('-') || file.replace(PathBuf::from(arg)).is_some() {
            return Err(ArgError::Usage);
        }
    }
    let file = file.ok_or(ArgError::Usage)?;
    let id = match id {
        Some(id) => id,
        None => default_id(&file).ok_or(ArgError::BadId)?,
    };
    Ok(ImportArgs { file, id })
}

/// File stem, if it is already a valid id (letters, digits, `_`, `-`). Nothing is rewritten.
fn default_id(file: &Path) -> Option<String> {
    let stem = file.file_stem()?.to_str()?;
    let valid = !stem.is_empty()
        && stem.len() <= 59
        && !stem.ends_with("-cert")
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    valid.then(|| stem.to_owned())
}

/// Entry point for the fuzz target: any argument list through the parser and the help lookup.
/// Returns whether the command line was accepted, so a caller can tell that the work was done.
#[must_use]
pub fn fuzz_cli_args(args: Vec<String>) -> bool {
    let parsed = parse_command(args.clone());
    if let Ok(Command::Help(topic)) = &parsed {
        let _ = help::text(*topic);
    }
    let _ = parse_args(args);
    parsed.is_ok()
}

#[cfg(test)]
mod tests;
