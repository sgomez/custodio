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
/// [`ArgError::Bare`] for a command that needs arguments and got none, [`ArgError::CommandUsage`]
/// with what is wrong for any other bad line of a known command, [`ArgError::Usage`] for an unknown
/// command, and [`ArgError::BadId`] for an `import` without a derivable key id.
pub fn parse_command<I: IntoIterator<Item = String>>(args: I) -> Result<Command, ArgError> {
    let args: Vec<String> = args.into_iter().collect();
    let known = args.first().and_then(|a| help::command(a));
    let help_only = args.len() == 2 && is_help(&args[1]);
    if let Some(spec) = known {
        if help_only {
            return Ok(Command::Help(Some(spec.path)));
        }
        if !spec.children.is_empty() {
            return parse_group(spec, &args[1..]);
        }
        let bare = args.len() == 1;
        return parse_known(spec.name, args).map_err(|e| match e {
            Bad::Wrong(Wrong::Missing(_)) if bare => ArgError::Bare(spec.path),
            Bad::Wrong(w) => ArgError::CommandUsage(spec.path, w),
            Bad::BadId => ArgError::BadId,
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

/// The words after a command that only groups others: a topic or an action each, down to the one
/// that does something. Help for any level is `--help` or `-h` alone after its words.
fn parse_group(group: &'static help::CommandSpec, rest: &[String]) -> Result<Command, ArgError> {
    let mut node = group;
    let mut rest = rest;
    while !node.children.is_empty() {
        let Some((word, after)) = rest.split_first() else {
            return Err(ArgError::Bare(node.path));
        };
        if let Some(child) = node.children.iter().find(|c| c.name == *word) {
            node = child;
            rest = after;
            if rest.len() == 1 && is_help(&rest[0]) {
                return Ok(Command::Help(Some(node.path)));
            }
        } else {
            return Err(ArgError::CommandUsage(
                node.path,
                Wrong::extra(word.clone()),
            ));
        }
    }
    let wrong = |w| ArgError::CommandUsage(node.path, w);
    let it = rest.iter().cloned();
    match node.path.split(' ').nth(1) {
        Some("fingerprint") => {
            end(it).map_err(wrong)?;
            Ok(Command::Fingerprint(if node.name == "enable" {
                Action::Enable
            } else {
                Action::Disable
            }))
        }
        _ => register_native::parse_register_args(node.name, it)
            .map(Command::Register)
            .map_err(wrong),
    }
}

/// What is wrong with the command line of a known command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wrong {
    /// An option the command does not take.
    UnknownOption(String),
    /// An argument the command does not take, or one too many.
    Unexpected(String),
    /// A required argument, named as in the help.
    Missing(&'static str),
    /// An option without its value.
    NoValue(&'static str),
    /// An option given twice.
    Twice(&'static str),
}

impl Wrong {
    /// An argument that is not taken here: an option if it starts with `-`.
    #[must_use]
    pub fn extra(arg: String) -> Self {
        if arg.starts_with('-') {
            Self::UnknownOption(arg)
        } else {
            Self::Unexpected(arg)
        }
    }
}

impl fmt::Display for Wrong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::cert_text::escape;
        match self {
            Self::UnknownOption(o) => write!(f, "unknown option {}", escape(o)),
            Self::Unexpected(a) => write!(f, "unexpected argument {}", escape(a)),
            Self::Missing(a) => write!(f, "missing {a}"),
            Self::NoValue(o) => write!(f, "{o} needs a value"),
            Self::Twice(o) => write!(f, "{o} given twice"),
        }
    }
}

/// Why `parse_known` failed, before the command's name is attached.
enum Bad {
    Wrong(Wrong),
    BadId,
}

impl From<Wrong> for Bad {
    fn from(w: Wrong) -> Self {
        Self::Wrong(w)
    }
}

/// No more arguments, or the first one left over is wrong.
fn end<I: Iterator<Item = String>>(mut it: I) -> Result<(), Wrong> {
    it.next().map_or(Ok(()), |a| Err(Wrong::extra(a)))
}

const KEY_ID: &str = "<key id>";

fn parse_known(name: &str, args: Vec<String>) -> Result<Command, Bad> {
    let mut it = args.into_iter().peekable();
    it.next();
    match name {
        "list" => {
            let mut args = crate::list::ListArgs::default();
            while it.next_if(|a| a == "-v" || a == "--verbose").is_some() {
                if std::mem::replace(&mut args.verbose, true) {
                    return Err(Wrong::Twice("-v").into());
                }
            }
            // As for `delete`: `--` ends the options, so an id that starts with `-` can be shown.
            let dashes = it.next_if(|a| a == "--").is_some();
            if !dashes && it.peek().is_some_and(|id| id.starts_with('-')) {
                return Err(Wrong::extra(it.next().unwrap_or_default()).into());
            }
            let id = it.next();
            if dashes && id.is_none() {
                return Err(Wrong::Missing(KEY_ID).into());
            }
            end(it)?;
            Ok(Command::List(crate::list::ListArgs { id, ..args }))
        }
        "doctor" => {
            end(it)?;
            Ok(Command::Doctor)
        }
        "delete" => {
            // `--` ends the options, so an id that starts with `-` can still be deleted. It is the
            // only option accepted, and it is not a bypass of the confirmation.
            if it.next_if(|a| a == "--").is_none()
                && it.peek().is_some_and(|id| id.starts_with('-'))
            {
                return Err(Wrong::extra(it.next().unwrap_or_default()).into());
            }
            let id = it.next().ok_or(Wrong::Missing(KEY_ID))?;
            end(it)?;
            Ok(Command::Delete(id))
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
    /// An unknown command, or a line that is not a command at all.
    Usage,
    /// A command that needs arguments was given none: its short help is the answer.
    Bare(&'static str),
    /// The command line of this known command is wrong, and how.
    CommandUsage(&'static str, Wrong),
    BadId,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => f.write_str(&usage()),
            Self::Bare(name) => f.write_str(&help::short(name).unwrap_or_else(usage)),
            Self::CommandUsage(path, wrong) => write!(
                f,
                "custodio {path}: {wrong}\nRun 'custodio {path} --help' for help."
            ),
            Self::BadId => f.write_str("cannot derive a key id from the file name; use --id"),
        }
    }
}

impl std::error::Error for ArgError {}

/// Parse the arguments after the program name. Any option other than `--id` (for example
/// `--password`) is a usage error: secrets must not travel through argv.
///
/// # Errors
/// [`ArgError::Usage`] if the command is not `import`, [`ArgError::CommandUsage`] for anything
/// unexpected after it, [`ArgError::BadId`] if no id can be derived.
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<ImportArgs, ArgError> {
    let mut it = args.into_iter();
    if it.next().as_deref() != Some("import") {
        return Err(ArgError::Usage);
    }
    parse_import(it).map_err(|e| match e {
        Bad::Wrong(w) => ArgError::CommandUsage("import", w),
        Bad::BadId => ArgError::BadId,
    })
}

fn parse_import<I: Iterator<Item = String>>(mut it: I) -> Result<ImportArgs, Bad> {
    let mut file = None;
    let mut id = None;
    while let Some(arg) = it.next() {
        if arg == "--id" {
            let value = it.next().ok_or(Wrong::NoValue("--id"))?;
            if id.replace(value).is_some() {
                return Err(Wrong::Twice("--id").into());
            }
        } else if arg.starts_with('-') || file.is_some() {
            return Err(Wrong::extra(arg).into());
        } else {
            file = Some(PathBuf::from(arg));
        }
    }
    let file = file.ok_or(Wrong::Missing("<file.p12>"))?;
    let id = match id {
        Some(id) => id,
        None => default_id(&file).ok_or(Bad::BadId)?,
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
