//! Custodio import tool: logic behind `custodio import <file.p12>`.
#![forbid(unsafe_code)]

use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;

use custodio_client::{Kind, MAX_P12_LEN};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

pub use delete::{Confirmation, DeleteFailure, KeyDeleter, delete_command, run_delete};
pub use failure::ServiceFailure;
pub use help::{COMMANDS, CommandSpec, OptionSpec};
pub use list::{KeyEntry, KeyLister, ListArgs, ListFailure, Look, run_list, run_show};
pub use parse::{
    ArgError, Command, ImportArgs, Wrong, fuzz_cli_args, parse_args, parse_command, usage,
};
pub use storage::{StateStorage, StorageReader};

pub mod agent;
pub mod browser_files;
pub mod bus;
pub mod cert_text;
pub mod colour;
pub mod delete;
pub mod doctor_cmd;
pub mod doctor_decide;
pub mod doctor_later;
pub mod error;
pub mod failure;
pub mod fingerprint_cmd;
pub mod fingerprint_decide;
pub mod help;
pub mod journald_conf;
pub mod key_ids;
pub mod list;
pub mod parse;
pub mod register_cli;
pub mod register_discover;
mod register_modutil;
pub mod register_native;
pub mod register_snap;
pub mod report;
pub mod storage;
pub mod tty;

/// Where the password comes from. The real one is the controlling terminal.
pub trait PasswordPrompt {
    /// # Errors
    /// If there is no terminal or reading fails.
    fn password(&mut self, prompt: &str) -> io::Result<SecretString>;
}

/// The service side of `ImportP12`.
pub trait Importer {
    /// Returns the key type and the storage kind reported by the service.
    ///
    /// # Errors
    /// A [`ServiceFailure`]: it has a fixed message and never holds the password or the service's text.
    fn import_p12(
        &self,
        id: &str,
        p12: &[u8],
        password: &SecretString,
    ) -> Result<(String, Kind), ServiceFailure>;
}

#[derive(Debug)]
pub enum ImportFailure {
    Read(io::Error),
    TooLarge,
    Password(io::Error),
    Service(ServiceFailure),
}

impl fmt::Display for ImportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(e) => write!(f, "cannot read the file: {e}"),
            Self::TooLarge => write!(f, "the file is larger than {MAX_P12_LEN} bytes"),
            Self::Password(e) => write!(f, "cannot read the password: {e}"),
            Self::Service(failure) => write!(f, "{failure}"),
        }
    }
}

impl std::error::Error for ImportFailure {}

fn read_limited(path: &Path) -> Result<Zeroizing<Vec<u8>>, ImportFailure> {
    let file = File::open(path).map_err(ImportFailure::Read)?;
    let mut data = Zeroizing::new(Vec::new());
    let limit = u64::try_from(MAX_P12_LEN).map_err(|_| ImportFailure::TooLarge)?;
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(ImportFailure::Read)?;
    if data.len() > MAX_P12_LEN {
        return Err(ImportFailure::TooLarge);
    }
    Ok(data)
}

/// The note under a weaker or unknown storage kind; `None` for `tpm`.
fn kind_note(kind: &Kind) -> Option<&'static str> {
    match kind {
        Kind::Tpm => None,
        Kind::EncryptedTpm => Some("Root can use this key while the machine runs."),
        Kind::EncryptedHost => Some("Root, and anyone with a copy of /var/lib, can use this key."),
        Kind::Unknown(_) => Some("This CLI does not know this storage kind."),
    }
}

/// The line of an imported key: `ok` (`tpm`) or `warn` (any other kind), the key id, then type
/// and kind as `list` shows them; under it the kind's note and [`next_steps`].
#[must_use]
pub fn imported_line(
    id: &str,
    key_type: &str,
    kind: &Kind,
    file: &Path,
    home: Option<&Path>,
) -> report::Line {
    let note = kind_note(kind);
    let state = if note.is_some() {
        report::State::Warn
    } else {
        report::State::Ok
    };
    let mut line = report::Line::new(
        state,
        cert_text::escape(id),
        format!(
            "{}  {}",
            cert_text::escape(key_type),
            cert_text::escape(kind.wire())
        ),
    );
    line.under.extend(note.map(str::to_owned));
    line.under.extend(next_steps(file, home));
    line
}

/// What to do after an import: delete the original, restart Firefox.
#[must_use]
pub fn next_steps(file: &Path, home: Option<&Path>) -> [String; 2] {
    [
        format!(
            "Delete the original: shred -u {}",
            report::shell_path(file, home)
        ),
        "Restart Firefox, and any program using Custodio, to see the key.".to_owned(),
    ]
}

/// Read the file, ask for the password, send both to the service, then show the key and the next
/// steps. Those are printed only after the service accepted the import.
///
/// # Errors
/// See [`ImportFailure`].
pub fn run_import<P: PasswordPrompt, I: Importer, W: Write>(
    args: &ImportArgs,
    prompt: &mut P,
    importer: &I,
    out: &mut W,
) -> Result<(), ImportFailure> {
    import_painted(args, prompt, importer, out, false)
}

fn import_painted<P: PasswordPrompt, I: Importer, W: Write>(
    args: &ImportArgs,
    prompt: &mut P,
    importer: &I,
    out: &mut W,
    colour: bool,
) -> Result<(), ImportFailure> {
    let data = read_limited(&args.file)?;
    let password = prompt
        .password(&format!("Password for {}: ", args.file.display()))
        .map_err(ImportFailure::Password)?;
    let (key_type, kind) = importer
        .import_p12(&args.id, &data, &password)
        .map_err(ImportFailure::Service)?;
    // Output errors must not hide the fact that the import happened.
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let line = imported_line(&args.id, &key_type, &kind, &args.file, home.as_deref());
    let _ = write!(out, "{}", report::render(&[line], colour));
    Ok(())
}

/// `custodio import`: [`run_import`], in colour if `colour`, then the storage warning on `err`
/// when the import succeeded.
///
/// # Errors
/// See [`ImportFailure`]; the warning never adds one.
pub fn import_command<P: PasswordPrompt, I: Importer, S: StorageReader, W: Write, E: Write>(
    args: &ImportArgs,
    prompt: &mut P,
    importer: &I,
    storage: &S,
    out: &mut W,
    err: &mut E,
    colour: bool,
) -> Result<(), ImportFailure> {
    import_painted(args, prompt, importer, out, colour)?;
    storage::warn(storage, err, colour);
    Ok(())
}

/// `custodio list`: [`run_show`] for a key id, [`run_list`] otherwise, then the storage warning on `err`
/// when the keys were shown without error.
///
/// # Errors
/// See [`ListFailure`]; the warning never adds one.
pub fn list_command<L: KeyLister, S: StorageReader, W: Write, E: Write>(
    lister: &L,
    storage: &S,
    args: &ListArgs,
    look: Look,
    out: &mut W,
    err: &mut E,
) -> Result<(), ListFailure> {
    match &args.id {
        Some(id) => run_show(lister, id, out, look)?,
        None => run_list(lister, out, look, args.verbose)?,
    }
    storage::warn(storage, err, look.colour);
    Ok(())
}

/// Everything that can end a run of the tool without success.
#[derive(Debug)]
pub enum CliError {
    /// The command line is wrong: the usage text, exit status 2.
    Args(ArgError),
    /// The system bus cannot be reached.
    SystemBus(String),
    Import(ImportFailure),
    List(ListFailure),
    Delete(DeleteFailure),
    Register(register_native::RegisterError),
    Fingerprint(fingerprint_cmd::Failure),
    Doctor(doctor_cmd::Failure),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Args(e) => write!(f, "{e}"),
            Self::SystemBus(why) => write!(f, "custodio: cannot reach the system bus: {why}"),
            Self::Import(e) => write!(f, "custodio: {e}"),
            Self::List(e) => write!(f, "custodio: {e}"),
            Self::Delete(e) => write!(f, "custodio: {e}"),
            Self::Register(e) => write!(f, "{e}"),
            Self::Fingerprint(e) => write!(f, "{e}"),
            Self::Doctor(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CliError {}

/// Exit status of a run: 0 on success, 2 for a usage error, 1 for every other failure.
#[must_use]
pub const fn exit_status(result: &Result<(), CliError>) -> u8 {
    match result {
        Ok(()) => 0,
        Err(
            CliError::Args(_)
            | CliError::Register(register_native::RegisterError::Refused(_))
            | CliError::Doctor(doctor_cmd::Failure::Root),
        ) => 2,
        Err(
            CliError::SystemBus(_)
            | CliError::Import(_)
            | CliError::List(_)
            | CliError::Delete(_)
            | CliError::Register(_)
            | CliError::Fingerprint(_)
            | CliError::Doctor(
                doctor_cmd::Failure::BrokenInclude | doctor_cmd::Failure::Unsatisfied(_),
            ),
        ) => 1,
    }
}

/// Writes the diagnostic of a failed run to `err` (nothing on success, nor after a doctor report)
/// and returns the exit status.
/// `coloured` puts the `custodio:` prefix of the first line in bold.
pub fn finish<W: Write>(result: &Result<(), CliError>, err: &mut W, coloured: bool) -> u8 {
    match result {
        // The report on standard output already ends with how many problems there are.
        Ok(())
        | Err(CliError::Doctor(
            doctor_cmd::Failure::BrokenInclude | doctor_cmd::Failure::Unsatisfied(_),
        )) => {}
        Err(e) => {
            let _ = writeln!(err, "{}", colour::prefix(&error::render(e), coloured));
        }
    }
    exit_status(result)
}

/// Read one line without the newline into zeroizing storage.
///
/// # Errors
/// On I/O errors, invalid UTF-8, or end of input before any byte.
pub fn read_secret_line<R: BufRead>(reader: &mut R) -> io::Result<SecretString> {
    let mut raw = Zeroizing::new(Vec::new());
    if reader.read_until(b'\n', &mut raw)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no input"));
    }
    while matches!(raw.last(), Some(b'\n' | b'\r')) {
        raw.pop();
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "password is not valid UTF-8"))?;
    let secret = SecretString::from(text.to_owned());
    debug_assert_eq!(secret.expose_secret().len(), raw.len());
    Ok(secret)
}
