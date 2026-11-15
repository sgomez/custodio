//! Custodio import tool: logic behind `custodio import <file.p12>`.
#![forbid(unsafe_code)]

use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;

use custodio_client::{Kind, MAX_P12_LEN};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

pub use delete::{Confirmation, DeleteFailure, KeyDeleter, run_delete};
pub use failure::ServiceFailure;
pub use help::{COMMANDS, CommandSpec, OptionSpec};
pub use list::{KeyEntry, KeyLister, ListFailure, run_list};
pub use parse::{ArgError, Command, ImportArgs, USAGE, fuzz_cli_args, parse_args, parse_command};
pub use storage::{StateStorage, StorageReader};

pub mod agent;
pub mod browser_files;
pub mod bus;
pub mod colour;
pub mod delete;
pub mod error;
pub mod failure;
pub mod help;
pub mod list;
pub mod parse;
pub mod register_cli;
pub mod register_discover;
mod register_modutil;
pub mod register_native;
pub mod register_snap;
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

/// What the person is told about where the key now lives. The reason of a weaker kind comes from
/// the kind alone: the import result names no missing capability.
fn kind_text(kind: &Kind) -> String {
    match kind {
        Kind::Tpm => "Storage: tpm. The key is in the TPM and cannot be copied out of it.".to_owned(),
        Kind::EncryptedHost => "Storage: encrypted-host. This key is weaker than a TPM key: this machine has no TPM, so the key is \
a file encrypted with the host key. Root, and anyone with a copy of /var/lib, can use it."
            .to_owned(),
        Kind::EncryptedTpm => "Storage: encrypted-tpm. This key is weaker than a TPM key: the TPM of this machine lacks a capability \
the key type needs, so the key is a file encrypted with a key bound to this TPM. Root can use it while the machine runs.\n\
See \"TPM capabilities\" in docs/api.md for what each key type needs."
            .to_owned(),
        Kind::Unknown(text) => format!(
            "Storage: {}. This CLI does not know this kind, so it cannot say what the key is protected against.",
            list::escape(text)
        ),
    }
}

/// The sentence `custodio list` adds under a key whose kind is weaker than a TPM key: the reason
/// of [`kind_text`], without its `Storage:` prefix and without the pointer line. A `tpm` key and a
/// kind this CLI does not know get none.
pub(crate) fn weaker_note(kind: &Kind) -> Option<String> {
    if !matches!(kind, Kind::EncryptedHost | Kind::EncryptedTpm) {
        return None;
    }
    let text = kind_text(kind);
    let first = text.lines().next()?;
    first.split_once(". ").map(|(_, reason)| reason.to_owned())
}

/// Read the file, ask for the password, send both to the service, then tell the person to delete
/// the original. The reminder is printed only after the service accepted the import.
///
/// # Errors
/// See [`ImportFailure`].
pub fn run_import<P: PasswordPrompt, I: Importer, W: Write>(
    args: &ImportArgs,
    prompt: &mut P,
    importer: &I,
    out: &mut W,
) -> Result<(), ImportFailure> {
    let data = read_limited(&args.file)?;
    let password = prompt
        .password(&format!("Password for {}: ", args.file.display()))
        .map_err(ImportFailure::Password)?;
    let (key_type, kind) = importer
        .import_p12(&args.id, &data, &password)
        .map_err(ImportFailure::Service)?;
    // Output errors must not hide the fact that the import happened.
    let _ = writeln!(
        out,
        "Imported key '{}' ({}).",
        args.id,
        list::escape(&key_type)
    );
    let _ = writeln!(out, "{}", kind_text(&kind));
    let _ = writeln!(
        out,
        "Now delete the original file: it still holds your private key.\n  shred -u {}   (or remove it with your file manager and empty the trash)",
        args.file.display()
    );
    Ok(())
}

/// `custodio import`: [`run_import`], then the storage warning on `err` when the import succeeded.
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
) -> Result<(), ImportFailure> {
    run_import(args, prompt, importer, out)?;
    storage::warn(storage, err);
    Ok(())
}

/// `custodio list`: [`run_list`], then the storage warning on `err` when the list was shown without error.
///
/// # Errors
/// See [`ListFailure`]; the warning never adds one.
pub fn list_command<L: KeyLister, S: StorageReader, W: Write, E: Write>(
    lister: &L,
    storage: &S,
    out: &mut W,
    err: &mut E,
) -> Result<(), ListFailure> {
    run_list(lister, out)?;
    storage::warn(storage, err);
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
        }
    }
}

impl std::error::Error for CliError {}

/// Exit status of a run: 0 on success, 2 for a usage error, 1 for every other failure.
#[must_use]
pub const fn exit_status(result: &Result<(), CliError>) -> u8 {
    match result {
        Ok(()) => 0,
        Err(CliError::Args(_) | CliError::Register(register_native::RegisterError::Refused(_))) => {
            2
        }
        Err(
            CliError::SystemBus(_)
            | CliError::Import(_)
            | CliError::List(_)
            | CliError::Delete(_)
            | CliError::Register(_),
        ) => 1,
    }
}

/// Writes the diagnostic of a failed run to `err` (nothing on success) and returns the exit status.
/// `coloured` puts the `custodio:` prefix of the first line in bold.
pub fn finish<W: Write>(result: &Result<(), CliError>, err: &mut W, coloured: bool) -> u8 {
    if let Err(e) = result {
        let _ = writeln!(err, "{}", colour::prefix(&error::render(e), coloured));
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
