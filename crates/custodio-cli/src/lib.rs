//! Custodio import tool: logic behind `custodio import <file.p12>`.
#![forbid(unsafe_code)]

use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

use custodiod::import::MAX_P12_LEN;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

pub mod bus;
pub mod tty;

pub const USAGE: &str = "usage: custodio import [--id <key id>] <file.p12>\n\
The password is asked on the terminal; it is never taken from arguments or the environment.";

/// Parsed command line.
#[derive(Debug, PartialEq, Eq)]
pub struct ImportArgs {
    pub file: PathBuf,
    pub id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ArgError {
    Usage,
    BadId,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => f.write_str(USAGE),
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

/// Where the password comes from. The real one is the controlling terminal.
pub trait PasswordPrompt {
    /// # Errors
    /// If there is no terminal or reading fails.
    fn password(&mut self, prompt: &str) -> io::Result<SecretString>;
}

/// The service side of `ImportP12`.
pub trait Importer {
    /// Returns the key type reported by the service.
    ///
    /// # Errors
    /// A message that is safe to show (never contains the password).
    fn import_p12(&self, id: &str, p12: &[u8], password: &SecretString) -> Result<String, String>;
}

#[derive(Debug)]
pub enum ImportFailure {
    Read(io::Error),
    TooLarge,
    Password(io::Error),
    Service(String),
}

impl fmt::Display for ImportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(e) => write!(f, "cannot read the file: {e}"),
            Self::TooLarge => write!(f, "the file is larger than {MAX_P12_LEN} bytes"),
            Self::Password(e) => write!(f, "cannot read the password: {e}"),
            Self::Service(m) => write!(f, "the service refused the import: {m}"),
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
    let kind = importer
        .import_p12(&args.id, &data, &password)
        .map_err(ImportFailure::Service)?;
    // Output errors must not hide the fact that the import happened.
    let _ = writeln!(out, "Imported key '{}' ({kind}).", args.id);
    let _ = writeln!(
        out,
        "Now delete the original file: it still holds your private key.\n  shred -u {}   (or remove it with your file manager and empty the trash)",
        args.file.display()
    );
    Ok(())
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
