//! `custodio list`: a table of the caller's keys, and `custodio list <id>`: one key in full.
//!
//! The certificate comes from `ListKeys` as DER and is read here, on the client side
//! ([`crate::cert_text`]); `list <id>` picks its key from the same reply, there is no other call.
//! Whatever the service or the certificate holds is untrusted text for a terminal: every cell is
//! escaped, so a cell never holds a line end and a key is always exactly one row.

use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::time::{Duration, SystemTime};

use custodio_client::Kind;

use crate::cert_text::{CertFields, UNREADABLE, escape, fields};
use crate::colour::{self, Paint};
use crate::failure::ServiceFailure;

/// What `custodio list` prints when the caller has no key.
pub const NO_KEYS: &str = "You have no keys in the custodio service.";

/// What follows [`NO_KEYS`] on the next line.
pub const NONE_HINT: &str = "Import one with: custodio import <file.p12>";

/// The note at the foot of the table when a key is `encrypted-tpm` or `encrypted-host`. Only the table has it.
pub const WEAKER_NOTE: &str = "Note: encrypted-tpm and encrypted-host keys are files that root can use while the machine runs.";

/// How close to its end of validity a key is marked `expires soon`.
pub const SOON: Duration = Duration::from_hours(30 * 24);

/// How the output looks: the header row only on a terminal (a script reads every line as a key),
/// colour, and the time expiry is judged against.
#[derive(Debug, Clone, Copy)]
pub struct Look {
    pub terminal: bool,
    pub colour: bool,
    pub now: SystemTime,
}

impl Look {
    /// Neither a terminal nor colour: what a script gets.
    #[must_use]
    pub const fn plain(now: SystemTime) -> Self {
        Self {
            terminal: false,
            colour: false,
            now,
        }
    }
}

/// Where a key stands against its end of validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    Valid,
    Soon,
    Expired,
}

impl Expiry {
    /// `None` when the certificate gives no time.
    #[must_use]
    pub fn of(expires: Option<SystemTime>, now: SystemTime) -> Option<Self> {
        let end = expires?;
        Some(if end <= now {
            Self::Expired
        } else if end.duration_since(now).unwrap_or_default() <= SOON {
            Self::Soon
        } else {
            Self::Valid
        })
    }

    /// The mark after the date, coloured when `on`; empty for a valid key.
    fn mark(self, on: bool) -> String {
        match self {
            Self::Valid => String::new(),
            Self::Soon => colour::paint("expires soon", Paint::Yellow, on),
            Self::Expired => colour::paint("expired", Paint::Red, on),
        }
    }
}

/// `YYYY-MM-DDThh:mm:ssZ` as `YYYY-MM-DD hh:mm:ss UTC`; anything else unchanged.
fn readable_time(t: &str) -> String {
    match t.strip_suffix('Z').and_then(|t| t.split_once('T')) {
        Some((day, time)) if day.len() == 10 && time.len() == 8 => format!("{day} {time} UTC"),
        _ => t.to_owned(),
    }
}

/// The day of a `YYYY-MM-DDThh:mm:ssZ` time; anything else unchanged.
fn day(t: &str) -> String {
    match t.split_once('T') {
        Some((day, _)) if day.len() == 10 => day.to_owned(),
        _ => t.to_owned(),
    }
}

/// The command line of `custodio list`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListArgs {
    /// Show this key in full.
    pub id: Option<String>,
    /// Show every key in full (`-v`, `--verbose`).
    pub verbose: bool,
}

/// One element of the `ListKeys` reply.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyEntry {
    pub id: String,
    pub key_type: String,
    pub kind: Kind,
    /// DER certificate. Never printed.
    pub certificate: Vec<u8>,
}

impl fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyEntry")
            .field("id", &self.id)
            .field("key_type", &self.key_type)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// The service side of `ListKeys`.
pub trait KeyLister {
    /// The caller's keys, in any order.
    ///
    /// # Errors
    /// A [`ServiceFailure`], with a fixed message.
    fn list_keys(&self) -> Result<Vec<KeyEntry>, ServiceFailure>;
}

/// Why a run of `list` did not succeed.
#[derive(Debug)]
pub enum ListFailure {
    Service(ServiceFailure),
    /// This many keys were shown without subject and validity.
    Unreadable(usize),
    /// `list <id>` for an id the caller does not have.
    UnknownId(String),
    /// The output could not be written.
    Output(io::Error),
}

impl fmt::Display for ListFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service(failure) => write!(f, "{failure}"),
            Self::Unreadable(n) => write!(f, "{n} certificate(s) could not be read"),
            Self::UnknownId(id) => write!(f, "you have no key with the id '{}'", escape(id)),
            Self::Output(e) => write!(f, "cannot write the list: {e}"),
        }
    }
}

impl std::error::Error for ListFailure {}

/// Whether a kind is one `custodio list` explains: weaker than a TPM key.
fn is_weaker(kind: &Kind) -> bool {
    matches!(kind, Kind::EncryptedHost | Kind::EncryptedTpm)
}

/// Whether the certificate parsed.
fn is_readable(fields: &CertFields) -> bool {
    fields.fingerprint != UNREADABLE
}

/// The header of the table, shown on a terminal only.
pub const HEADER: [&str; 5] = ["ID", "TYPE", "STORAGE", "SUBJECT", "EXPIRES"];

/// One row per key, in the order given: id, type, kind, subject, day of the end of validity and, for a key
/// that has expired or soon will, a mark. Columns are padded to their widest cell, the last has no padding.
/// Every cell is escaped, so a row is one line. On a terminal a header row comes first.
#[must_use]
pub fn table(keys: &[KeyEntry], look: Look) -> String {
    let rows: Vec<([String; 5], String)> = keys
        .iter()
        .map(|key| {
            let f = fields(&key.certificate);
            let mark =
                Expiry::of(f.expires, look.now).map_or_else(String::new, |e| e.mark(look.colour));
            (
                [
                    escape(&key.id),
                    escape(&key.key_type),
                    escape(key.kind.wire()),
                    f.subject_short,
                    day(&f.not_after),
                ],
                mark,
            )
        })
        .collect();
    let header = look
        .terminal
        .then(|| (HEADER.map(str::to_owned), String::new()));
    let mut widths = [0; 5];
    for (row, _) in header.iter().chain(&rows) {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for (i, (row, mark)) in header.iter().chain(&rows).enumerate() {
        let mut line = String::new();
        for (cell, width) in row.iter().zip(widths) {
            let _ = write!(line, "{cell:<width$}  ");
        }
        line.push_str(mark);
        let line = line.trim_end();
        if i == 0 && header.is_some() {
            out.push_str(&colour::bold(line, look.colour));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// One key in full: the id as a title, then every field indented under it, the subject and issuer
/// whole, the start and end of validity each on its line.
#[must_use]
pub fn view(key: &KeyEntry, look: Look) -> String {
    let f = fields(&key.certificate);
    let mut not_after = readable_time(&f.not_after);
    if let Some(e) = Expiry::of(f.expires, look.now).filter(|e| *e != Expiry::Valid) {
        not_after = format!("{not_after}  {}", e.mark(look.colour));
    }
    let mut out = format!("{}\n", colour::bold(&escape(&key.id), look.colour));
    for (label, value) in [
        ("type", escape(&key.key_type)),
        ("storage", escape(key.kind.wire())),
        ("subject", f.subject),
        ("issuer", f.issuer),
        ("serial", f.serial),
        ("not before", readable_time(&f.not_before)),
        ("not after", not_after),
        ("SHA-256", f.fingerprint),
    ] {
        let _ = writeln!(out, "  {label:<10}  {value}");
    }
    out
}

/// Asks the service for the keys and writes them sorted by id, as the table or, `verbose`, each in full;
/// or the none sentence.
///
/// # Errors
/// See [`ListFailure`]. A key whose certificate does not parse is still shown, and counted.
pub fn run_list<L: KeyLister, W: Write>(
    lister: &L,
    out: &mut W,
    look: Look,
    verbose: bool,
) -> Result<(), ListFailure> {
    let mut keys = lister.list_keys().map_err(ListFailure::Service)?;
    if keys.is_empty() {
        writeln!(out, "{NO_KEYS}\n{NONE_HINT}").map_err(ListFailure::Output)?;
        return Ok(());
    }
    keys.sort_by(|a, b| a.id.cmp(&b.id));
    let mut text = if verbose {
        let blocks: Vec<String> = keys.iter().map(|k| view(k, look)).collect();
        blocks.join("\n")
    } else {
        table(&keys, look)
    };
    if !verbose && keys.iter().any(|k| is_weaker(&k.kind)) {
        let _ = writeln!(text, "\n{WEAKER_NOTE}");
    }
    out.write_all(text.as_bytes())
        .map_err(ListFailure::Output)?;
    let unreadable = keys
        .iter()
        .filter(|k| !is_readable(&fields(&k.certificate)))
        .count();
    if unreadable > 0 {
        return Err(ListFailure::Unreadable(unreadable));
    }
    Ok(())
}

/// Like [`run_list`] for one key, chosen from the same reply.
///
/// # Errors
/// See [`ListFailure`]; [`ListFailure::UnknownId`] if the caller has no key `id`.
pub fn run_show<L: KeyLister, W: Write>(
    lister: &L,
    id: &str,
    out: &mut W,
    look: Look,
) -> Result<(), ListFailure> {
    let keys = lister.list_keys().map_err(ListFailure::Service)?;
    let key = keys
        .iter()
        .find(|k| k.id == id)
        .ok_or_else(|| ListFailure::UnknownId(id.to_owned()))?;
    out.write_all(view(key, look).as_bytes())
        .map_err(ListFailure::Output)?;
    if is_readable(&fields(&key.certificate)) {
        Ok(())
    } else {
        Err(ListFailure::Unreadable(1))
    }
}

#[cfg(test)]
mod tests;
