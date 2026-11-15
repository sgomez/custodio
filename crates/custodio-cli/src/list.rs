//! `custodio list`: a table of the caller's keys, and `custodio list <id>`: one key in full.
//!
//! The certificate comes from `ListKeys` as DER and is read here, on the client side
//! ([`crate::cert_text`]); `list <id>` picks its key from the same reply, there is no other call.
//! Whatever the service or the certificate holds is untrusted text for a terminal: every cell is
//! escaped, so a cell never holds a line end and a key is always exactly one row.

use std::fmt::{self, Write as _};
use std::io::{self, Write};

use custodio_client::Kind;

use crate::cert_text::{CertFields, UNREADABLE, escape, fields};
use crate::failure::ServiceFailure;

/// What `custodio list` prints when the caller has no key.
pub const NO_KEYS: &str = "You have no keys in the custodio service.";

/// What follows [`NO_KEYS`] on the next line.
pub const NONE_HINT: &str = "Import one with: custodio import <file.p12>";

/// The note at the foot of the table when a key is `encrypted-tpm` or `encrypted-host`. Only the table has it.
pub const WEAKER_NOTE: &str = "Note: a key of kind encrypted-tpm or encrypted-host is weaker than a tpm key: it is a file that root can use \
while the machine runs. See README.md#storage-kinds.";

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

/// The end of validity as the table shows it.
fn is_readable(fields: &CertFields) -> bool {
    fields.fingerprint != UNREADABLE
}

/// One row per key, in the order given: id, type, kind, subject, end of validity. Columns are padded to
/// their widest cell, the last has no padding. Every cell is escaped, so a row is one line.
#[must_use]
pub fn table(keys: &[KeyEntry]) -> String {
    let rows: Vec<[String; 5]> = keys
        .iter()
        .map(|key| {
            let f = fields(&key.certificate);
            [
                escape(&key.id),
                escape(&key.key_type),
                escape(key.kind.wire()),
                f.subject_short,
                f.not_after,
            ]
        })
        .collect();
    let mut widths = [0; 5];
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in &rows {
        for (cell, width) in row.iter().zip(widths) {
            let _ = write!(out, "{cell:<width$}  ");
        }
        out.truncate(out.trim_end().len());
        out.push('\n');
    }
    out
}

/// One key in full: everything of its row, then issuer, serial, start of validity and fingerprint.
#[must_use]
pub fn view(key: &KeyEntry) -> String {
    let f = fields(&key.certificate);
    let mut out = String::new();
    for (label, value) in [
        ("id", escape(&key.id)),
        ("type", escape(&key.key_type)),
        ("kind", escape(key.kind.wire())),
        ("subject", f.subject),
        ("issuer", f.issuer),
        ("serial", f.serial),
        ("valid from", f.not_before),
        ("valid until", f.not_after),
        ("SHA-256", f.fingerprint),
    ] {
        let _ = writeln!(out, "{label:<12}{value}");
    }
    out
}

/// Asks the service for the keys and writes the table, sorted by id, or the none sentence.
///
/// # Errors
/// See [`ListFailure`]. A key whose certificate does not parse is still shown, and counted.
pub fn run_list<L: KeyLister, W: Write>(lister: &L, out: &mut W) -> Result<(), ListFailure> {
    let mut keys = lister.list_keys().map_err(ListFailure::Service)?;
    if keys.is_empty() {
        writeln!(out, "{NO_KEYS}\n{NONE_HINT}").map_err(ListFailure::Output)?;
        return Ok(());
    }
    keys.sort_by(|a, b| a.id.cmp(&b.id));
    let mut text = table(&keys);
    if keys.iter().any(|k| is_weaker(&k.kind)) {
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
) -> Result<(), ListFailure> {
    let keys = lister.list_keys().map_err(ListFailure::Service)?;
    let key = keys
        .iter()
        .find(|k| k.id == id)
        .ok_or_else(|| ListFailure::UnknownId(id.to_owned()))?;
    out.write_all(view(key).as_bytes())
        .map_err(ListFailure::Output)?;
    if is_readable(&fields(&key.certificate)) {
        Ok(())
    } else {
        Err(ListFailure::Unreadable(1))
    }
}

#[cfg(test)]
mod tests;
