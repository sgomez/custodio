//! `custodio list`: the caller's keys with id, key type, certificate subject and end of validity.
//!
//! The certificate comes from `ListKeys` as DER and is read here, on the client side. Whatever
//! the service or the certificate holds is untrusted text for a terminal: control characters are
//! written as `\xNN` escapes, never raw.

use std::fmt::{self, Write as _};
use std::io::{self, Write};

use x509_cert::Certificate;
use x509_cert::der::Decode;

use crate::failure::ServiceFailure;

/// What `custodio list` prints when the caller has no key.
pub const NO_KEYS: &str = "You have no keys in the custodio service.";

/// What stands in the place of the subject and the end of validity of a certificate that does not parse.
pub const UNREADABLE: &str = "certificate unreadable";

/// One element of the `ListKeys` reply.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyEntry {
    pub id: String,
    pub key_type: String,
    /// DER certificate. Never printed.
    pub certificate: Vec<u8>,
}

impl fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyEntry")
            .field("id", &self.id)
            .field("key_type", &self.key_type)
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

/// The two facts read from a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    pub subject: String,
    pub not_after: String,
}

/// Reads the subject (RFC 4514) and `notAfter` (`YYYY-MM-DDThh:mm:ssZ`); `None` if it does not parse.
#[must_use]
pub fn certificate_info(der: &[u8]) -> Option<CertificateInfo> {
    let cert = Certificate::from_der(der).ok()?;
    let tbs = cert.tbs_certificate();
    Some(CertificateInfo {
        subject: tbs.subject().to_string(),
        not_after: tbs.validity().not_after.to_string(),
    })
}

/// `text` with every control character as an escape (`\x1b`, `\x0a`, `\u{85}` stays `\x85`).
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            let _ = write!(out, "\\x{:02x}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// Why a run of `list` did not succeed.
#[derive(Debug)]
pub enum ListFailure {
    Service(ServiceFailure),
    /// This many keys were shown without subject and validity.
    Unreadable(usize),
    /// The output could not be written.
    Output(io::Error),
}

impl fmt::Display for ListFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service(failure) => write!(f, "{failure}"),
            Self::Unreadable(n) => write!(f, "{n} certificate(s) could not be read"),
            Self::Output(e) => write!(f, "cannot write the list: {e}"),
        }
    }
}

impl std::error::Error for ListFailure {}

/// Writes one block of four lines for a key.
///
/// # Errors
/// If writing fails.
pub fn write_entry<W: Write>(
    out: &mut W,
    id: &str,
    key_type: &str,
    info: Option<&CertificateInfo>,
) -> io::Result<()> {
    writeln!(out, "id: {}", escape(id))?;
    writeln!(out, "  type: {}", escape(key_type))?;
    if let Some(info) = info {
        writeln!(out, "  subject: {}", escape(&info.subject))?;
        writeln!(out, "  valid until: {}", escape(&info.not_after))
    } else {
        writeln!(out, "  subject: {UNREADABLE}")?;
        writeln!(out, "  valid until: {UNREADABLE}")
    }
}

/// Asks the service for the keys and writes them, sorted by id, or the none sentence.
///
/// # Errors
/// See [`ListFailure`]. A key whose certificate does not parse is still shown, and counted.
pub fn run_list<L: KeyLister, W: Write>(lister: &L, out: &mut W) -> Result<(), ListFailure> {
    let mut keys = lister.list_keys().map_err(ListFailure::Service)?;
    if keys.is_empty() {
        writeln!(out, "{NO_KEYS}").map_err(ListFailure::Output)?;
        return Ok(());
    }
    keys.sort_by(|a, b| a.id.cmp(&b.id));
    let mut unreadable = 0;
    for key in &keys {
        let info = certificate_info(&key.certificate);
        unreadable += usize::from(info.is_none());
        write_entry(out, &key.id, &key.key_type, info.as_ref()).map_err(ListFailure::Output)?;
    }
    if unreadable > 0 {
        return Err(ListFailure::Unreadable(unreadable));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
