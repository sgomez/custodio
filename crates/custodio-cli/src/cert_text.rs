//! The fields `custodio list` shows, read from a certificate's DER on the client side.
//!
//! Everything a certificate holds, and everything the service reports, is untrusted text for a
//! terminal. Every function here returns text that is already safe to print: no control character
//! (C0, DEL, C1), no line or paragraph separator, no bidirectional or other invisible format
//! character, no private-use or tag character. Such a character is written as a visible escape
//! (`\x1b`, `\u{202e}`), so a field cannot move the cursor, change colours, reorder the text or
//! start a line or a row of its own. Input that does not parse never panics: each field is then
//! [`UNREADABLE`].

use std::fmt::Write as _;

use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
use x509_cert::name::Name;

/// What stands in the place of a field of a certificate that does not parse.
pub const UNREADABLE: &str = "certificate unreadable";

/// The object identifier of `commonName`.
const COMMON_NAME: &str = "2.5.4.3";

/// The fields of one certificate, each one safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFields {
    /// The whole subject, RFC 4514.
    pub subject: String,
    /// The subject as the table shows it: its common name, or the whole subject if it has none.
    pub subject_short: String,
    /// The whole issuer, RFC 4514.
    pub issuer: String,
    /// The serial number in uppercase hexadecimal.
    pub serial: String,
    /// `YYYY-MM-DDThh:mm:ssZ`.
    pub not_before: String,
    /// `YYYY-MM-DDThh:mm:ssZ`.
    pub not_after: String,
    /// SHA-256 of the DER, as OpenSSL prints it: uppercase hexadecimal pairs joined by `:`.
    pub fingerprint: String,
}

impl CertFields {
    fn unreadable() -> Self {
        let u = || UNREADABLE.to_owned();
        Self {
            subject: u(),
            subject_short: u(),
            issuer: u(),
            serial: u(),
            not_before: u(),
            not_after: u(),
            fingerprint: u(),
        }
    }
}

/// Whether a character is written as an escape instead of itself.
fn must_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{ad}'
                | '\u{61c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{fffe}'
                | '\u{ffff}'
                | '\u{e000}'..='\u{f8ff}'
                | '\u{e0000}'..='\u{e007f}'
                | '\u{f0000}'..='\u{10ffff}'
        )
}

/// `text` with every character that could drive a terminal or hide something as an escape: `\xNN`
/// up to U+00FF, `\u{N}` above.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let n = u32::from(c);
        if !must_escape(c) {
            out.push(c);
        } else if n <= 0xff {
            let _ = write!(out, "\\x{n:02x}");
        } else {
            let _ = write!(out, "\\u{{{n:x}}}");
        }
    }
    out
}

fn string_value(value: &x509_cert::der::Any) -> Option<String> {
    if let Ok(s) = value.decode_as::<Utf8StringRef<'_>>() {
        return Some(s.as_str().to_owned());
    }
    if let Ok(s) = value.decode_as::<PrintableStringRef<'_>>() {
        return Some(s.as_str().to_owned());
    }
    if let Ok(s) = value.decode_as::<Ia5StringRef<'_>>() {
        return Some(s.as_str().to_owned());
    }
    value
        .decode_as::<TeletexStringRef<'_>>()
        .ok()
        .map(|s| s.as_str().to_owned())
}

/// The first common name of `name` that is readable text and not empty.
fn common_name(name: &Name) -> Option<String> {
    name.iter()
        .filter(|atv| atv.oid.to_string() == COMMON_NAME)
        .filter_map(|atv| string_value(&atv.value))
        .find(|cn| !cn.is_empty())
}

fn hex(bytes: &[u8], separator: &str) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(separator);
        }
        let _ = write!(out, "{b:02X}");
    }
    out
}

/// Reads the fields from `der`. Any input is accepted; one that is not exactly one certificate gives
/// [`UNREADABLE`] in every field.
#[must_use]
pub fn fields(der: &[u8]) -> CertFields {
    let Ok(cert) = Certificate::from_der(der) else {
        return CertFields::unreadable();
    };
    let tbs = cert.tbs_certificate();
    let subject = escape(&tbs.subject().to_string());
    let subject_short =
        common_name(tbs.subject()).map_or_else(|| subject.clone(), |cn| escape(&cn));
    CertFields {
        subject,
        subject_short,
        issuer: escape(&tbs.issuer().to_string()),
        serial: hex(tbs.serial_number().as_bytes(), ""),
        not_before: escape(&tbs.validity().not_before.to_string()),
        not_after: escape(&tbs.validity().not_after.to_string()),
        fingerprint: hex(&Sha256::digest(der), ":"),
    }
}

/// Entry point for the fuzz target: any bytes through [`fields`] and [`escape`]. Panics (so the fuzzer
/// notices) if a field could drive the terminal. Returns whether the bytes were a certificate.
///
/// # Panics
/// If a field holds a character that [`escape`] would have escaped.
#[must_use]
pub fn fuzz_cert_fields(data: &[u8]) -> bool {
    let f = fields(data);
    let all = [
        &f.subject,
        &f.subject_short,
        &f.issuer,
        &f.serial,
        &f.not_before,
        &f.not_after,
        &f.fingerprint,
        &escape(&String::from_utf8_lossy(data)),
    ];
    for text in all {
        assert!(
            !text.chars().any(must_escape),
            "a field holds a character that could drive a terminal"
        );
    }
    f.fingerprint != UNREADABLE
}
