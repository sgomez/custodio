//! The fields `custodio list` shows, read from a certificate's DER: the values of real certificates
//! (compared with what OpenSSL prints for the same files), and certificates and bytes that are
//! hostile or broken. No field may hold a character that could drive a terminal or start a line.

use custodio_cli::cert_text::{UNREADABLE, escape, fields};

const P256: &[u8] = include_bytes!("../../custodio-it/tests/fixtures/cert-p256-other.der");
const RSA: &[u8] = include_bytes!("../../custodio-it/tests/fixtures/cert-rsa3072.der");
const HOSTILE: &[u8] =
    include_bytes!("../../custodio-it/tests/fixtures/cert-p256-other-hostile.der");

/// True if `text` could not move the cursor, start a line or change the text direction.
fn harmless(text: &str) -> bool {
    text.chars().all(|c| {
        !c.is_control()
            && !matches!(c, '\u{ad}' | '\u{61c}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{e000}'..='\u{f8ff}'
                | '\u{e0000}'..='\u{e007f}')
    })
}

#[test]
fn the_fields_of_a_real_certificate_are_what_openssl_prints() {
    // `openssl x509 -inform DER -noout -serial -fingerprint -sha256 -subject -issuer -startdate -enddate`
    let f = fields(P256);
    assert_eq!(f.subject, "CN=custodio test p256-other");
    assert_eq!(f.subject_short, "custodio test p256-other");
    assert_eq!(f.issuer, "CN=custodio test p256-other");
    assert_eq!(f.serial, "1A0DA9C946F9D0B76E0B1925A0550BE816DF3D21");
    assert_eq!(f.not_before, "2026-10-27T16:05:48Z");
    assert_eq!(f.not_after, "2126-10-03T16:05:48Z");
    assert_eq!(
        f.fingerprint,
        "51:30:3C:19:FF:27:E3:D4:BC:4D:9A:80:56:59:DD:A6:AF:75:47:E3:C1:80:27:64:B8:58:3F:BD:0E:70:D6:42"
    );
    let r = fields(RSA);
    assert_eq!(r.subject_short, "custodio test rsa3072");
    assert_eq!(r.serial, "0513024ADC13F297B8955D6C9DBC7A0DA76DA895");
    assert_eq!(
        r.fingerprint,
        "8F:9B:96:DF:38:61:78:DB:6D:13:D0:4F:71:51:D2:16:0A:A6:E4:C0:42:1E:2D:D9:77:7D:B7:50:2D:03:E8:37"
    );
}

#[test]
fn a_hostile_subject_and_issuer_are_escaped_and_still_readable() {
    let f = fields(HOSTILE);
    assert_eq!(f.serial, "1095");
    assert_eq!(f.subject_short, "a\\x1b[31mb\\x0ac\\x7fd");
    // The whole names are RFC 4514: the X.509 library writes the C0 controls and DEL as `\1b`, the rest is ours.
    assert_eq!(f.subject, "O=x\\01y,CN=a\\1b[31mb\\0ac\\7fd");
    assert!(
        f.issuer.contains("CN=ca\\1b]0\\;pwn\\07\\0a\\7fCA"),
        "{}",
        f.issuer
    );
    assert!(
        f.issuer.contains("O=i\\01\\x85ssuer\\u{202e}"),
        "{}",
        f.issuer
    );
    for text in [
        &f.subject,
        &f.subject_short,
        &f.issuer,
        &f.serial,
        &f.fingerprint,
    ] {
        assert!(harmless(text), "{text:?}");
        assert!(text.chars().all(|c| c != '\n' && c != '\u{1b}'), "{text:?}");
    }
}

#[test]
fn the_predicate_fails_on_an_unescaped_sample() {
    assert!(!harmless("CN=a\nb"));
    assert!(!harmless("CN=\u{1b}[31m"));
    assert!(!harmless("CN=\u{85}"));
    assert!(!harmless("CN=\u{202e}"));
    assert!(harmless(&escape("CN=a\nb\u{1b}\u{85}\u{202e}")));
}

#[test]
fn escape_writes_every_non_printable_char_as_a_visible_escape() {
    assert_eq!(escape("plain é 日本"), "plain é 日本");
    assert_eq!(escape("a\nb"), "a\\x0ab");
    assert_eq!(escape("\x1b\x7f\u{9f}"), "\\x1b\\x7f\\x9f");
    assert_eq!(
        escape("\u{202e}\u{200b}\u{feff}\u{2028}"),
        "\\u{202e}\\u{200b}\\u{feff}\\u{2028}"
    );
    assert_eq!(escape("\u{e0041}\u{e000}"), "\\u{e0041}\\u{e000}");
    assert_eq!(escape("\u{ad}\u{61c}\u{2066}"), "\\xad\\u{61c}\\u{2066}");
    // The escape itself is not escaped twice.
    assert_eq!(escape(&escape("\n")), "\\x0a");
}

fn all_placeholders(der: &[u8]) {
    let f = fields(der);
    for text in [
        &f.subject,
        &f.subject_short,
        &f.issuer,
        &f.serial,
        &f.not_before,
        &f.not_after,
        &f.fingerprint,
    ] {
        assert_eq!(text, UNREADABLE, "{der:?}");
    }
}

#[test]
fn broken_der_gives_a_placeholder_for_every_field() {
    all_placeholders(b"");
    all_placeholders(b"not a certificate");
    all_placeholders(&P256[..P256.len() - 5]);
    all_placeholders(&P256[..3]);
    // Trailing bytes.
    let mut trailing = P256.to_vec();
    trailing.extend_from_slice(b"\x00\x01");
    all_placeholders(&trailing);
    // Wrong outer tag, and a length that claims far more than there is.
    let mut tag = P256.to_vec();
    tag[0] = 0x31;
    all_placeholders(&tag);
    all_placeholders(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x01]);
    all_placeholders(&[0x30, 0x80]);
    all_placeholders(&[0xff; 64]);
}

/// Replaces the bytes of `needle` in the certificate by `with` (same length: the DER stays valid).
fn patched(der: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), with.len());
    let mut out = der.to_vec();
    let at = out
        .windows(needle.len())
        .rposition(|w| w == needle)
        .expect("the needle is in the certificate");
    out[at..at + needle.len()].copy_from_slice(with);
    out
}

#[test]
fn invalid_text_or_time_inside_a_valid_structure_gives_placeholders_not_a_panic() {
    // Invalid UTF-8 in a UTF8String of the subject: the name falls back to a placeholder text, the rest stays.
    let bad_utf8 = patched(P256, b"p256-other", b"p256\xff\xfe\xc3\x28ab");
    let f = fields(&bad_utf8);
    assert!(harmless(&f.subject) && harmless(&f.subject_short), "{f:?}");
    assert_eq!(f.serial, "1A0DA9C946F9D0B76E0B1925A0550BE816DF3D21");
    // An impossible month inside the UTCTime/GeneralizedTime: the dates are placeholders, never a panic.
    let bad_time = patched(P256, b"261027160548Z", b"269927160548Z");
    let f = fields(&bad_time);
    assert!(harmless(&f.not_before) && harmless(&f.not_after), "{f:?}");
    assert!(!f.not_before.contains("9927"), "{f:?}");
}
