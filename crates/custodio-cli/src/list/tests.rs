use super::*;
use crate::{ArgError, Command, ImportArgs, parse_command};

const P256: &[u8] = include_bytes!("../../../custodio-it/tests/fixtures/cert-p256-other.der");
const RSA: &[u8] = include_bytes!("../../../custodio-it/tests/fixtures/cert-rsa3072.der");

struct Fixed(Result<Vec<KeyEntry>, ServiceFailure>);

impl KeyLister for Fixed {
    fn list_keys(&self) -> Result<Vec<KeyEntry>, ServiceFailure> {
        self.0.clone()
    }
}

fn key(id: &str, kind: &str, der: &[u8]) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        key_type: kind.into(),
        kind: Kind::Tpm,
        certificate: der.to_vec(),
    }
}

fn run(lister: &Fixed) -> (Result<(), ListFailure>, String) {
    let mut out = Vec::new();
    let result = run_list(lister, &mut out);
    (result, String::from_utf8_lossy(&out).into_owned())
}

#[test]
fn a_certificate_gives_its_subject_and_end_of_validity() {
    assert_eq!(
        certificate_info(P256),
        Some(CertificateInfo {
            subject: "CN=custodio test p256-other".into(),
            not_after: "2126-10-03T16:05:48Z".into(),
        })
    );
    assert_eq!(
        certificate_info(RSA).map(|i| i.subject),
        Some("CN=custodio test rsa3072".into())
    );
}

#[test]
fn garbage_is_not_a_certificate() {
    assert_eq!(certificate_info(b""), None);
    assert_eq!(certificate_info(b"not a certificate"), None);
    assert_eq!(certificate_info(&P256[..P256.len() - 5]), None);
}

#[test]
fn keys_are_sorted_by_id_each_with_its_own_certificate() {
    let lister = Fixed(Ok(vec![
        key("b", "rsa2048", RSA),
        key("a", "ecdsa-p256", P256),
    ]));
    let (result, out) = run(&lister);
    assert!(result.is_ok());
    assert_eq!(
        out,
        "id: a\n  type: ecdsa-p256\n  kind: tpm\n  subject: CN=custodio test p256-other\n  valid until: 2126-10-03T16:05:48Z\n\
         id: b\n  type: rsa2048\n  kind: tpm\n  subject: CN=custodio test rsa3072\n  valid until: 2126-10-03T16:05:48Z\n"
    );
    assert!(!out.contains(NO_KEYS));
}

#[test]
fn no_keys_says_so() {
    let (result, out) = run(&Fixed(Ok(Vec::new())));
    assert!(result.is_ok());
    assert_eq!(out, format!("{NO_KEYS}\n"));
}

#[test]
fn a_failure_prints_no_key_line() {
    let (result, out) = run(&Fixed(Err(ServiceFailure::AuthorizationUnavailable)));
    assert!(matches!(
        result,
        Err(ListFailure::Service(
            ServiceFailure::AuthorizationUnavailable
        ))
    ));
    assert_eq!(out, "");
}

#[test]
fn an_unreadable_certificate_never_hides_the_key() {
    let (result, out) = run(&Fixed(Ok(vec![
        key("bad", "rsa2048", b"garbage"),
        key("good", "ecdsa-p256", P256),
    ])));
    assert!(matches!(result, Err(ListFailure::Unreadable(1))));
    assert!(
        out.contains("id: bad\n  type: rsa2048\n  kind: tpm\n  subject: certificate unreadable\n")
    );
    assert!(out.contains("id: good\n"));
    assert!(out.contains("CN=custodio test p256-other"));
    assert!(!out.contains("garbage"));
}

#[test]
fn control_characters_are_never_written_raw_but_the_readable_part_stays() {
    let info = CertificateInfo {
        subject: "CN=evil\n\x1b[31mred\x07\u{85}\x7f end".into(),
        not_after: "2126-10-03T16:05:48Z".into(),
    };
    let mut out = Vec::new();
    write_entry(&mut out, "i\td", "ty\rpe", &Kind::Tpm, Some(&info)).unwrap_or_default();
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("CN=evil\\x0a\\x1b[31mred\\x07\\x85\\x7f end"),
        "{text}"
    );
    assert!(text.contains("id: i\\x09d\n"), "{text}");
    assert!(text.contains("ty\\x0dpe"), "{text}");
    for b in text.bytes() {
        assert!(b == b'\n' || (b >= 0x20 && b != 0x7f), "raw byte {b:#x}");
    }
    assert_eq!(text.matches('\n').count(), 5);
}

#[test]
fn a_certificate_with_control_bytes_in_its_subject_is_escaped() {
    // Same length, so the DER stays valid: "custodio test p256-other" -> hostile bytes.
    let mut der = P256.to_vec();
    let needle = b"custodio test p256-other";
    let at = der
        .windows(needle.len())
        .rposition(|w| w == needle)
        .expect("the subject is in the certificate");
    der[at + 3..at + 6].copy_from_slice(b"\n\x1b\x07");
    let (result, out) = run(&Fixed(Ok(vec![key("k", "ecdsa-p256", &der)])));
    assert!(result.is_ok());
    // The X.509 library already writes control bytes as `\xx` (RFC 4514); ours is the second layer.
    assert!(
        out.contains("CN=cus") && out.contains("io test p256-other"),
        "{out}"
    );
    for b in out.bytes() {
        assert!(b == b'\n' || (b >= 0x20 && b != 0x7f), "raw byte {b:#x}");
    }
}

#[test]
fn the_debug_form_of_an_entry_has_no_certificate() {
    let shown = format!("{:?}", key("k", "rsa2048", &[0xde, 0xad, 0xbe, 0xef]));
    assert!(
        !shown.contains("222") && !shown.to_lowercase().contains("de, ad"),
        "{shown}"
    );
}

fn args(list: &[&str]) -> Result<Command, ArgError> {
    parse_command(list.iter().map(|s| (*s).to_owned()))
}

#[test]
fn list_takes_no_argument() {
    assert_eq!(args(&["list"]), Ok(Command::List));
    for bad in [
        &["list", "extra"][..],
        &["list", "--id", "x"],
        &["list", "-x"],
        &["List"],
        &[],
    ] {
        assert_eq!(args(bad), Err(ArgError::Usage), "{bad:?}");
    }
}

#[test]
fn import_still_parses_through_the_dispatcher() {
    assert_eq!(
        args(&["import", "--id", "k", "a.p12"]),
        Ok(Command::Import(ImportArgs {
            file: "a.p12".into(),
            id: "k".into()
        }))
    );
    assert_eq!(args(&["import"]), Err(ArgError::Usage));
}

#[test]
fn the_usage_names_both_commands() {
    assert!(crate::USAGE.contains("custodio import"));
    assert!(crate::USAGE.contains("custodio list"));
}
