use super::*;
use crate::{ArgError, Command, ImportArgs, parse_command};

const P256: &[u8] = include_bytes!("../../../custodio-it/tests/fixtures/cert-p256-other.der");
const RSA: &[u8] = include_bytes!("../../../custodio-it/tests/fixtures/cert-rsa3072.der");

/// A lister that allows exactly one `ListKeys` call: a second one fails the test.
struct Fixed(Result<Vec<KeyEntry>, ServiceFailure>, std::cell::Cell<u32>);

impl Fixed {
    fn new(reply: Result<Vec<KeyEntry>, ServiceFailure>) -> Self {
        Self(reply, std::cell::Cell::new(0))
    }
}

impl KeyLister for Fixed {
    fn list_keys(&self) -> Result<Vec<KeyEntry>, ServiceFailure> {
        self.1.set(self.1.get() + 1);
        assert_eq!(self.1.get(), 1, "ListKeys is the only call, and only once");
        self.0.clone()
    }
}

fn key(id: &str, key_type: &str, der: &[u8]) -> KeyEntry {
    of_kind(id, key_type, Kind::Tpm, der)
}

fn of_kind(id: &str, key_type: &str, kind: Kind, der: &[u8]) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        key_type: key_type.into(),
        kind,
        certificate: der.to_vec(),
    }
}

fn run(lister: &Fixed) -> (Result<(), ListFailure>, String) {
    let mut out = Vec::new();
    let result = run_list(lister, &mut out);
    (result, String::from_utf8_lossy(&out).into_owned())
}

const HOSTILE: &[u8] =
    include_bytes!("../../../custodio-it/tests/fixtures/cert-p256-other-hostile.der");

fn show(lister: &Fixed, id: &str) -> (Result<(), ListFailure>, String) {
    let mut out = Vec::new();
    let result = run_show(lister, id, &mut out);
    (result, String::from_utf8_lossy(&out).into_owned())
}

#[test]
fn keys_are_rows_sorted_by_id_with_aligned_columns() {
    let lister = Fixed::new(Ok(vec![
        key("bb", "rsa2048", RSA),
        key("a", "ecdsa-p256", P256),
    ]));
    let (result, out) = run(&lister);
    assert!(result.is_ok());
    assert_eq!(
        out,
        "a   ecdsa-p256  tpm  custodio test p256-other  2126-10-03T16:05:48Z\n\
         bb  rsa2048     tpm  custodio test rsa3072     2126-10-03T16:05:48Z\n"
    );
    assert!(!out.contains(NO_KEYS));
    assert!(!out.contains(WEAKER_NOTE));
}

#[test]
fn no_keys_says_so_and_how_to_import_one() {
    let (result, out) = run(&Fixed::new(Ok(Vec::new())));
    assert!(result.is_ok());
    assert_eq!(out, format!("{NO_KEYS}\n{NONE_HINT}\n"));
    assert!(NONE_HINT.contains("custodio import"));
}

#[test]
fn a_failure_prints_no_key_line() {
    let (result, out) = run(&Fixed::new(Err(ServiceFailure::AuthorizationUnavailable)));
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
    let (result, out) = run(&Fixed::new(Ok(vec![
        key("bad", "rsa2048", b"garbage"),
        key("good", "ecdsa-p256", P256),
    ])));
    assert!(matches!(result, Err(ListFailure::Unreadable(1))));
    assert!(
        out.starts_with(
            "bad   rsa2048     tpm  certificate unreadable    certificate unreadable\n"
        ),
        "{out}"
    );
    assert!(out.contains("good  ecdsa-p256  tpm  custodio test p256-other"));
    assert!(!out.contains("garbage"));
}

#[test]
fn the_weaker_storage_note_is_at_the_foot_once_or_not_at_all() {
    let kinds = [
        Kind::Tpm,
        Kind::EncryptedTpm,
        Kind::EncryptedHost,
        Kind::Unknown("future".into()),
    ];
    // Every combination of kinds over up to three keys.
    for mask in 1_u32..(1 << kinds.len()) {
        let chosen: Vec<&Kind> = kinds
            .iter()
            .enumerate()
            .filter(|(i, _)| mask >> i & 1 == 1)
            .map(|(_, k)| k)
            .collect();
        let keys: Vec<KeyEntry> = chosen
            .iter()
            .enumerate()
            .map(|(i, k)| of_kind(&format!("k{i}"), "rsa2048", (*k).clone(), RSA))
            .collect();
        let (result, out) = run(&Fixed::new(Ok(keys)));
        assert!(result.is_ok());
        let weaker = chosen
            .iter()
            .any(|k| matches!(k, Kind::EncryptedTpm | Kind::EncryptedHost));
        assert_eq!(
            out.matches(WEAKER_NOTE).count(),
            usize::from(weaker),
            "{out}"
        );
        assert_eq!(out.matches("Note:").count(), usize::from(weaker), "{out}");
        if weaker {
            assert!(out.ends_with(&format!("\n\n{WEAKER_NOTE}\n")), "{out}");
        }
        assert_eq!(
            out.lines()
                .filter(|l| l.contains("custodio test rsa3072"))
                .count(),
            chosen.len()
        );
    }
}

#[test]
fn the_note_names_the_readme_section_that_exists() {
    assert!(WEAKER_NOTE.contains("README.md#storage-kinds"));
    let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md"))
        .expect("README.md");
    assert!(readme.lines().any(|l| l == "### Storage kinds"));
}

#[test]
fn a_hostile_certificate_and_hostile_ids_cannot_forge_a_row_or_drive_the_terminal() {
    let (result, out) = run(&Fixed::new(Ok(vec![
        key("a\nforged  row", "rsa\x1b[2J", HOSTILE),
        of_kind("b", "t", Kind::Unknown("x\ny\u{202e}".into()), P256),
    ])));
    assert!(result.is_ok());
    assert_eq!(out.lines().count(), 2, "{out}");
    for c in out.chars() {
        assert!(c == '\n' || !c.is_control(), "raw {c:?}");
    }
    assert!(!out.contains('\u{202e}'));
    assert!(out.contains("a\\x0aforged  row"), "{out}");
    assert!(out.contains("a\\x1b[31mb\\x0ac\\x7fd"), "{out}");
}

#[test]
fn list_with_an_id_shows_that_key_in_full_from_the_one_reply() {
    let lister = Fixed::new(Ok(vec![
        key("other", "rsa2048", RSA),
        of_kind("mine", "ecdsa-p256", Kind::EncryptedHost, P256),
    ]));
    let (result, out) = show(&lister, "mine");
    assert!(result.is_ok());
    assert_eq!(lister.1.get(), 1);
    assert_eq!(
        out,
        "id          mine\n\
         type        ecdsa-p256\n\
         kind        encrypted-host\n\
         subject     CN=custodio test p256-other\n\
         issuer      CN=custodio test p256-other\n\
         serial      1A0DA9C946F9D0B76E0B1925A0550BE816DF3D21\n\
         valid from  2026-10-27T16:05:48Z\n\
         valid until 2126-10-03T16:05:48Z\n\
         SHA-256     51:30:3C:19:FF:27:E3:D4:BC:4D:9A:80:56:59:DD:A6:AF:75:47:E3:C1:80:27:64:B8:58:3F:BD:0E:70:D6:42\n"
    );
}

#[test]
fn list_with_an_unknown_id_is_an_error_that_prints_nothing() {
    let lister = Fixed::new(Ok(vec![key("a", "rsa2048", RSA)]));
    let (result, out) = show(&lister, "A");
    assert!(matches!(result, Err(ListFailure::UnknownId(ref id)) if id == "A"));
    assert_eq!(out, "");
    let (result, _) = show(&Fixed::new(Ok(Vec::new())), "a");
    assert!(matches!(result, Err(ListFailure::UnknownId(_))));
    let (result, _) = show(
        &Fixed::new(Err(ServiceFailure::AuthorizationUnavailable)),
        "a",
    );
    assert!(matches!(result, Err(ListFailure::Service(_))));
}

#[test]
fn the_full_view_of_a_hostile_key_is_escaped_and_an_unreadable_one_is_an_error() {
    let (result, out) = show(&Fixed::new(Ok(vec![key("a", "t", HOSTILE)])), "a");
    assert!(result.is_ok());
    assert_eq!(out.lines().count(), 9, "{out}");
    for c in out.chars() {
        assert!(c == '\n' || !c.is_control(), "raw {c:?}");
    }
    let (result, out) = show(&Fixed::new(Ok(vec![key("a", "t", b"junk")])), "a");
    assert!(matches!(result, Err(ListFailure::Unreadable(1))));
    assert_eq!(out.matches("certificate unreadable").count(), 6, "{out}");
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
fn list_takes_one_optional_key_id() {
    assert_eq!(args(&["list"]), Ok(Command::List(None)));
    assert_eq!(
        args(&["list", "work"]),
        Ok(Command::List(Some("work".into())))
    );
    assert_eq!(
        args(&["list", "--", "-x"]),
        Ok(Command::List(Some("-x".into())))
    );
    for bad in [
        &["list", "extra", "more"][..],
        &["list", "--id", "x"],
        &["list", "-x"],
        &["list", "--"],
        &["list", "--", "a", "b"],
    ] {
        assert_eq!(args(bad), Err(ArgError::CommandUsage("list")), "{bad:?}");
    }
    for bad in [&["List"][..], &[]] {
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
    assert_eq!(args(&["import"]), Err(ArgError::CommandUsage("import")));
}

#[test]
fn the_usage_names_both_commands() {
    assert!(crate::USAGE.contains("custodio import"));
    assert!(crate::USAGE.contains("custodio list"));
}

#[test]
fn a_list_failure_reads_as_a_sentence_with_the_id_escaped() {
    assert_eq!(
        ListFailure::Unreadable(2).to_string(),
        "2 certificate(s) could not be read"
    );
    assert_eq!(
        ListFailure::UnknownId("a\nb".into()).to_string(),
        "you have no key with the id 'a\\x0ab'"
    );
    assert!(
        ListFailure::Output(io::Error::other("full"))
            .to_string()
            .contains("cannot write the list: full")
    );
    assert_eq!(
        ListFailure::Service(ServiceFailure::AuthorizationUnavailable).to_string(),
        ServiceFailure::AuthorizationUnavailable.to_string()
    );
}
