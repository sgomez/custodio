//! What `custodio import` and `custodio list` say about the storage kind (SPEC section 7, "CLI").

use std::io;
use std::path::PathBuf;

use custodio_cli::{
    ImportArgs, ImportFailure, Importer, KeyEntry, KeyLister, PasswordPrompt, ServiceFailure,
    next_steps, run_import, run_list,
};
use custodio_client::Kind;
use secrecy::SecretString;

mod import_view;
use import_view::{Imported, parse};

const KEY_TYPES: [&str; 2] = ["rsa2048", "ecdsa-p256"];
const CERT: &[u8] = include_bytes!("../../custodio-it/tests/fixtures/cert-p256-other.der");

struct Prompt;

impl PasswordPrompt for Prompt {
    fn password(&mut self, _: &str) -> io::Result<SecretString> {
        Ok(SecretString::from("pw".to_owned()))
    }
}

struct Fake(Result<(String, Kind), ServiceFailure>);

impl Importer for Fake {
    fn import_p12(
        &self,
        _: &str,
        _: &[u8],
        _: &SecretString,
    ) -> Result<(String, Kind), ServiceFailure> {
        self.0.clone()
    }
}

fn import_file(
    name: &str,
    result: Result<(String, Kind), ServiceFailure>,
) -> (Result<(), ImportFailure>, String, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let file: PathBuf = dir.path().join(name);
    std::fs::write(&file, b"p12").expect("write");
    let args = ImportArgs {
        file: file.clone(),
        id: "mykey".into(),
    };
    let mut out = Vec::new();
    let r = run_import(&args, &mut Prompt, &Fake(result), &mut out);
    (r, String::from_utf8_lossy(&out).into_owned(), file)
}

fn import(result: Result<(String, Kind), ServiceFailure>) -> (Result<(), ImportFailure>, String) {
    let (r, out, _) = import_file("k.p12", result);
    (r, out)
}

/// The output of a successful import of `key_type` stored as `kind`, after the checks that hold for
/// every kind: the key's cells, then the next steps of the product.
fn imported(key_type: &str, kind: &Kind) -> Imported {
    let (r, out, file) = import_file("k.p12", Ok((key_type.into(), kind.clone())));
    assert!(r.is_ok());
    let view = parse(&out);
    assert_eq!(
        view.cells,
        [
            "mykey",
            key_type,
            &custodio_cli::cert_text::escape(kind.wire())
        ],
        "{out}"
    );
    let expected: Vec<(String, String)> = next_steps(&file)
        .into_iter()
        .map(|(c, w)| (c, w.to_owned()))
        .collect();
    assert_eq!(view.next, expected, "{out}");
    view
}

#[test]
fn a_tpm_key_is_ok_with_nothing_under_it() {
    for t in KEY_TYPES {
        let view = imported(t, &Kind::Tpm);
        assert_eq!(view.word, "ok");
        assert!(view.notes.is_empty(), "{view:?}");
    }
}

#[test]
fn any_other_kind_is_a_warning_with_one_note_of_its_own() {
    let kinds = [
        Kind::EncryptedHost,
        Kind::EncryptedTpm,
        Kind::Unknown("future".into()),
    ];
    let mut notes = Vec::new();
    for t in KEY_TYPES {
        for kind in &kinds {
            let view = imported(t, kind);
            assert_eq!(view.word, "warn", "{kind:?}");
            assert_eq!(view.notes.len(), 1, "{kind:?}");
            notes.push(view.notes[0].clone());
        }
    }
    notes.sort();
    notes.dedup();
    assert_eq!(
        notes.len(),
        kinds.len(),
        "each kind has its own note: {notes:?}"
    );
}

#[test]
fn an_unknown_kind_is_shown_escaped() {
    let view = imported("rsa2048", &Kind::Unknown("odd\x1b[2Jkind".into()));
    assert!(view.cells.iter().all(|c| !c.contains('\x1b')), "{view:?}");
}

#[test]
fn the_delete_step_is_a_command_the_shell_reads_back_as_the_file() {
    for name in ["k.p12", "my cert.p12", "it's.p12", "~k.p12"] {
        let (r, out, file) = import_file(name, Ok(("rsa2048".into(), Kind::Tpm)));
        assert!(r.is_ok());
        let command = &parse(&out).next[0].0;
        let echoed = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "printf %s {}",
                command.trim_start_matches("shred -u ")
            ))
            .output()
            .expect("sh");
        assert!(command.starts_with("shred -u "), "{command}");
        assert_eq!(
            String::from_utf8_lossy(&echoed.stdout),
            file.display().to_string(),
            "{command}"
        );
    }
}

#[test]
fn failed_import_prints_no_kind() {
    // The failing fake still has a kind-shaped value around; nothing of it may be printed.
    let (r, out) = import(Err(ServiceFailure::Transport));
    assert!(matches!(r, Err(ImportFailure::Service(_))));
    assert_eq!(out, "");
}

struct Keys(Vec<KeyEntry>);

impl KeyLister for Keys {
    fn list_keys(&self) -> Result<Vec<KeyEntry>, ServiceFailure> {
        Ok(self.0.clone())
    }
}

fn entry(id: &str, kind: Kind) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        key_type: "ecdsa-p256".into(),
        kind,
        certificate: CERT.to_vec(),
    }
}

fn list(keys: Vec<KeyEntry>) -> String {
    let mut out = Vec::new();
    let look = custodio_cli::Look::plain(std::time::SystemTime::now());
    run_list(&Keys(keys), &mut out, look, false).expect("list");
    String::from_utf8_lossy(&out).into_owned()
}

/// The third cell of the row of `id`: the kind.
fn kind_of(out: &str, id: &str) -> String {
    let row = out
        .lines()
        .find(|l| l.split("  ").next() == Some(id))
        .unwrap_or_else(|| panic!("no row for {id} in {out}"));
    row.split("  ")
        .filter(|c| !c.is_empty())
        .nth(2)
        .expect("kind cell")
        .to_owned()
}

#[test]
fn list_shows_each_kind() {
    let out = list(vec![
        entry("a", Kind::EncryptedHost),
        entry("b", Kind::Tpm),
        entry("c", Kind::Unknown("future".into())),
        entry("d", Kind::EncryptedTpm),
        entry("e", Kind::EncryptedHost),
    ]);
    assert_eq!(kind_of(&out, "a"), "encrypted-host");
    assert_eq!(kind_of(&out, "b"), "tpm");
    assert_eq!(kind_of(&out, "c"), "future");
    assert_eq!(kind_of(&out, "d"), "encrypted-tpm");
    assert_eq!(kind_of(&out, "e"), "encrypted-host");
}

#[test]
fn list_escapes_kind() {
    let out = list(vec![entry("a", Kind::Unknown("x\x1b[31my".into()))]);
    assert_eq!(kind_of(&out, "a"), "x\\x1b[31my");
    assert!(!out.contains('\x1b'));
}
