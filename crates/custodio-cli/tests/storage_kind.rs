//! What `custodio import` and `custodio list` say about the storage kind (SPEC section 7, "CLI").

use std::io;
use std::path::PathBuf;

use custodio_cli::{
    ImportArgs, ImportFailure, Importer, KeyEntry, KeyLister, PasswordPrompt, ServiceFailure,
    run_import, run_list,
};
use custodio_client::Kind;
use secrecy::SecretString;

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

fn import(result: Result<(String, Kind), ServiceFailure>) -> (Result<(), ImportFailure>, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let file: PathBuf = dir.path().join("k.p12");
    std::fs::write(&file, b"p12").expect("write");
    let args = ImportArgs {
        file,
        id: "mykey".into(),
    };
    let mut out = Vec::new();
    let r = run_import(&args, &mut Prompt, &Fake(result), &mut out);
    (r, String::from_utf8_lossy(&out).into_owned())
}

fn imported(key_type: &str, kind: Kind) -> String {
    let (r, out) = import(Ok((key_type.into(), kind)));
    assert!(r.is_ok());
    assert!(out.contains(key_type), "{out}");
    assert!(out.contains("Now delete the original file"), "{out}");
    out
}

#[test]
fn import_tpm() {
    for t in KEY_TYPES {
        let out = imported(t, Kind::Tpm);
        assert!(out.contains("tpm"), "{out}");
        assert!(out.contains("cannot be copied"), "{out}");
        assert!(!out.contains("weaker"), "{out}");
        assert!(!out.contains("capability"), "{out}");
        assert!(!out.contains("no TPM"), "{out}");
    }
}

#[test]
fn import_encrypted_host() {
    for t in KEY_TYPES {
        let out = imported(t, Kind::EncryptedHost);
        assert!(out.contains("encrypted-host"), "{out}");
        assert!(out.contains("weaker"), "{out}");
        assert!(out.contains("no TPM"), "{out}");
        assert!(out.contains("Root"), "{out}");
        assert!(out.contains("/var/lib"), "{out}");
        assert!(!out.contains("capability"), "{out}");
    }
}

#[test]
fn import_encrypted_tpm() {
    for t in KEY_TYPES {
        let out = imported(t, Kind::EncryptedTpm);
        assert!(out.contains("encrypted-tpm"), "{out}");
        assert!(out.contains("weaker"), "{out}");
        assert!(out.contains("lacks a capability"), "{out}");
        assert!(!out.contains("no TPM"), "{out}");
        assert!(out.contains("Root"), "{out}");
        assert!(out.contains("while the machine runs"), "{out}");
        assert!(out.contains("docs/api.md"), "{out}");
        assert!(out.contains("TPM capabilities"), "{out}");
        assert!(!out.contains("journal"), "{out}");
    }
}

#[test]
fn weaker_reasons_differ() {
    let host = imported("rsa2048", Kind::EncryptedHost);
    let tpm = imported("rsa2048", Kind::EncryptedTpm);
    assert_ne!(host, tpm);
    assert!(!host.contains("lacks a capability"));
    assert!(!tpm.contains("/var/lib"));
}

#[test]
fn import_unknown_kind() {
    for t in KEY_TYPES {
        let out = imported(t, Kind::Unknown("odd\x1b[2Jkind".into()));
        assert!(out.contains("odd\\x1b[2Jkind"), "{out}");
        assert!(!out.contains('\x1b'), "{out}");
        assert!(out.contains("does not know"), "{out}");
        assert!(!out.contains("weaker"), "{out}");
        assert!(!out.contains("stronger"), "{out}");
        assert!(!out.contains("in the TPM"), "{out}");
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
    run_list(&Keys(keys), &mut out).expect("list");
    String::from_utf8_lossy(&out).into_owned()
}

/// The `kind:` line of the block of `id`.
fn kind_of(out: &str, id: &str) -> String {
    let mut lines = out.lines().skip_while(|l| *l != format!("id: {id}"));
    lines.next().expect("block");
    for l in lines {
        if l.starts_with("id: ") {
            break;
        }
        if let Some(k) = l.trim().strip_prefix("kind: ") {
            return k.to_owned();
        }
    }
    panic!("no kind line for {id} in {out}");
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
    assert!(!out.contains("weaker"), "{out}");
}

#[test]
fn list_escapes_kind() {
    let out = list(vec![entry("a", Kind::Unknown("x\x1b[31my".into()))]);
    assert_eq!(kind_of(&out, "a"), "x\\x1b[31my");
    assert!(!out.contains('\x1b'));
}
