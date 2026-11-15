//! The storage warning of `custodio import` and `custodio list` (SPEC Design 7, acceptance 14).

use std::io;
use std::path::PathBuf;

use custodio_cli::storage::{README_ANCHOR, StateStorage, StorageReader, warning};
use custodio_cli::{
    CliError, ImportArgs, ImportFailure, Importer, KeyEntry, KeyLister, PasswordPrompt,
    ServiceFailure, finish, import_command, list_command,
};
use custodio_client::Kind;
use secrecy::SecretString;

const CERT: &[u8] = include_bytes!("../../custodio-it/tests/fixtures/cert-p256-other.der");

struct Prompt;

impl PasswordPrompt for Prompt {
    fn password(&mut self, _: &str) -> io::Result<SecretString> {
        Ok(SecretString::from("pw".to_owned()))
    }
}

struct Svc {
    storage: Option<StateStorage>,
    fail: bool,
}

impl Importer for Svc {
    fn import_p12(
        &self,
        _: &str,
        _: &[u8],
        _: &SecretString,
    ) -> Result<(String, Kind), ServiceFailure> {
        if self.fail {
            Err(ServiceFailure::Transport)
        } else {
            Ok(("ecdsa-p256".into(), Kind::Tpm))
        }
    }
}

impl KeyLister for Svc {
    fn list_keys(&self) -> Result<Vec<KeyEntry>, ServiceFailure> {
        if self.fail {
            return Err(ServiceFailure::Transport);
        }
        Ok(vec![KeyEntry {
            id: "k".into(),
            key_type: "ecdsa-p256".into(),
            kind: Kind::Tpm,
            certificate: CERT.to_vec(),
        }])
    }
}

impl StorageReader for Svc {
    fn state_storage(&self) -> Option<StateStorage> {
        self.storage
    }
}

struct Run {
    out: String,
    err: String,
    status: u8,
}

fn run_import(svc: &Svc) -> Run {
    let dir = tempfile::tempdir().expect("tempdir");
    let file: PathBuf = dir.path().join("k.p12");
    std::fs::write(&file, b"p12").expect("write");
    let args = ImportArgs {
        file,
        id: "mykey".into(),
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result =
        import_command(&args, &mut Prompt, svc, svc, &mut out, &mut err).map_err(CliError::Import);
    // The reminder names the temporary file: compare outputs with the directory name taken out.
    let mut run = finish_run(&result, &out, err);
    run.out = run.out.replace(&dir.path().display().to_string(), "<dir>");
    run
}

fn run_list(svc: &Svc) -> Run {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = list_command(svc, svc, &mut out, &mut err).map_err(CliError::List);
    finish_run(&result, &out, err)
}

fn finish_run(result: &Result<(), CliError>, out: &[u8], mut err: Vec<u8>) -> Run {
    let status = finish(result, &mut err);
    Run {
        out: String::from_utf8_lossy(out).into_owned(),
        err: String::from_utf8_lossy(&err).into_owned(),
        status,
    }
}

fn svc(storage: Option<StateStorage>) -> Svc {
    Svc {
        storage,
        fail: false,
    }
}

type Command = fn(&Svc) -> Run;
const COMMANDS: [(&str, Command); 2] = [("import", run_import), ("list", run_list)];

#[test]
fn not_encrypted_and_unknown_warn_and_point_to_the_readme() {
    for (name, run) in COMMANDS {
        for storage in [StateStorage::NotEncrypted, StateStorage::Unknown] {
            let r = run(&svc(Some(storage)));
            assert!(r.err.contains("Warning"), "{name} {storage:?}: {}", r.err);
            assert!(
                r.err
                    .contains("whoever takes this machine can use your keys"),
                "{}",
                r.err
            );
            assert!(r.err.contains("cannot copy a tpm key"), "{}", r.err);
            assert!(
                r.err.contains(&format!("README.md#{README_ANCHOR}")),
                "{}",
                r.err
            );
            assert_eq!(r.status, 0, "{name} {storage:?}");
        }
        let a = run(&svc(Some(StateStorage::NotEncrypted)));
        let b = run(&svc(Some(StateStorage::Unknown)));
        assert_ne!(a.err, b.err, "{name}: the two cases say different things");
    }
}

#[test]
fn encrypted_and_an_old_service_print_nothing() {
    for (name, run) in COMMANDS {
        for storage in [Some(StateStorage::Encrypted), None] {
            let r = run(&svc(storage));
            assert_eq!(r.err, "", "{name} {storage:?}");
            assert_eq!(r.status, 0, "{name} {storage:?}");
        }
    }
}

#[test]
fn the_data_and_the_status_are_the_same_with_and_without_the_warning() {
    for (name, run) in COMMANDS {
        let plain = run(&svc(Some(StateStorage::Encrypted)));
        for storage in [StateStorage::NotEncrypted, StateStorage::Unknown] {
            let warned = run(&svc(Some(storage)));
            assert_eq!(warned.out, plain.out, "{name}: standard output");
            assert_eq!(warned.status, plain.status, "{name}: status");
            assert!(
                !warned.out.contains("Warning"),
                "{name}: the warning is not data"
            );
        }
        assert_ne!(plain.out, "");
    }
}

#[test]
fn a_failed_command_prints_no_warning() {
    for (name, run) in COMMANDS {
        let r = run(&Svc {
            storage: Some(StateStorage::NotEncrypted),
            fail: true,
        });
        assert_eq!(r.status, 1, "{name}");
        assert!(!r.err.contains("Warning"), "{name}: {}", r.err);
    }
}

#[test]
fn a_value_the_cli_does_not_know_is_never_encrypted() {
    assert_eq!(
        StateStorage::from_wire("encrypted"),
        StateStorage::Encrypted
    );
    assert_eq!(
        StateStorage::from_wire("not-encrypted"),
        StateStorage::NotEncrypted
    );
    assert_eq!(StateStorage::from_wire("unknown"), StateStorage::Unknown);
    for odd in ["", "Encrypted", "encrypted ", "encrypted-with-raid", "yes"] {
        assert_eq!(
            StateStorage::from_wire(odd),
            StateStorage::Unknown,
            "{odd:?}"
        );
        assert!(warning(StateStorage::from_wire(odd)).is_some());
    }
    assert!(warning(StateStorage::Encrypted).is_none());
}

#[test]
fn warning_anchor_exists_in_readme() {
    let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md"))
        .expect("README.md");
    // GitHub's anchor of a heading: lower case, spaces to '-', punctuation dropped.
    let anchors: Vec<String> = readme
        .lines()
        .filter(|l| l.starts_with('#'))
        .map(|l| {
            l.trim_start_matches('#')
                .trim()
                .to_lowercase()
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-')
                .map(|c| if c == ' ' { '-' } else { c })
                .collect()
        })
        .collect();
    assert!(anchors.iter().any(|a| a == README_ANCHOR), "{anchors:?}");
}

#[test]
fn import_failure_type_is_unchanged() {
    // The warning adds no failure: the error type of a failed import is still `ImportFailure`.
    let _: fn(&Svc) -> Result<(), ImportFailure> = |s| {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        import_command(
            &ImportArgs {
                file: PathBuf::new(),
                id: String::new(),
            },
            &mut Prompt,
            s,
            s,
            &mut o,
            &mut e,
        )
    };
}
