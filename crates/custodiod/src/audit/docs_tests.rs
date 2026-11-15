//! Ties the audit code to `docs/audit.md` and `data/custodio.catalog`, so they cannot drift.
use super::*;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use crate::app_id::AppIdOutcome;
use crate::store::Kind as StorageKind;

type TestResult = Result<(), Box<dyn Error>>;

fn read(rel: &str) -> Result<String, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    Ok(fs::read_to_string(path)?)
}

fn docs() -> Result<String, Box<dyn Error>> {
    read("docs/audit.md")
}

fn catalog() -> Result<String, Box<dyn Error>> {
    read("data/custodio.catalog")
}

fn token(name: &str) -> String {
    format!("`{name}`")
}

/// Every outcome; the exhaustive match stops compiling when a variant is added.
fn outcomes() -> Vec<Outcome> {
    let all = |o: Outcome| match o {
        Outcome::Signed
        | Outcome::SigningFailed
        | Outcome::Denied
        | Outcome::AuthorizationUnavailable => [
            Outcome::Signed,
            Outcome::SigningFailed,
            Outcome::Denied,
            Outcome::AuthorizationUnavailable,
        ],
    };
    all(Outcome::Signed).to_vec()
}

fn key() -> Result<KeyId, InvalidKeyId> {
    KeyId::new("my-key")
}

const CALLER: Caller = Caller {
    uid: 1000,
    pid: 4242,
};

/// Every entry of the other operations, one per outcome (an import also with a key type).
fn operation_entries() -> Result<Vec<OperationEntry>, InvalidKeyId> {
    let mut all = Vec::new();
    for o in ImportOutcome::all() {
        let t = AuditKeyType::all();
        all.push(
            OperationEntry::import(o, Some(CALLER), key()?, t.first().copied()).with_app_id(app()),
        );
    }
    // One import per kind and one per cause, so the fields they add are among those the page must document.
    for kind in store_kinds() {
        let stored = OperationEntry::import(ImportOutcome::Stored, Some(CALLER), key()?, None);
        all.push(stored.with_storage_kind(kind).with_app_id(app()));
    }
    for cause in ImportCause::all() {
        let failed =
            OperationEntry::import(ImportOutcome::StorageFailure, Some(CALLER), key()?, None);
        all.push(failed.with_cause(cause).with_app_id(app()));
    }
    for o in DeleteOutcome::all() {
        all.push(OperationEntry::delete(o, Some(CALLER), key()?).with_app_id(app()));
    }
    for o in ReplaceOutcome::all() {
        all.push(OperationEntry::replace_certificate(o, Some(CALLER), key()?).with_app_id(app()));
    }
    all.push(OperationEntry::purge(Some(1000), key()?));
    Ok(all)
}

/// The `(outcome name, priority)` pairs of an operation, in the order of the code.
fn outcome_pairs(op: Operation) -> Vec<(&'static str, u8)> {
    match op {
        Operation::Sign => outcomes()
            .iter()
            .map(|o| (o.name(), o.priority()))
            .collect(),
        Operation::Import => ImportOutcome::all()
            .iter()
            .map(|o| (o.name(), o.priority()))
            .collect(),
        Operation::Delete => DeleteOutcome::all()
            .iter()
            .map(|o| (o.name(), o.priority()))
            .collect(),
        Operation::ReplaceCertificate => ReplaceOutcome::all()
            .iter()
            .map(|o| (o.name(), o.priority()))
            .collect(),
        Operation::Purge => PurgeOutcome::all()
            .iter()
            .map(|o| (o.name(), o.priority()))
            .collect(),
    }
}

/// The text of both catalog entries (`en` and untagged) of a `MESSAGE_ID`.
fn catalog_bodies(catalog: &str, id: &str) -> Vec<String> {
    catalog
        .split("\n-- ")
        .skip(1)
        .filter(|e| e.starts_with(&format!("{id} en\n")) || e.starts_with(&format!("{id}\n")))
        .map(str::to_owned)
        .collect()
}

/// Field names of the entries with this operation (all outcomes, everything known).
fn field_names(op: Operation) -> Result<BTreeSet<&'static str>, Box<dyn Error>> {
    let mut all = BTreeSet::new();
    if op == Operation::Sign {
        for o in outcomes() {
            all.extend(names(&full(o)?));
        }
        all.extend(names(&socket_entry()?));
        let failed = full(Outcome::SigningFailed)?;
        all.extend(names(&failed.with_storage_kind(StorageKind::Tpm)));
        all.extend(names(
            &full(Outcome::SigningFailed)?.with_cause(SignCause::KeyLost),
        ));
    }
    for e in operation_entries()?.iter().filter(|e| e.operation() == op) {
        all.extend(e.fields().into_iter().map(|(n, _)| n));
    }
    Ok(all)
}

fn full(o: Outcome) -> Result<Entry, InvalidKeyId> {
    Ok(Entry::new(
        o,
        Caller {
            uid: 1000,
            pid: 4242,
        },
        key()?,
        Some(AuditMechanism::Ecdsa),
    )
    .with_app_id(app()))
}

/// An entry of a call on a snap socket.
fn socket_entry() -> Result<Entry, Box<dyn Error>> {
    let label = PeerLabel::new(b"snap.firefox.firefox (enforce)")
        .map_err(|e| format!("the accepted label was refused: {e}"))?;
    Ok(full(Outcome::Signed)?.with_socket_peer(label))
}

fn names(e: &Entry) -> BTreeSet<&'static str> {
    e.fields().into_iter().map(|(n, _)| n).collect()
}

#[test]
fn every_field_name_in_the_catalog() -> TestResult {
    let catalog = catalog()?;
    let sign = field_names(Operation::Sign)?;
    assert!(sign.len() >= 10 && sign.contains("CUSTODIO_OPERATION"));
    for op in Operation::all() {
        let bodies = catalog_bodies(&catalog, op.message_id());
        assert_eq!(bodies.len(), 2, "catalog entries of {}", op.name());
        for name in field_names(op)? {
            for body in &bodies {
                assert!(
                    body.contains(&token(name)),
                    "the catalog entry of {} lacks {name}",
                    op.name()
                );
            }
        }
    }
    assert!(field_names(Operation::Import)?.contains("CUSTODIO_KEY_TYPE"));
    Ok(())
}

#[test]
fn catalog_format() -> TestResult {
    // For each id the `en` entry comes first and the untagged default entry follows, because a
    // catalog with only a tagged entry makes `journalctl --list-catalog` abort.
    let catalog = catalog()?;
    let lines: Vec<_> = catalog.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(lines.first(), Some(&format!("-- {MESSAGE_ID} en").as_str()));
    let entries: Vec<_> = catalog.split("\n-- ").skip(1).collect();
    let mut ids: Vec<_> = Operation::all().iter().map(|o| o.message_id()).collect();
    // The start-up entry for the state directory's storage is not an operation.
    ids.push(STATE_STORAGE_MESSAGE_ID);
    assert_eq!(
        entries.len(),
        2 * ids.len(),
        "the catalog has an id the code does not emit"
    );
    for id in ids {
        assert!(
            id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{id} is not 32 lower-case hex digits"
        );
        let pos = |head: String| entries.iter().position(|e| e.starts_with(&head));
        let (en, plain) = (pos(format!("{id} en\n")), pos(format!("{id}\n")));
        assert!(en.is_some() && plain.is_some(), "{id} lacks an entry");
        assert!(en < plain, "the en entry of {id} is not first");
        assert!(lines.contains(&format!("-- {id}").as_str()));
        for entry in catalog_bodies(&catalog, id) {
            let rest: Vec<_> = entry.lines().collect();
            assert_eq!(rest.iter().filter(|l| l.starts_with("Subject:")).count(), 1);
            assert_eq!(
                rest.iter()
                    .filter(|l| **l == "Defined-By: custodio")
                    .count(),
                1
            );
        }
    }
    Ok(())
}

#[test]
fn every_query_uses_only_what_the_code_emits() -> TestResult {
    let docs = docs()?;
    let mut ops = BTreeSet::new();
    let mut outcome_names = BTreeSet::new();
    for op in Operation::all() {
        ops.insert(op.name());
        outcome_names.extend(outcome_pairs(op).into_iter().map(|(n, _)| n));
    }
    let ids: BTreeSet<_> = Operation::all().iter().map(|o| o.message_id()).collect();
    let mut seen = 0;
    for line in docs
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("journalctl"))
    {
        seen += 1;
        let line = line.replace("$(id -u custodio)", "UID_OF_CUSTODIO");
        for term in line.split_whitespace().skip(1) {
            let (name, value) = term
                .split_once('=')
                .ok_or_else(|| format!("odd term {term}"))?;
            let ok = match name {
                "_SYSTEMD_UNIT" => value == "custodio.service",
                "_UID" => value == "UID_OF_CUSTODIO",
                "MESSAGE_ID" => ids.contains(value),
                "CUSTODIO_OPERATION" => ops.contains(value),
                "CUSTODIO_OUTCOME" => outcome_names.contains(value),
                "CUSTODIO_UID" | "CUSTODIO_OWNER_UID" => {
                    value.bytes().all(|b| b.is_ascii_digit()) && !value.is_empty()
                }
                "CUSTODIO_KEY_ID" => KeyId::new(value).is_ok(),
                "CUSTODIO_STORAGE_KIND" => store_kinds().iter().any(|k| k.wire() == value),
                "CUSTODIO_CAUSE" => cause_names().contains(value),
                "CUSTODIO_APP_ID" => crate::app_id::validate(value.as_bytes()).is_some(),
                "CUSTODIO_APP_ID_STATE" => {
                    ["read", "none", "undetermined"].contains(&value)
                        && [AppIdOutcome::None, AppIdOutcome::Undetermined, app()]
                            .iter()
                            .any(|c| app_id_state(c) == value)
                }
                _ => false,
            };
            assert!(ok, "query term {term} is not something the code emits");
        }
    }
    assert!(seen >= 12);
    Ok(())
}

mod causes;
use causes::{cause_names, store_kinds};
mod app_id;
use app_id::app;
