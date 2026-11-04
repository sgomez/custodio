//! Ties the audit code to `docs/audit.md` and `data/custodio.catalog`, so they cannot drift.
use super::*;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use crate::app_id::AppIdOutcome;

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

/// Every mechanism; the exhaustive match stops compiling when a variant is added.
fn mechanisms() -> Vec<AuditMechanism> {
    let all = |m: AuditMechanism| match m {
        AuditMechanism::RsaPkcs
        | AuditMechanism::RsaPkcsPssSha256
        | AuditMechanism::RsaPkcsPssSha384
        | AuditMechanism::RsaPkcsPssSha512
        | AuditMechanism::Ecdsa => [
            AuditMechanism::RsaPkcs,
            AuditMechanism::RsaPkcsPssSha256,
            AuditMechanism::RsaPkcsPssSha384,
            AuditMechanism::RsaPkcsPssSha512,
            AuditMechanism::Ecdsa,
        ],
    };
    all(AuditMechanism::RsaPkcs).to_vec()
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
    for o in DeleteOutcome::all() {
        all.push(OperationEntry::delete(o, Some(CALLER), key()?).with_app_id(app()));
    }
    for o in ReplaceOutcome::all() {
        all.push(OperationEntry::replace_certificate(o, Some(CALLER), key()?).with_app_id(app()));
    }
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
    }
}

/// The lines under the `### <op>` heading of the page, up to the next heading.
fn outcome_section(docs: &str, op: Operation) -> Vec<String> {
    let heading = format!("### {}", op.name());
    docs.lines()
        .skip_while(|l| *l != heading)
        .skip(1)
        .take_while(|l| !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
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
fn field_names(op: Operation) -> Result<BTreeSet<&'static str>, InvalidKeyId> {
    let mut all = BTreeSet::new();
    if op == Operation::Sign {
        for o in outcomes() {
            all.extend(names(&full(o)?));
        }
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

fn names(e: &Entry) -> BTreeSet<&'static str> {
    e.fields().into_iter().map(|(n, _)| n).collect()
}

fn cells(line: &str) -> Vec<&str> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(str::trim)
        .collect()
}

#[test]
fn message_id_in_docs_and_catalog() -> TestResult {
    let (docs, catalog) = (docs()?, catalog()?);
    for op in Operation::all() {
        let row = format!("| `{}` | `{}` |", op.name(), op.message_id());
        assert!(docs.contains(&row), "docs lack the id of {}", op.name());
        assert!(catalog.contains(op.message_id()));
    }
    assert_eq!(MESSAGE_ID, Operation::Sign.message_id());
    Ok(())
}

#[test]
fn every_field_name_in_docs_and_catalog() -> TestResult {
    let (docs, catalog) = (docs()?, catalog()?);
    let sign = field_names(Operation::Sign)?;
    assert!(sign.len() >= 10 && sign.contains("CUSTODIO_OPERATION"));
    for op in Operation::all() {
        let bodies = catalog_bodies(&catalog, op.message_id());
        assert_eq!(bodies.len(), 2, "catalog entries of {}", op.name());
        for name in field_names(op)? {
            assert!(docs.contains(&token(name)), "docs lack {name}");
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
fn optional_fields_flagged() -> TestResult {
    let docs = docs()?;
    let missing: Vec<_> = names(&full(Outcome::Signed)?)
        .difference(&names(&Entry::without_caller(key()?, None)))
        .copied()
        .collect();
    assert_eq!(
        missing,
        [
            "CUSTODIO_APP_ID",
            "CUSTODIO_MECHANISM",
            "CUSTODIO_PID",
            "CUSTODIO_UID"
        ]
    );
    let mut missing = missing;
    missing.push("CUSTODIO_KEY_TYPE");
    assert!(field_names(Operation::Import)?.contains("CUSTODIO_KEY_TYPE"));
    let untyped = OperationEntry::import(ImportOutcome::WrongPassword, None, key()?, None);
    assert!(
        untyped
            .fields()
            .iter()
            .all(|(n, _)| *n != "CUSTODIO_KEY_TYPE")
    );
    for name in missing {
        let flagged = docs.lines().any(|l| {
            let l = l.to_lowercase();
            l.contains(&token(&name.to_lowercase()).to_lowercase())
                && (l.contains("absent") || l.contains("omitted"))
        });
        assert!(flagged, "{name} is not flagged as absent or omitted");
    }
    Ok(())
}

#[test]
fn outcomes_and_priorities_documented() -> TestResult {
    let docs = docs()?;
    for op in Operation::all() {
        let section = outcome_section(&docs, op);
        let rows: Vec<_> = section
            .iter()
            .map(|l| cells(l))
            .filter(|c| c.first().is_some_and(|n| n.starts_with('`')))
            .collect();
        let want = outcome_pairs(op);
        assert_eq!(rows.len(), want.len(), "outcome rows of {}", op.name());
        for (name, prio) in want {
            let found = rows.iter().any(|c| {
                c.first() == Some(&token(name).as_str())
                    && c.get(1) == Some(&prio.to_string().as_str())
                    && c.get(2).is_some_and(|m| !m.is_empty())
            });
            assert!(found, "no table row for {name} of {}", op.name());
        }
    }
    Ok(())
}

#[test]
fn operations_documented() -> TestResult {
    let docs = docs()?;
    let row = docs
        .lines()
        .find(|l| cells(l).first() == Some(&token("CUSTODIO_OPERATION").as_str()))
        .ok_or("no row for CUSTODIO_OPERATION")?;
    assert_eq!(cells(row).get(2), Some(&"always"));
    for op in Operation::all() {
        assert!(
            row.contains(&token(op.name())),
            "field row lacks {}",
            op.name()
        );
    }
    Ok(())
}

#[test]
fn mechanisms_documented() -> TestResult {
    let docs = docs()?;
    for m in mechanisms() {
        assert!(docs.contains(&token(m.name())), "docs lack {}", m.name());
    }
    Ok(())
}

#[test]
fn message_example_in_docs() -> TestResult {
    let docs = docs()?;
    for o in outcomes() {
        let msg = full(o)?.message();
        assert!(docs.contains(&msg), "docs lack example: {msg}");
    }
    for e in operation_entries()? {
        let msg = e.message();
        assert!(docs.contains(&msg), "docs lack example: {msg}");
    }
    let unknown = Entry::without_caller(key()?, None).message();
    assert!(docs.contains(&unknown), "docs lack example: {unknown}");
    for name in names(&full(Outcome::Signed)?) {
        let row = docs
            .lines()
            .find(|l| cells(l).first() == Some(&token(name).as_str()));
        let row = row.ok_or_else(|| format!("no table row for {name}"))?;
        assert!(
            cells(row).get(1).is_some_and(|m| !m.is_empty()),
            "{name} has no meaning"
        );
    }
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
    let ids: Vec<_> = Operation::all().iter().map(|o| o.message_id()).collect();
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
fn query_uses_trusted_fields() -> TestResult {
    let docs = docs()?;
    let id = format!("MESSAGE_ID={MESSAGE_ID}");
    let queries: Vec<_> = docs
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("journalctl"))
        .collect();
    assert!(
        queries
            .iter()
            .any(|q| q.contains("_SYSTEMD_UNIT=custodio.service")
                && q.contains("_UID=")
                && q.contains(&id))
    );
    for field in ["CUSTODIO_UID=", "CUSTODIO_KEY_ID=", "CUSTODIO_OUTCOME="] {
        assert!(
            queries
                .iter()
                .any(|q| q.contains(field) && q.contains("_SYSTEMD_UNIT=custodio.service")),
            "no example query with {field}"
        );
    }
    for op in Operation::all() {
        let want = format!("CUSTODIO_OPERATION={}", op.name());
        assert!(
            queries
                .iter()
                .any(|q| q.split_whitespace().any(|t| t == want)
                    && q.split_whitespace()
                        .any(|t| t == "_SYSTEMD_UNIT=custodio.service")
                    && q.split_whitespace().any(|t| t.starts_with("_UID="))),
            "no query for {}",
            op.name()
        );
    }
    assert!(docs.contains("id -u custodio"));
    assert!(read("data/sysusers.d/custodio.conf")?.contains("u custodio"));
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
                "CUSTODIO_UID" => value.bytes().all(|b| b.is_ascii_digit()) && !value.is_empty(),
                "CUSTODIO_KEY_ID" => KeyId::new(value).is_ok(),
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

mod app_id;
use app_id::app;
