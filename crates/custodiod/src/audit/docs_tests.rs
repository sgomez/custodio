//! Ties the audit code to `docs/audit.md` and `data/custodio.catalog`, so they cannot drift.
use super::*;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

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

fn full(o: Outcome) -> Result<Entry, InvalidKeyId> {
    Ok(Entry::new(
        o,
        Caller {
            uid: 1000,
            pid: 4242,
        },
        key()?,
        Some(AuditMechanism::Ecdsa),
    ))
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
    assert!(docs()?.contains(MESSAGE_ID));
    assert!(catalog()?.contains(MESSAGE_ID));
    Ok(())
}

#[test]
fn every_field_name_in_docs_and_catalog() -> TestResult {
    let (docs, catalog) = (docs()?, catalog()?);
    let all = names(&full(Outcome::Signed)?);
    assert!(all.len() >= 9);
    for name in all {
        assert!(docs.contains(&token(name)), "docs lack {name}");
        assert!(catalog.contains(&token(name)), "catalog lacks {name}");
    }
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
        ["CUSTODIO_MECHANISM", "CUSTODIO_PID", "CUSTODIO_UID"]
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
    for o in outcomes() {
        let found = docs.lines().any(|l| {
            let c = cells(l);
            c.first() == Some(&token(o.name()).as_str())
                && c.get(1) == Some(&o.priority().to_string().as_str())
        });
        assert!(found, "no table row for {}", o.name());
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
fn limits_and_compatibility_documented() -> TestResult {
    let docs = docs()?;
    let mut lines = docs.lines();
    let heading = lines
        .by_ref()
        .find(|l| l.starts_with('#') && l.to_lowercase().contains("not guaranteed"));
    assert!(heading.is_some(), "no 'Not guaranteed' heading");
    let section = lines
        .take_while(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    for word in ["person", "pid reuse", "rate limit", "volatile", "imitat"] {
        assert!(section.contains(word), "'Not guaranteed' lacks {word}");
    }
    let rule = docs.lines().any(|l| {
        let l = l.to_lowercase();
        l.contains("names")
            && l.contains("identifier")
            && l.contains("priorities")
            && l.contains("only added to")
            && l.contains("never changed")
    });
    assert!(rule, "compatibility rule missing");
    Ok(())
}

#[test]
fn catalog_format() -> TestResult {
    let catalog = catalog()?;
    let mut lines = catalog.lines().filter(|l| !l.starts_with('#'));
    assert_eq!(lines.next(), Some(format!("-- {MESSAGE_ID}").as_str()));
    assert!(
        MESSAGE_ID.len() == 32
            && MESSAGE_ID
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    );
    let rest: Vec<_> = lines.collect();
    assert_eq!(rest.iter().filter(|l| l.starts_with("Subject:")).count(), 1);
    assert_eq!(
        rest.iter()
            .filter(|l| **l == "Defined-By: custodio")
            .count(),
        1
    );
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
    assert!(docs.contains("data/sysusers.d/custodio.conf") && docs.contains("id -u custodio"));
    assert!(read("data/sysusers.d/custodio.conf")?.contains("u custodio"));
    Ok(())
}
