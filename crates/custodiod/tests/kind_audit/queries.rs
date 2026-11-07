//! The queries `docs/audit.md` gives for the new fields: each is read from the page and applied to the entries the rows
//! produce, with a matcher written here from the journal's rule (every `NAME=value` term must hold).
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodiod::audit::{Entry, OperationEntry};
use zbus::block_on;

use crate::case::{Case, Fail};
use crate::kit::{Family, STORAGES, Setup};
use crate::rig::{SUBJECTS, TestResult};

/// An entry as the journal would hold it, with what the typed entry says about it, read independently of `fields()`.
struct Seen {
    fields: Vec<(&'static str, String)>,
    operation: &'static str,
    outcome: &'static str,
    kind: Option<&'static str>,
    cause: Option<&'static str>,
}

impl Seen {
    fn import(e: &OperationEntry) -> Self {
        Self {
            fields: e.fields(),
            operation: e.operation().name(),
            outcome: e.outcome_name(),
            kind: e.storage_kind().map(custodiod::store::Kind::wire),
            cause: e.cause().map(custodiod::audit::ImportCause::name),
        }
    }

    fn sign(e: &Entry) -> Self {
        Self {
            fields: e.fields(),
            operation: "sign",
            outcome: e.outcome().name(),
            kind: e.storage_kind().map(custodiod::store::Kind::wire),
            cause: e.cause().map(custodiod::audit::SignCause::name),
        }
    }

    /// What the typed entry says a term should select.
    fn says(&self, name: &str, value: &str) -> bool {
        match name {
            "CUSTODIO_OPERATION" => self.operation == value,
            "CUSTODIO_OUTCOME" => self.outcome == value,
            "CUSTODIO_STORAGE_KIND" => self.kind == Some(value),
            "CUSTODIO_CAUSE" => self.cause == Some(value),
            other => panic!("a term {other} the page uses for these queries is not modelled"),
        }
    }
}

/// The `NAME=value` terms of a query after the trusted ones, and whether it names the unit and the user.
fn terms(query: &str) -> (Vec<(String, String)>, bool) {
    let mut unit = false;
    let mut uid = false;
    let mut rest = Vec::new();
    let query = query.replace("$(id -u custodio)", "UID_OF_CUSTODIO");
    for term in query.split_whitespace().skip(1) {
        let (n, v) = term.split_once('=').unwrap();
        match n {
            "_SYSTEMD_UNIT" => unit = v == "custodio.service",
            "_UID" => uid = true,
            _ => rest.push((n.to_owned(), v.to_owned())),
        }
    }
    (rest, unit && uid)
}

/// The journal's rule: a term holds when the entry has the field with that value; all terms must hold.
fn selects(terms: &[(String, String)], entry: &Seen) -> bool {
    terms.iter().all(|(n, v)| {
        entry
            .fields
            .iter()
            .any(|(fname, fval)| fname == n && fval == v)
    })
}

fn all_entries() -> Vec<Seen> {
    let mut seen = Vec::new();
    let rsa = SUBJECTS[0];
    seen.extend(
        crate::import::entries_for_queries(rsa)
            .iter()
            .map(Seen::import),
    );
    block_on(async {
        // Signatures that succeed, for each kind, and the ways a key stops working.
        for storage in STORAGES {
            let setup = Setup::new(storage, rsa).await.unwrap();
            setup.sign(Family::of(rsa)[0]).await.unwrap();
            seen.extend(setup.svc.sink.entries().iter().map(Seen::sign));
        }
        for fail in Fail::ALL {
            let case = Case::new(fail, rsa).await.unwrap();
            case.break_it();
            case.setup.sign(Family::of(rsa)[0]).await.unwrap_err();
            seen.extend(case.setup.svc.sink.entries().iter().map(Seen::sign));
        }
    });
    seen
}

/// The page's queries for the kind, the cause, the lost key and the failed import select what they describe.
#[test]
fn documented_queries() -> TestResult {
    let docs =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/audit.md"))?;
    let queries: Vec<_> = docs
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("journalctl"))
        .collect();
    let seen = all_entries();
    let mut checked = Vec::new();
    for query in queries {
        let (terms, trusted) = terms(query);
        let new = terms
            .iter()
            .any(|(n, _)| n == "CUSTODIO_STORAGE_KIND" || n == "CUSTODIO_CAUSE")
            || terms
                == [
                    ("CUSTODIO_OPERATION".to_owned(), "import".to_owned()),
                    ("CUSTODIO_OUTCOME".to_owned(), "storage_failure".to_owned()),
                ];
        if !new {
            continue;
        }
        assert!(trusted, "{query}: names _SYSTEMD_UNIT and _UID");
        let picked: Vec<_> = seen.iter().filter(|e| selects(&terms, e)).collect();
        let described: Vec<_> = seen
            .iter()
            .filter(|e| terms.iter().all(|(n, v)| e.says(n, v)))
            .collect();
        assert!(!picked.is_empty(), "{query} selects nothing");
        assert!(picked.len() < seen.len(), "{query} selects everything");
        assert_eq!(picked.len(), described.len(), "{query}");
        assert!(
            picked
                .iter()
                .all(|p| described.iter().any(|d| std::ptr::eq(*p, *d))),
            "{query}: selects what it does not describe"
        );
        checked.push(terms);
    }
    let has = |n: &str, v: &str| {
        checked
            .iter()
            .any(|t| t.iter().any(|(tn, tv)| tn == n && tv == v))
    };
    // A query for each: the kind, the cause of an import, the lost key, and a failed import.
    assert!(
        checked
            .iter()
            .any(|t| t.iter().any(|(n, _)| n == "CUSTODIO_STORAGE_KIND"))
    );
    assert!(has("CUSTODIO_CAUSE", "key_lost"));
    assert!(checked.iter().any(|t| {
        t.iter().any(|(n, _)| n == "CUSTODIO_CAUSE")
            && t.iter()
                .any(|(n, v)| n == "CUSTODIO_OPERATION" && v == "import")
    }));
    assert!(has("CUSTODIO_OUTCOME", "storage_failure"));
    // The lost-key query selects the signatures of the lost rows and no other entry.
    let lost: Vec<_> = seen
        .iter()
        .filter(|e| e.cause == Some("key_lost"))
        .collect();
    assert_eq!(lost.len(), Fail::ALL.iter().filter(|f| f.lost()).count());
    assert!(lost.iter().all(|e| e.operation == "sign"));
    Ok(())
}
