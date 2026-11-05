//! The storage kinds and causes the code can emit against `docs/audit.md`.
use super::*;

/// Every storage kind; the exhaustive match stops compiling when a variant is added.
pub(super) fn store_kinds() -> [StorageKind; 3] {
    match StorageKind::Tpm {
        StorageKind::Tpm | StorageKind::EncryptedTpm | StorageKind::EncryptedHost => [
            StorageKind::Tpm,
            StorageKind::EncryptedTpm,
            StorageKind::EncryptedHost,
        ],
    }
}

pub(super) fn cause_names() -> BTreeSet<&'static str> {
    let import = ImportCause::all().map(ImportCause::name);
    let sign = SignCause::all().map(SignCause::name);
    import.into_iter().chain(sign).collect()
}

/// The first cell of the table rows under the heading `### <heading>` or `## <heading>`, with the priority cell.
fn rows_under(docs: &str, heading: &str) -> Vec<(String, String)> {
    docs.lines()
        .skip_while(|l| *l != heading)
        .skip(1)
        .take_while(|l| !l.starts_with('#'))
        .filter(|l| l.starts_with('|'))
        .map(cells)
        .filter(|c| c.first().is_some_and(|n| n.starts_with('`')))
        .map(|c| {
            let strip = |t: &str| t.trim_matches('`').to_owned();
            (
                c.first().map(|n| strip(n)).unwrap_or_default(),
                c.get(1).map(|p| strip(p)).unwrap_or_default(),
            )
        })
        .collect()
}

/// Whether `docs` lists exactly the kinds and causes the code can emit, the causes with the priority of their outcome.
fn kinds_and_causes_match(docs: &str) -> Result<(), String> {
    let kinds: BTreeSet<_> = rows_under(docs, "## Storage kind")
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    let want: BTreeSet<_> = store_kinds().iter().map(|k| k.wire().to_owned()).collect();
    if kinds != want {
        return Err(format!(
            "storage kinds: documented {kinds:?}, emitted {want:?}"
        ));
    }
    let table = [
        (
            "### import causes",
            ImportCause::all().map(ImportCause::name).to_vec(),
            ImportOutcome::StorageFailure.priority(),
        ),
        (
            "### sign causes",
            SignCause::all().map(SignCause::name).to_vec(),
            Outcome::SigningFailed.priority(),
        ),
    ];
    for (heading, names, priority) in table {
        let rows = rows_under(docs, heading);
        let want: Vec<_> = names
            .iter()
            .map(|n| ((*n).to_owned(), priority.to_string()))
            .collect();
        if rows != want {
            return Err(format!("{heading}: documented {rows:?}, emitted {want:?}"));
        }
    }
    Ok(())
}

#[test]
fn kinds_and_causes_documented() -> TestResult {
    let docs = docs()?;
    kinds_and_causes_match(&docs)?;
    // The two lists share no value, so a query by cause names its operation without saying so.
    let import: BTreeSet<_> = ImportCause::all()
        .map(ImportCause::name)
        .into_iter()
        .collect();
    let sign: BTreeSet<_> = SignCause::all().map(SignCause::name).into_iter().collect();
    assert!(import.is_disjoint(&sign));
    // Every kind and cause is also in the catalog's text of its entry.
    let catalog = catalog()?;
    for field in ["CUSTODIO_STORAGE_KIND", "CUSTODIO_CAUSE"] {
        assert!(catalog.contains(&token(field)), "the catalog lacks {field}");
    }
    Ok(())
}

/// Negative control: a row removed from, or invented in, a copy of the page is reported.
#[test]
fn kinds_and_causes_control() -> TestResult {
    let docs = docs()?;
    let rows: Vec<&str> = docs
        .lines()
        .filter(|l| {
            let c = cells(l);
            c.first()
                .is_some_and(|n| cause_names().iter().any(|v| *n == token(v)))
                || store_kinds()
                    .iter()
                    .any(|k| c.first() == Some(&token(k.wire()).as_str()))
        })
        .collect();
    assert_eq!(rows.len(), cause_names().len() + 3);
    for row in rows {
        let edited = docs.replacen(&format!("{row}\n"), "", 1);
        assert_ne!(edited, docs);
        assert!(kinds_and_causes_match(&edited).is_err(), "{row}");
    }
    let invented = docs.replacen(
        "| `store` | 3 |",
        "| `invented` | 3 | x |\n| `store` | 3 |",
        1,
    );
    assert!(kinds_and_causes_match(&invented).is_err());
    let wrong_priority = docs.replacen("| `tpm_device` | 3 |", "| `tpm_device` | 4 |", 1);
    assert!(kinds_and_causes_match(&wrong_priority).is_err());
    Ok(())
}
