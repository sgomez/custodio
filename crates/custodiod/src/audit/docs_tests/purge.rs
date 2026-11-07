//! The purge entry against the page, with edited copies that must fail.
use super::*;

/// What the page must say of the purge entry, from the code: the outcome row with its priority, the identifier row,
/// the owner field row, the message example and a query.
fn purge_matches(docs: &str) -> Result<(), String> {
    let entry = OperationEntry::purge(Some(1000), key().map_err(|e| e.to_string())?);
    let rows = outcome_section(docs, Operation::Purge);
    let outcome = format!("| {} | {} |", token(entry.outcome_name()), entry.priority());
    if !rows.iter().any(|l| l.starts_with(&outcome)) {
        return Err(format!("no outcome row {outcome}"));
    }
    let id = format!(
        "| {} | {} |",
        token(Operation::Purge.name()),
        token(Operation::Purge.message_id())
    );
    let owner = format!("| {} |", token("CUSTODIO_OWNER_UID"));
    for want in [id, owner, entry.message()] {
        if !docs.contains(&want) {
            return Err(format!("the page lacks {want}"));
        }
    }
    let query = format!("CUSTODIO_OPERATION={}", Operation::Purge.name());
    if !docs
        .lines()
        .any(|l| l.trim().starts_with("journalctl") && l.contains(&query))
    {
        return Err("no query".to_owned());
    }
    Ok(())
}

#[test]
fn purge_is_documented_and_the_check_can_fail() -> TestResult {
    let docs = docs()?;
    assert_eq!(purge_matches(&docs), Ok(()));
    let entry = OperationEntry::purge(Some(1000), key()?);
    let outcome = format!("| {} | {} |", token("purged"), entry.priority());
    for (what, edited) in [
        ("outcome row", docs.replacen(&outcome, "| `other` | 4 |", 1)),
        (
            "priority",
            docs.replacen(
                &outcome,
                &format!("| `purged` | {} |", entry.priority() + 1),
                1,
            ),
        ),
        (
            "identifier",
            docs.replacen(Operation::Purge.message_id(), "0", 1),
        ),
        (
            "owner field",
            docs.replace(&token("CUSTODIO_OWNER_UID"), "`X`"),
        ),
        ("message", docs.replace(&entry.message(), "x")),
        (
            "query",
            docs.replace("CUSTODIO_OPERATION=purge", "CUSTODIO_OPERATION=x"),
        ),
    ] {
        assert_ne!(edited, docs, "{what}");
        assert!(purge_matches(&edited).is_err(), "{what}");
    }
    Ok(())
}
