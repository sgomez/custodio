//! The flatpak app-id section of `docs/audit.md`.

use super::*;

/// A read app-id, so that the entries carry every field.
pub(super) fn app() -> AppIdOutcome {
    crate::app_id::validate(b"org.example.App")
        .map_or(AppIdOutcome::Undetermined, AppIdOutcome::Read)
}

#[test]
fn app_id_cases_fields_and_queries_documented() -> TestResult {
    let docs = docs()?;
    let section: Vec<&str> = docs
        .lines()
        .skip_while(|l| *l != "## Flatpak app-id")
        .skip(1)
        .take_while(|l| !l.starts_with("## "))
        .collect();
    let section = section.join("\n");
    assert_ne!(section, "");
    for case in [AppIdOutcome::None, AppIdOutcome::Undetermined, app()] {
        let row = format!("| `{}` |", app_id_state(&case));
        assert!(section.contains(&row), "no row for {}", app_id_state(&case));
    }
    for name in [APP_ID_FIELD, APP_ID_STATE_FIELD] {
        assert!(docs.contains(&token(name)), "docs lack {name}");
    }
    // The bound of the lookup is the constant of the code.
    let bound = crate::app_id_source::LOOKUP_DEADLINE;
    assert_eq!(bound.subsec_nanos(), 0);
    // e2e/appid_journal.py reads the bound from this sentence.
    assert!(section.contains(&format!(
        "longer than {} s (the bound, `LOOKUP_DEADLINE`)",
        bound.as_secs()
    )));
    assert!(section.contains(&format!("at most {} s", bound.as_secs())));
    // The queries by app-id and by each case.
    let queries: Vec<&str> = docs
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("journalctl"))
        .collect();
    let has = |term: &str| {
        queries
            .iter()
            .any(|q| q.split_whitespace().any(|t| t == term))
    };
    assert!(has("CUSTODIO_APP_ID=org.example.App"));
    for case in [AppIdOutcome::None, AppIdOutcome::Undetermined, app()] {
        assert!(has(&format!(
            "{APP_ID_STATE_FIELD}={}",
            app_id_state(&case)
        )));
    }
    Ok(())
}
