//! The earlier format is recognised, never read.

use super::*;

const MARKER: &[u8] = b"LEGACY-KEY-CONTENT-MARKER";

fn der(marker: &[u8]) -> Vec<u8> {
    let mut v = vec![0x30, 0x82, 0x01, 0x00];
    v.extend(marker);
    v
}

#[test]
fn legacy_files_are_recognised_not_read() -> TestResult {
    let (_tmp, store) = fresh();
    plant(&store, OWNER, "old", &der(MARKER));
    plant(&store, OWNER, "old-cert", &der(b"cert"));
    plant(&store, OWNER, "orphan-cert", &der(b"cert"));
    store.put(&host("new", b"cert"))?;
    plant(&store, 7, "other", &der(MARKER));

    let err = store.get(OWNER, "old").unwrap_err();
    assert!(
        matches!(err, custodiod::store::StoreError::Legacy),
        "{err:?}"
    );
    assert!(!format!("{err:?} {err}").contains("MARKER"));
    assert!(matches!(
        store.get(OWNER, "old-cert"),
        Err(custodiod::store::StoreError::Legacy)
    ));
    assert!(store.get(OWNER, "new").is_ok());

    let entries = store.legacy(OWNER)?;
    let ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(
        ids,
        ["old", "orphan"],
        "one entry per key; the new record is not listed"
    );
    assert_eq!(entries[0].files, ["old", "old-cert"]);
    assert_eq!(entries[1].files, ["orphan-cert"]);
    assert!(entries.iter().all(|e| e.owner == Some(OWNER)));
    assert!(!format!("{entries:?}").contains("MARKER"));
    let all: Vec<(Option<u32>, String)> = store
        .legacy_all()?
        .into_iter()
        .map(|e| (e.owner, e.id))
        .collect();
    assert_eq!(
        all,
        [
            (Some(7), "other".to_owned()),
            (Some(OWNER), "old".to_owned()),
            (Some(OWNER), "orphan".to_owned())
        ]
    );
    // Nothing was changed.
    assert_eq!(std::fs::read(area(&store, OWNER).join("old"))?, der(MARKER));
    Ok(())
}

#[test]
fn a_legacy_looking_file_under_a_bad_mode_is_a_file_rule_error() {
    let (_tmp, store) = fresh();
    let path = plant(&store, OWNER, "old", &der(MARKER));
    set_mode(&path, 0o644);
    assert!(matches!(
        store.get(OWNER, "old"),
        Err(custodiod::store::StoreError::BadPermissions(_))
    ));
}
