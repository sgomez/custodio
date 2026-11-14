use super::*;

#[test]
fn fields_carry_the_verdict_and_the_fixed_parts() {
    for (storage, priority) in [
        (StateStorage::Encrypted, "6"),
        (StateStorage::NotEncrypted, "4"),
        (StateStorage::Unknown, "4"),
    ] {
        let f = fields(storage);
        let get = |n: &str| f.iter().find(|(k, _)| *k == n).map(|(_, v)| v.as_str());
        assert_eq!(get(STATE_STORAGE_FIELD), Some(storage.name()));
        assert_eq!(get("PRIORITY"), Some(priority));
        assert_eq!(get("MESSAGE_ID"), Some(STATE_STORAGE_MESSAGE_ID));
        assert_eq!(get("SYSLOG_IDENTIFIER"), Some("custodiod"));
        assert!(get("MESSAGE").is_some_and(|m| m.ends_with(storage.name())));
        assert_eq!(f.len(), 5, "no caller, key or operation field");
    }
}

#[test]
fn the_documents_name_the_entry() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let docs = std::fs::read_to_string(root.join("docs/audit.md"))?;
    assert!(docs.contains(STATE_STORAGE_MESSAGE_ID));
    assert!(docs.contains(STATE_STORAGE_FIELD));
    let api = std::fs::read_to_string(root.join("docs/api.md"))?;
    for s in StateStorage::all() {
        assert!(
            docs.contains(s.name()) && api.contains(s.name()),
            "{}",
            s.name()
        );
    }
    Ok(())
}
