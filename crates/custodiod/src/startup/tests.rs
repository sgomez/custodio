use super::*;
use crate::audit::{FailingSink, MemorySink};

#[test]
fn errors_say_what_stopped_the_start() {
    let store = PurgeError::Store(StoreError::TooLarge);
    assert!(
        store
            .to_string()
            .contains(&StoreError::TooLarge.to_string())
    );
    let audit = PurgeError::Audit(AuditError::TooLarge);
    assert!(
        audit
            .to_string()
            .contains(&AuditError::TooLarge.to_string())
    );
    assert_ne!(store.to_string(), audit.to_string());
    let start = StartError::Purge(PurgeError::Store(StoreError::TooLarge));
    assert!(start.to_string().contains(&store.to_string()));
    let bus = StartError::Bus(zbus::Error::Unsupported);
    assert!(
        bus.to_string()
            .contains(&zbus::Error::Unsupported.to_string())
    );
    assert_ne!(start.to_string(), bus.to_string());
}

#[test]
fn a_store_without_legacy_keys_purges_nothing() -> Result<(), Box<dyn Error>> {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    let sink = MemorySink::default();
    assert_eq!(purge_legacy(&store, &sink)?, []);
    assert_eq!(sink.operation_entries(), []);
    // With nothing to write, a sink that fails is never asked.
    assert_eq!(purge_legacy(&store, &FailingSink)?, []);
    Ok(())
}
