use std::sync::atomic::Ordering;

use super::sign_call::{Counting, Creds, rig, seed};
use super::*;
use crate::audit::FailingSink;

type R = Result<(), Box<dyn std::error::Error>>;

/// Runs `f` to the end. A delete that waits for a lock nobody releases would stop the test run, so
/// after 20 s the process exits and the run fails instead.
pub(super) fn guarded<T>(f: impl Future<Output = T>) -> T {
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&done);
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(20));
        if !seen.load(Ordering::SeqCst) {
            eprintln!("a delete did not finish: is a lock never released?");
            std::process::exit(101);
        }
    });
    let out = zbus::block_on(f);
    done.store(true, Ordering::SeqCst);
    out
}

fn delete(r: &super::sign_call::Rig, sender: Option<&str>, id: &str) -> Result<(), ServiceError> {
    guarded(r.service.delete_call(sender, id))
}

#[test]
fn polkit_outcomes_map_to_their_errors_and_keep_the_key() -> R {
    type Answer = fn() -> Result<(), AuthError>;
    let cases: [(Answer, ServiceError, &str); 3] = [
        (
            || Err(AuthError::Denied),
            ServiceError::PolkitDenied,
            "denied",
        ),
        (
            || Err(AuthError::BadSender),
            ServiceError::AuthorizationUnavailable,
            "authorization_unavailable",
        ),
        (
            || Err(AuthError::Unavailable("x".into())),
            ServiceError::AuthorizationUnavailable,
            "authorization_unavailable",
        ),
    ];
    for (result, want, outcome) in cases {
        let r = rig(result)?;
        seed(&r, "k")?;
        assert_eq!(delete(&r, Some(":1.1"), "k"), Err(want));
        assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
        assert_eq!(r.store.list(11)?, ["k"]);
        assert_eq!(r.sink.entries().len(), 0);
        // One entry, whatever polkit said, and it says why the key was kept.
        let entries = r.sink.operation_entries();
        assert_eq!(entries.len(), 1);
        let e = entries.first().ok_or("no entry")?;
        assert_eq!(e.operation(), crate::audit::Operation::Delete);
        assert_eq!(e.caller(), Some(Caller { uid: 11, pid: 22 }));
        assert_eq!(e.key_id().as_str(), "k");
        assert_eq!(e.outcome_name(), outcome);
    }
    Ok(())
}

#[test]
fn an_approved_delete_removes_the_record_of_the_caller_only() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    seed(&r, "keep")?;
    // The same id under another uid.
    crate::import::import_p12(
        &r.store,
        &crate::creds::memory::MemoryCreds::host(),
        12,
        "k",
        super::sign_call::P12,
        &SecretString::from("test-password".to_owned()),
    )?;
    assert_eq!(delete(&r, Some(":1.1"), "k"), Ok(()));
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(r.store.list(11)?, ["keep"]);
    assert_eq!(r.store.list(12)?, ["k"]);
    assert_eq!(delete(&r, Some(":1.1"), "k"), Err(ServiceError::NoSuchKey));
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn refusals_before_polkit_ask_nothing() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    assert_eq!(
        delete(&r, None, "k"),
        Err(ServiceError::AuthorizationUnavailable)
    );
    assert_eq!(
        delete(&r, Some(":1.1"), "k-cert"),
        Err(ServiceError::InvalidArgs)
    );
    assert_eq!(delete(&r, Some(":1.1"), "no"), Err(ServiceError::NoSuchKey));
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 0);
    // Only the missing id reaches the credentials: no sender has none, a bad id is refused first.
    assert_eq!(r.cred_calls.load(Ordering::SeqCst), 1);
    assert_eq!(r.store.list(11)?, ["k"]);
    Ok(())
}

#[test]
fn a_key_that_cannot_be_read_is_internal_before_polkit() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    std::fs::remove_file(r.store.dir().join("11").join("k"))?;
    std::fs::create_dir(r.store.dir().join("11").join("k"))?;
    assert_eq!(delete(&r, Some(":1.1"), "k"), Err(ServiceError::Internal));
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 0);
    // The directory that took the place of the record is untouched.
    assert!(r.store.dir().join("11").join("k").is_dir());
    Ok(())
}

#[test]
fn an_approved_delete_records_deleted_and_a_missing_sender_records_unavailable() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    assert_eq!(
        delete(&r, None, "k"),
        Err(ServiceError::AuthorizationUnavailable)
    );
    assert_eq!(delete(&r, Some(":1.1"), "k"), Ok(()));
    let outcomes: Vec<_> = r
        .sink
        .operation_entries()
        .iter()
        .map(|e| (e.outcome_name(), e.caller()))
        .collect();
    assert_eq!(
        outcomes,
        [
            ("authorization_unavailable", None),
            ("deleted", Some(Caller { uid: 11, pid: 22 }))
        ]
    );
    // Refusals before authorization leave no entry.
    assert_eq!(delete(&r, Some(":1.1"), "k"), Err(ServiceError::NoSuchKey));
    assert_eq!(
        delete(&r, Some(":1.1"), "bad id"),
        Err(ServiceError::InvalidArgs)
    );
    assert_eq!(r.sink.operation_entries().len(), 2);
    Ok(())
}

#[test]
fn a_sink_that_fails_restores_the_key_and_the_lock_is_free_again() -> R {
    let r = rig(|| Ok(()))?;
    let failing = Custodio::new(
        r.store.clone(),
        Counting {
            result: || Ok(()),
            calls: r.auth_calls.clone(),
        },
        Creds(r.cred_calls.clone()),
        Arc::new(FailingSink),
    )
    .with_key_credentials(std::sync::Arc::new(
        crate::creds::memory::MemoryCreds::host(),
    ));
    seed(&r, "k")?;
    let before = r.store.list(11)?;
    for _ in 0..2 {
        // A second round shows the lock of the first was released.
        let got = guarded(failing.delete_call(Some(":1.1"), "k"));
        assert_eq!(got, Err(ServiceError::AuditUnavailable));
        assert_eq!(r.store.list(11)?, before);
        assert!(!failing.deletes.is_unusable(11, "k"));
        assert_eq!(failing.deletes.locked(), 0);
    }
    // Sign and list see the key again.
    assert_eq!(
        zbus::block_on(failing.list_keys_call(Some(":1.1")))?.len(),
        1
    );
    Ok(())
}

/// A sink that records nothing but makes the removal that follows fail: it loosens the record's mode.
struct LoosenSink(std::path::PathBuf);

impl crate::audit::AuditSink for LoosenSink {
    fn record(&self, _: &crate::audit::Entry) -> Result<(), crate::audit::AuditError> {
        Ok(())
    }

    fn record_operation(
        &self,
        _: &crate::audit::OperationEntry,
    ) -> Result<(), crate::audit::AuditError> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| crate::audit::AuditError::Io(e.kind()))
    }
}

#[test]
fn a_removal_that_fails_leaves_the_key_unusable_for_sign_and_list() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    // The record passes the lookup, and its mode is loosened once the entry went out: the removal fails.
    let service = Custodio::new(
        r.store.clone(),
        Counting {
            result: || Ok(()),
            calls: r.auth_calls.clone(),
        },
        Creds(r.cred_calls.clone()),
        Arc::new(LoosenSink(r.store.dir().join("11").join("k"))),
    )
    .with_key_credentials(Arc::new(crate::creds::memory::MemoryCreds::host()));
    let got = guarded(service.delete_call(Some(":1.1"), "k"));
    assert_eq!(got, Err(ServiceError::Internal));
    assert!(service.deletes.is_unusable(11, "k"));
    assert_eq!(service.deletes.locked(), 0);
    assert_eq!(
        zbus::block_on(service.list_keys_call(Some(":1.1")))?.len(),
        0
    );
    let signed = zbus::block_on(service.sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"));
    assert_eq!(signed, Err(ServiceError::NoSuchKey));
    assert_eq!(r.sink.entries().len(), 0);
    Ok(())
}
