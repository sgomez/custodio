use std::sync::atomic::Ordering;

use super::sign_call::{rig, seed};
use super::*;
use crate::import::cert_id;

type R = Result<(), Box<dyn std::error::Error>>;

fn delete(r: &super::sign_call::Rig, sender: Option<&str>, id: &str) -> Result<(), ServiceError> {
    zbus::block_on(r.service.delete_call(sender, id))
}

#[test]
fn polkit_outcomes_map_to_their_errors_and_keep_the_key() -> R {
    type Answer = fn() -> Result<(), AuthError>;
    let cases: [(Answer, ServiceError); 3] = [
        (|| Err(AuthError::Denied), ServiceError::PolkitDenied),
        (
            || Err(AuthError::BadSender),
            ServiceError::AuthorizationUnavailable,
        ),
        (
            || Err(AuthError::Unavailable("x".into())),
            ServiceError::AuthorizationUnavailable,
        ),
    ];
    for (result, want) in cases {
        let r = rig(result)?;
        seed(&r, "k")?;
        assert_eq!(delete(&r, Some(":1.1"), "k"), Err(want));
        assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
        assert_eq!(r.store.list(11)?, ["k", "k-cert"]);
        assert_eq!(r.sink.entries().len(), 0);
    }
    Ok(())
}

#[test]
fn an_approved_delete_removes_both_files_of_the_caller_only() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    seed(&r, "keep")?;
    // The same id under another uid.
    crate::import::import_p12(
        &r.store,
        12,
        "k",
        super::sign_call::P12,
        &SecretString::from("test-password".to_owned()),
    )?;
    assert_eq!(delete(&r, Some(":1.1"), "k"), Ok(()));
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(r.store.list(11)?, ["keep", "keep-cert"]);
    assert_eq!(r.store.list(12)?, ["k", "k-cert"]);
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
    assert_eq!(r.store.list(11)?, ["k", "k-cert"]);
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
    assert!(r.store.dir().join("11").join(cert_id("k")).exists());
    Ok(())
}
