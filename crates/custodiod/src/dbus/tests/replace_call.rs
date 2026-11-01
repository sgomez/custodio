//! `replace_call` with counting doubles: the order of the checks and the error mapping.

use std::sync::atomic::Ordering;

use super::sign_call::{rig, seed};
use super::*;

type R = Result<(), Box<dyn std::error::Error>>;

const RECERT: &[u8] = include_bytes!("../../../tests/fixtures/cert-p256-recert.der");
const OTHER: &[u8] = include_bytes!("../../../tests/fixtures/cert-p256-other.der");

fn replace(
    r: &super::sign_call::Rig,
    sender: Option<&str>,
    id: &str,
    cert: &[u8],
) -> Result<(), ServiceError> {
    zbus::block_on(r.service.replace_call(sender, id, cert))
}

fn cert_on_disk(
    r: &super::sign_call::Rig,
    id: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(std::fs::read(r.store.dir().join("11").join(cert_id(id)))?)
}

#[test]
fn an_approved_replace_stores_the_certificate_and_asks_once() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    assert_eq!(replace(&r, Some(":1.1"), "k", RECERT), Ok(()));
    assert_eq!(cert_on_disk(&r, "k")?, RECERT);
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(r.service.deletes.locked(), 0);
    // No journal entry yet.
    assert_eq!(r.sink.entries().len(), 0);
    assert_eq!(r.sink.operation_entries().len(), 0);
    Ok(())
}

#[test]
fn polkit_outcomes_map_to_their_errors_and_change_nothing() -> R {
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
        let before = cert_on_disk(&r, "k")?;
        assert_eq!(replace(&r, Some(":1.1"), "k", RECERT), Err(want));
        assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cert_on_disk(&r, "k")?, before);
        assert_eq!(r.service.deletes.locked(), 0);
    }
    Ok(())
}

#[test]
fn refusals_before_polkit_ask_nothing_and_arguments_come_first() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    let before = cert_on_disk(&r, "k")?;
    // Arguments first: no sender and a bad id or certificate is `InvalidArgs`, with no lookup.
    assert_eq!(
        replace(&r, None, "k-cert", RECERT),
        Err(ServiceError::InvalidArgs)
    );
    assert_eq!(
        replace(&r, None, "k", b"junk"),
        Err(ServiceError::InvalidArgs)
    );
    assert_eq!(r.cred_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        replace(&r, None, "k", RECERT),
        Err(ServiceError::AuthorizationUnavailable)
    );
    assert_eq!(r.cred_calls.load(Ordering::SeqCst), 0);
    // A missing key is refused after the credentials and before polkit.
    assert_eq!(
        replace(&r, Some(":1.1"), "no", RECERT),
        Err(ServiceError::NoSuchKey)
    );
    assert_eq!(r.cred_calls.load(Ordering::SeqCst), 1);
    // So is a key a delete has made unusable.
    r.service.deletes.mark_unusable(11, "k");
    assert_eq!(
        replace(&r, Some(":1.1"), "k", RECERT),
        Err(ServiceError::NoSuchKey)
    );
    assert_eq!(r.service.deletes.locked(), 0);
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(cert_on_disk(&r, "k")?, before);
    Ok(())
}

#[test]
fn a_mismatch_comes_after_polkit() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    let before = cert_on_disk(&r, "k")?;
    assert_eq!(
        replace(&r, Some(":1.1"), "k", OTHER),
        Err(ServiceError::CertificateMismatch)
    );
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(cert_on_disk(&r, "k")?, before);
    assert_eq!(r.service.deletes.locked(), 0);
    Ok(())
}

#[test]
fn unreadable_keys_and_missing_certificates_are_internal_or_no_such_key() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    // A key that is not a supported private key: `Internal`, after polkit.
    let key = r.store.dir().join("11").join("k");
    std::fs::remove_file(&key)?;
    std::fs::write(&key, b"junk")?;
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    assert_eq!(
        replace(&r, Some(":1.1"), "k", RECERT),
        Err(ServiceError::Internal)
    );
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
    // A key that cannot be read at all is `Internal` before polkit.
    std::fs::remove_file(&key)?;
    std::fs::create_dir(&key)?;
    assert_eq!(
        replace(&r, Some(":1.1"), "k", RECERT),
        Err(ServiceError::Internal)
    );
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
    // A key without its certificate: the replace never creates one.
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    std::fs::remove_file(r.store.dir().join("11").join("k-cert"))?;
    assert_eq!(
        replace(&r, Some(":1.1"), "k", RECERT),
        Err(ServiceError::Internal)
    );
    assert!(!r.store.dir().join("11").join("k-cert").exists());
    Ok(())
}

#[test]
fn the_lock_of_a_delete_is_shared_and_released() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    // A replace waits while a delete of the same id runs, and goes on when it is over.
    let held = zbus::block_on(r.service.deletes.lock_key(11, "k"));
    let mut pending = Box::pin(r.service.replace_call(Some(":1.1"), "k", RECERT));
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    assert!(pending.as_mut().poll(&mut cx).is_pending());
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 0);
    drop(held);
    assert_eq!(zbus::block_on(pending), Ok(()));
    assert_eq!(r.service.deletes.locked(), 0);
    Ok(())
}
