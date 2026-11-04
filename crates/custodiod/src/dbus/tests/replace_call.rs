//! `replace_call` with counting doubles: the order of the checks and the error mapping.

use std::sync::atomic::Ordering;

use super::delete_call::guarded;
use super::sign_call::{Counting, Creds, rig, seed};
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

/// The entries the sink got: outcome and caller.
fn recorded(r: &super::sign_call::Rig) -> Vec<(&'static str, Option<Caller>)> {
    r.sink
        .operation_entries()
        .iter()
        .map(|e| {
            assert_eq!(e.operation(), crate::audit::Operation::ReplaceCertificate);
            (e.outcome_name(), e.caller())
        })
        .collect()
}

fn cert_on_disk(
    r: &super::sign_call::Rig,
    id: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(r.store.get(11, id)?.certificate().to_vec())
}

#[test]
fn an_approved_replace_stores_the_certificate_and_asks_once() -> R {
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    assert_eq!(replace(&r, Some(":1.1"), "k", RECERT), Ok(()));
    assert_eq!(cert_on_disk(&r, "k")?, RECERT);
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(r.service.deletes.locked(), 0);
    assert_eq!(r.sink.entries().len(), 0);
    assert_eq!(
        recorded(&r),
        [("replaced", Some(Caller { uid: 11, pid: 22 }))]
    );
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
    for ((result, want), name) in cases.into_iter().zip([
        "denied",
        "authorization_unavailable",
        "authorization_unavailable",
    ]) {
        let r = rig(result)?;
        seed(&r, "k")?;
        let before = cert_on_disk(&r, "k")?;
        assert_eq!(replace(&r, Some(":1.1"), "k", RECERT), Err(want));
        assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cert_on_disk(&r, "k")?, before);
        assert_eq!(r.service.deletes.locked(), 0);
        assert_eq!(recorded(&r), [(name, Some(Caller { uid: 11, pid: 22 }))]);
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
    // The missing sender left one entry without a caller; the refusals below leave none.
    assert_eq!(recorded(&r), [("authorization_unavailable", None)]);
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
    assert_eq!(recorded(&r).len(), 1);
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
    assert_eq!(
        recorded(&r),
        [("certificate_mismatch", Some(Caller { uid: 11, pid: 22 }))]
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
    let creds = crate::creds::memory::MemoryCreds::host();
    let junk = crate::creds::seal(
        &creds,
        &crate::import::credential_name(11, "k"),
        &secrecy::SecretSlice::from(b"junk".to_vec()),
    )?;
    let protected = crate::store::Protected::from_sealed(&junk);
    r.store.put(&crate::store::Record::new(
        11,
        "k",
        protected.natural_kind(),
        b"cert",
        protected,
    )?)?;
    assert_eq!(
        replace(&r, Some(":1.1"), "k", RECERT),
        Err(ServiceError::Internal)
    );
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
    // The key type the comparison does not support is a storage failure.
    assert_eq!(
        recorded(&r),
        [("storage_failure", Some(Caller { uid: 11, pid: 22 }))]
    );
    // A key that cannot be read at all is `Internal` before polkit.
    std::fs::remove_file(&key)?;
    std::fs::create_dir(&key)?;
    assert_eq!(
        replace(&r, Some(":1.1"), "k", RECERT),
        Err(ServiceError::Internal)
    );
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 1);
    // A key still in the earlier format is not read: `Internal` before polkit, and nothing is changed.
    let r = rig(|| Ok(()))?;
    seed(&r, "k")?;
    let path = r.store.dir().join("11").join("k");
    std::fs::remove_file(&path)?;
    std::fs::write(&path, [0x30_u8, 0x82, 0x01, 0x00])?;
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    assert_eq!(
        replace(&r, Some(":1.1"), "k", RECERT),
        Err(ServiceError::Internal)
    );
    assert_eq!(r.auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read(&path)?, [0x30_u8, 0x82, 0x01, 0x00]);
    assert_eq!(recorded(&r), []);
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

#[test]
fn a_sink_that_fails_puts_the_old_certificate_back_for_every_outcome() -> R {
    use crate::audit::FailingSink;
    type Answer = fn() -> Result<(), AuthError>;
    let answers: [(Answer, &[u8], ServiceError); 4] = [
        (|| Ok(()), RECERT, ServiceError::AuditUnavailable),
        (|| Ok(()), OTHER, ServiceError::AuditUnavailable),
        (
            || Err(AuthError::Denied),
            RECERT,
            ServiceError::AuditUnavailable,
        ),
        (
            || Err(AuthError::BadSender),
            RECERT,
            ServiceError::AuditUnavailable,
        ),
    ];
    for (result, cert, want) in answers {
        let r = rig(result)?;
        let failing = Custodio::new(
            r.store.clone(),
            Counting {
                result,
                calls: r.auth_calls.clone(),
            },
            Creds(r.cred_calls.clone()),
            Arc::new(FailingSink),
        )
        .with_key_credentials(std::sync::Arc::new(
            crate::creds::memory::MemoryCreds::host(),
        ));
        seed(&r, "k")?;
        let before = std::fs::read_dir(r.store.dir().join("11"))?.count();
        let old = cert_on_disk(&r, "k")?;
        for _ in 0..2 {
            // A second round shows the lock of the first was released.
            let got = guarded(failing.replace_call(Some(":1.1"), "k", cert));
            assert_eq!(got, Err(want));
            assert_eq!(cert_on_disk(&r, "k")?, old);
            assert_eq!(failing.deletes.locked(), 0);
        }
        assert_eq!(std::fs::read_dir(r.store.dir().join("11"))?.count(), before);
    }
    // No sender: the entry is refused too.
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
    assert_eq!(
        guarded(failing.replace_call(None, "k", RECERT)),
        Err(ServiceError::AuditUnavailable)
    );
    Ok(())
}

/// A record of the TPM kind holding the public area of the P12 fixture's key. The private area is a
/// stand-in: the comparison only looks at the public area, and makes no TPM call.
fn seed_tpm(r: &super::sign_call::Rig, id: &str) -> R {
    use crate::store::{Kind, Protected, Record};
    use crate::tpm::blob::{Blob, Imported};
    use secrecy::ExposeSecret;
    use tss_esapi::traits::Marshall;
    let parsed = crate::import::parse_p12(
        super::sign_call::P12,
        &SecretString::from("test-password".to_owned()),
    )?;
    let key = crate::tpm::key::ImportKey::from_pkcs8(parsed.key.expose_secret())?;
    let public = crate::tpm::wrap::template(&key)?.marshall()?;
    let mut private = vec![0, 32];
    private.extend([9_u8; 32]);
    private.extend([7_u8; 40]);
    let imported = Imported {
        blob: Blob::from_parts(&public, &private)?,
        parent_name: [vec![0, 0x0b], vec![0x42; 32]].concat(),
    };
    let record = Record::new(
        11,
        id,
        Kind::Tpm,
        &parsed.certificate,
        Protected::from_imported(&imported)?,
    )?;
    r.store.put(&record)?;
    Ok(())
}

#[test]
fn a_tpm_record_is_matched_against_the_public_area_of_its_blob() -> R {
    let r = rig(|| Ok(()))?;
    seed_tpm(&r, "t")?;
    assert_eq!(
        replace(&r, Some(":1.1"), "t", OTHER),
        Err(ServiceError::CertificateMismatch)
    );
    assert_ne!(cert_on_disk(&r, "t")?, OTHER);
    assert_eq!(replace(&r, Some(":1.1"), "t", RECERT), Ok(()));
    assert_eq!(cert_on_disk(&r, "t")?, RECERT);
    Ok(())
}
