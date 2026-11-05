//! The sign entry: the lost and the transient failure told apart, with the kind of the record; the other entries as
//! they were.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodiod::audit::{Entry, Outcome, SignCause};
use custodiod::creds::CredsError;
use zbus::block_on;

use crate::bus::Answer;
use crate::case::{Case, Fail};
use crate::kit::{ERR_INTERNAL, ERR_KEY_LOST, ERR_UNAVAILABLE, Family, STORAGES, Setup};
use crate::rig::{SUBJECTS, TestResult, pkcs8_of};
use crate::secrets::{Secrets, assert_sign_clean};

pub fn value(e: &Entry, name: &str) -> Option<String> {
    e.fields()
        .into_iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v)
}

fn secrets(setup: &Setup) -> Secrets {
    Secrets::new(
        setup.subject.p12,
        pkcs8_of(setup.subject),
        vec![setup.record_bytes()],
    )
}

fn last(setup: &Setup) -> Entry {
    setup.svc.sink.entries().pop().unwrap()
}

/// The cause a failure must carry, from the D-Bus error it gives: a literal table.
fn cause_of(error: &str) -> SignCause {
    match error {
        ERR_KEY_LOST => SignCause::KeyLost,
        ERR_UNAVAILABLE => SignCause::TemporarilyUnavailable,
        other => panic!("{other} has no cause"),
    }
}

/// Every failure of `Fail::ALL` whose class is `lost`, for both key types: one `signing_failed` entry with the cause of
/// its class and the kind of the record, and the record and the listing as they were.
async fn failure_rows(lost: bool) -> TestResult {
    let mut seen = 0;
    for fail in Fail::ALL.into_iter().filter(|f| f.lost() == lost) {
        for subject in SUBJECTS {
            seen += 1;
            let who = format!("{fail:?} {}", subject.reply);
            let case = Case::new(fail, subject).await?;
            let setup = &case.setup;
            let family = Family::of(subject)[0];
            let (record, listed) = (setup.record_bytes(), setup.list().await?);
            let before = setup.svc.sink.entries().len();
            case.break_it();
            assert_eq!(
                setup.sign(family).await,
                Err(fail.error().to_owned()),
                "{who}"
            );
            let entries = setup.svc.sink.entries();
            assert_eq!(entries.len(), before + 1, "{who}");
            let e = entries.last().unwrap();
            assert_eq!(e.outcome(), Outcome::SigningFailed, "{who}");
            assert_eq!(e.cause(), Some(cause_of(fail.error())), "{who}");
            assert_eq!(e.storage_kind(), Some(fail.storage().kind()), "{who}");
            assert_eq!(e.outcome().priority(), 3, "{who}");
            let (want_cause, other) = if lost {
                ("key_lost", "temporarily_unavailable")
            } else {
                ("temporarily_unavailable", "key_lost")
            };
            let got = value(e, "CUSTODIO_CAUSE");
            assert_eq!(got.as_deref(), Some(want_cause), "{who}");
            assert_ne!(got.as_deref(), Some(other), "{who}");
            assert_eq!(
                value(e, "CUSTODIO_OUTCOME").as_deref(),
                Some("signing_failed"),
                "{who}"
            );
            assert_eq!(
                value(e, "CUSTODIO_STORAGE_KIND").as_deref(),
                Some(match fail.storage() {
                    crate::kit::Storage::Tpm => "tpm",
                    crate::kit::Storage::EncryptedTpm => "encrypted-tpm",
                    crate::kit::Storage::EncryptedHost => "encrypted-host",
                }),
                "{who}"
            );
            assert_eq!(setup.list().await?, listed, "{who}: the listing");
            if !lost {
                assert_eq!(setup.record_bytes(), record, "{who}: the record");
            }
            assert_sign_clean(e, &secrets(setup), &who);
        }
    }
    assert!(seen >= 8, "{seen} rows");
    Ok(())
}

/// The key no longer loads or decrypts: the lost cause.
#[test]
fn sign_lost_key() -> TestResult {
    block_on(failure_rows(true))?;
    // All three kinds are among the rows that lose a key.
    let kinds: std::collections::BTreeSet<_> = Fail::ALL
        .into_iter()
        .filter(|f| f.lost())
        .map(|f| f.storage().kind().wire())
        .collect();
    assert_eq!(kinds.len(), 3);
    Ok(())
}

/// The TPM or the credential service cannot be used now: the transient cause, never the lost one.
#[test]
fn sign_transient() -> TestResult {
    block_on(failure_rows(false))
}

/// Signatures, denials and an `Internal` failure keep their entries, with the kind of the record where it was read.
#[test]
fn sign_other_entries() -> TestResult {
    block_on(async {
        for storage in STORAGES {
            for subject in SUBJECTS {
                let who = format!("{storage:?} {}", subject.reply);
                let setup = Setup::new(storage, subject).await?;
                let family = Family::of(subject)[0];
                let wire = crate::kit::Storage::kind(storage).wire();
                // A signature: `signed`, the kind, the mechanism, no cause.
                setup.sign(family).await?;
                let e = last(&setup);
                assert_eq!(e.outcome(), Outcome::Signed, "{who}");
                assert_eq!(e.cause(), None, "{who}");
                assert_eq!(value(&e, "CUSTODIO_STORAGE_KIND").as_deref(), Some(wire));
                let mechanism = match family {
                    Family::RsaPkcs => "rsa_pkcs",
                    Family::RsaPss => "rsa_pkcs_pss_sha256",
                    Family::Ecdsa => "ecdsa",
                };
                assert_eq!(value(&e, "CUSTODIO_MECHANISM").as_deref(), Some(mechanism));
                assert_sign_clean(&e, &secrets(&setup), &who);
                // Denied and unavailable: no cause.
                for (answer, outcome, name) in [
                    (Answer::No, Outcome::Denied, "denied"),
                    (
                        Answer::Fail,
                        Outcome::AuthorizationUnavailable,
                        "authorization_unavailable",
                    ),
                ] {
                    *setup.svc.answer.lock().unwrap() = answer;
                    assert!(setup.sign(family).await.is_err(), "{who}: {name}");
                    let e = last(&setup);
                    assert_eq!(e.outcome(), outcome, "{who}: {name}");
                    assert_eq!(e.cause(), None, "{who}: {name}");
                    assert_eq!(value(&e, "CUSTODIO_CAUSE"), None, "{who}: {name}");
                    assert_sign_clean(&e, &secrets(&setup), &who);
                }
                *setup.svc.answer.lock().unwrap() = Answer::Yes;
            }
        }
        // An `Internal` failure: the credential service refuses the request. Neither lost nor transient.
        for subject in SUBJECTS {
            let who = format!("internal {}", subject.reply);
            let setup = Setup::new(crate::kit::Storage::EncryptedHost, subject).await?;
            let family = Family::of(subject)[0];
            setup
                .svc
                .creds
                .fail_decrypt_with(Some(CredsError::BadRequest));
            assert_eq!(
                setup.sign(family).await,
                Err(ERR_INTERNAL.to_owned()),
                "{who}"
            );
            let e = last(&setup);
            assert_eq!(e.outcome(), Outcome::SigningFailed, "{who}");
            assert_eq!(e.cause(), None, "{who}");
            assert_eq!(value(&e, "CUSTODIO_CAUSE"), None, "{who}");
            assert_eq!(
                value(&e, "CUSTODIO_STORAGE_KIND").as_deref(),
                Some("encrypted-host"),
                "{who}"
            );
            assert_eq!(value(&e, "PRIORITY").as_deref(), Some("3"), "{who}");
            assert_sign_clean(&e, &secrets(&setup), &who);
        }
        Ok(())
    })
}
