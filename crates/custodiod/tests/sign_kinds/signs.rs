//! Sign, delete and replace a certificate for each storage kind, on the success paths.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodiod::audit::Outcome;
use zbus::block_on;

use crate::bus::Answer;
use crate::common::uid;
use crate::kit::{
    ERR_DENIED, ERR_MISMATCH, ERR_NO_KEY, Family, ID, STORAGES, Setup, Storage, p12_certificate,
    second_certificate,
};
use crate::rig::{SUBJECTS, TestResult};

#[test]
fn signs_each_kind() -> TestResult {
    for storage in STORAGES {
        for subject in SUBJECTS {
            block_on(async {
                let who = format!("{storage:?} {}", subject.reply);
                let setup = Setup::new(storage, subject).await?;
                // The record holds what the kind says: a blob and no credential, or the reverse.
                let record = setup.svc.store.get(uid(), ID)?;
                assert_eq!(record.kind(), storage.kind(), "{who}");
                assert_eq!(
                    record.protected().blob().is_some(),
                    storage == Storage::Tpm,
                    "{who}"
                );
                assert_eq!(
                    record.protected().credential().is_some(),
                    storage != Storage::Tpm,
                    "{who}"
                );
                let before = setup.counts();
                let mut signed = 0;
                for family in Family::of(subject) {
                    let signature = setup.sign(*family).await?;
                    signed += 1;
                    setup.assert_signed_by_stored_key(*family, &signature, &who);
                    setup.assert_entries(signed, *family, Outcome::Signed, &who);
                }
                let after = setup.counts();
                if storage == Storage::Tpm {
                    // Inside the TPM: opened for each signature, the credential service never asked.
                    assert_eq!(after.opens - before.opens, signed, "{who}");
                    assert_eq!(after.decrypts, before.decrypts, "{who}");
                } else {
                    // Decrypted for each signature (the next one decrypts again), the TPM never opened.
                    assert_eq!(after.opens, before.opens, "{who}");
                    assert_eq!(after.decrypts - before.decrypts, signed, "{who}");
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
    }
    Ok(())
}

#[test]
fn polkit_every_signature() -> TestResult {
    for storage in STORAGES {
        for subject in SUBJECTS {
            block_on(async {
                let who = format!("{storage:?} {}", subject.reply);
                let setup = Setup::new(storage, subject).await?;
                let family = Family::of(subject)[0];
                let asked = || setup.svc.requests.lock().unwrap().len();
                let start = asked();
                for n in 1..=3 {
                    setup.sign(family).await?;
                    assert_eq!(asked() - start, n, "{who}: one polkit call per signature");
                }
                *setup.svc.answer.lock().unwrap() = Answer::No;
                let before = setup.counts();
                assert_eq!(
                    setup.sign(family).await,
                    Err(ERR_DENIED.to_owned()),
                    "{who}"
                );
                assert_eq!(asked() - start, 4, "{who}");
                // Denied: neither the TPM nor the credentials were touched.
                assert_eq!(setup.counts(), before, "{who}");
                setup.assert_entries(4, family, Outcome::Denied, &who);
                // Allowed again: asked again, signs again.
                *setup.svc.answer.lock().unwrap() = Answer::Yes;
                setup.sign(family).await?;
                assert_eq!(asked() - start, 5, "{who}");
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
    }
    Ok(())
}

#[test]
fn delete_each_kind() -> TestResult {
    for storage in STORAGES {
        for subject in SUBJECTS {
            block_on(async {
                let who = format!("{storage:?} {}", subject.reply);
                let setup = Setup::new(storage, subject).await?;
                let family = Family::of(subject)[0];
                setup.sign(family).await?;
                let before = setup.counts();
                setup.delete(ID).await?;
                assert_eq!(setup.counts(), before, "{who}: delete touches neither");
                setup.svc.assert_empty(&who);
                assert!(setup.list().await?.is_empty(), "{who}");
                assert_eq!(
                    setup.sign(family).await,
                    Err(ERR_NO_KEY.to_owned()),
                    "{who}"
                );
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
    }
    Ok(())
}

#[test]
fn replace_each_kind() -> TestResult {
    for storage in STORAGES {
        for subject in SUBJECTS {
            block_on(async {
                let who = format!("{storage:?} {}", subject.reply);
                let setup = Setup::new(storage, subject).await?;
                let before_record = setup.svc.store.get(uid(), ID)?;
                let first = before_record.certificate().to_vec();
                let second = second_certificate(&setup.rig, subject);
                assert_ne!(first, second, "{who}");

                let before = setup.counts();
                setup.replace(ID, &second).await?;
                if storage == Storage::Tpm {
                    assert_eq!(setup.counts().opens, before.opens, "{who}: no TPM call");
                }
                let listed = setup.list().await?;
                assert_eq!(listed.len(), 1, "{who}");
                assert_eq!(listed[0].3, second, "{who}: ListKeys shows the new one");
                // The kind and the protected form are what they were.
                let after_record = setup.svc.store.get(uid(), ID)?;
                assert_eq!(after_record.kind(), before_record.kind(), "{who}");
                assert_eq!(after_record.protected(), before_record.protected(), "{who}");
                // A signature afterwards verifies against the new certificate.
                let family = Family::of(subject)[0];
                let signature = setup.sign(family).await?;
                setup.assert_signed_by_stored_key(family, &signature, &who);
                assert_eq!(
                    setup.svc.store.get(uid(), ID)?.certificate(),
                    second,
                    "{who}"
                );

                // A certificate of another key changes nothing.
                let other = SUBJECTS.iter().find(|s| s.reply != subject.reply).unwrap();
                let bytes = setup.record_bytes();
                assert_eq!(
                    setup.replace(ID, &p12_certificate(*other)).await,
                    Err(ERR_MISMATCH.to_owned()),
                    "{who}"
                );
                assert_eq!(setup.record_bytes(), bytes, "{who}");
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
    }
    Ok(())
}

#[test]
fn replace_lost_key() -> TestResult {
    // A credential that cannot be decrypted cannot be compared with the certificate: the replace fails closed with
    // `Internal` and the stored certificate is the one it was.
    for storage in [Storage::EncryptedTpm, Storage::EncryptedHost] {
        for subject in SUBJECTS {
            block_on(async {
                let who = format!("{storage:?} {}", subject.reply);
                let setup = Setup::new(storage, subject).await?;
                setup
                    .svc
                    .creds
                    .fail_decrypt_with(Some(custodiod::creds::CredsError::CannotDecrypt));
                let bytes = setup.record_bytes();
                let second = second_certificate(&setup.rig, subject);
                assert_eq!(
                    setup.replace(ID, &second).await,
                    Err(crate::kit::ERR_INTERNAL.to_owned()),
                    "{who}"
                );
                assert_eq!(setup.record_bytes(), bytes, "{who}");
                // Control: with the credentials back, the same replace works.
                setup.svc.creds.fail_decrypt_with(None);
                setup.replace(ID, &second).await?;
                assert_eq!(
                    setup.svc.store.get(uid(), ID)?.certificate(),
                    second,
                    "{who}"
                );
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
    }
    Ok(())
}
