//! A key that cannot be used: the lost class and the transient class, told apart, with the key left as it was.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodiod::audit::Outcome;
use custodiod::tpm::open::TestTcti;
use zbus::block_on;

use crate::case::{Case, Fail};
use crate::common::uid;
use crate::kit::{ERR_INTERNAL, Family, ID, Setup, Storage};
use crate::rig::{SUBJECTS, TestResult};

/// The signature fails closed with the failure's documented name, leaves one `signing_failed` entry, and the record is
/// byte-for-byte what it was. The kind's own access point is the only one asked.
async fn assert_fails_closed(case: &Case, family: Family) -> TestResult {
    let setup = &case.setup;
    let who = format!("{:?} {}", case.fail, case.subject.reply);
    let record = setup.record_bytes();
    let before = setup.counts();
    let entries = setup.svc.sink.entries().len();
    assert_eq!(
        setup.sign(family).await,
        Err(case.fail.error().to_owned()),
        "{who}"
    );
    assert_ne!(case.fail.error(), ERR_INTERNAL, "{who}");
    assert_eq!(
        setup.record_bytes(),
        record,
        "{who}: the record is unchanged"
    );
    setup.assert_entries(entries + 1, family, Outcome::SigningFailed, &who);
    let after = setup.counts();
    // No fallback to the other kind of protection, and nothing was made or stored on the way.
    if setup.storage == Storage::Tpm {
        assert_eq!(after.decrypts, before.decrypts, "{who}: no decrypt");
    } else {
        assert_eq!(after.opens, before.opens, "{who}: no TPM open");
    }
    assert_eq!(after.encrypts, before.encrypts, "{who}: no encrypt");
    Ok(())
}

async fn row(fail: Fail) -> TestResult {
    for subject in SUBJECTS {
        let case = Case::new(fail, subject).await?;
        let family = Family::of(subject)[0];
        // Control: before the failure the same call signs.
        case.setup.sign(family).await?;
        case.break_it();
        assert_fails_closed(&case, family).await?;
        if !fail.lost() {
            // Nothing was deleted or marked: once the access point works the same key signs again.
            case.heal();
            let signature = case.setup.sign(family).await?;
            case.setup
                .assert_signed_by_stored_key(family, &signature, &format!("{fail:?} healed"));
        }
    }
    Ok(())
}

mod lost_keys {
    use super::*;

    #[test]
    fn tpm_cleared_under_tpm_key() -> TestResult {
        block_on(row(Fail::TpmClearedUnderTpmKey))
    }

    #[test]
    fn tpm_bound_credential_cannot_decrypt() -> TestResult {
        block_on(row(Fail::TpmCredentialLost))
    }

    #[test]
    fn host_key_changed() -> TestResult {
        block_on(row(Fail::HostKeyChanged))
    }

    #[test]
    fn damaged_blob() -> TestResult {
        block_on(row(Fail::DamagedBlob))
    }
}

mod transient {
    use super::*;

    #[test]
    fn tpm_absent() -> TestResult {
        block_on(row(Fail::TpmAbsent))
    }

    #[test]
    fn tpm_faulted() -> TestResult {
        block_on(row(Fail::TpmFaulted))
    }

    #[test]
    fn tpm_lacks_the_mechanism() -> TestResult {
        block_on(row(Fail::TpmLacksTheMechanism))
    }

    #[test]
    fn credentials_down() -> TestResult {
        block_on(row(Fail::CredentialsDown))
    }
}

#[test]
fn lost_keys_stay_listed_and_deletable() -> TestResult {
    block_on(async {
        for fail in Fail::ALL {
            for subject in SUBJECTS {
                let who = format!("{fail:?} {}", subject.reply);
                let case = Case::new(fail, subject).await?;
                let setup = &case.setup;
                let family = Family::of(subject)[0];
                let certificate = setup.svc.store.get(uid(), ID)?.certificate().to_vec();
                case.break_it();
                assert_eq!(
                    setup.sign(family).await,
                    Err(fail.error().to_owned()),
                    "{who}"
                );
                // Still listed, with its certificate.
                let listed = setup.list().await?;
                assert_eq!(listed.len(), 1, "{who}");
                assert_eq!(
                    (listed[0].0.as_str(), listed[0].1.as_str(), &listed[0].3),
                    (ID, subject.reply, &certificate),
                    "{who}"
                );
                // Deleted with the TPM absent or cleared and the credential undecryptable: neither is touched.
                let before = setup.counts();
                setup.delete(ID).await?;
                assert_eq!(setup.counts(), before, "{who}: delete touches neither");
                setup.svc.assert_empty(&who);
                // The same id imports again once the access points work.
                heal_all(&case);
                assert_eq!(
                    setup.svc.import_subject(ID, subject).await?,
                    subject.reply,
                    "{who}"
                );
            }
        }
        Ok(())
    })
}

/// Whatever the scenario broke works again, for the import that follows. A cleared `swtpm` works for a new import.
fn heal_all(case: &Case) {
    let setup = &case.setup;
    setup.svc.creds.fail_decrypt_with(None);
    setup.svc.tpm.swap(TestTcti::new(&setup.rig.tcti()));
}

/// A symptom check, not evidence: a TPM key and a TPM-bound credential signing at once on the same bus both succeed.
/// The credential is decrypted while the TPM key's signature holds the TPM connection.
#[test]
fn concurrent_kinds() -> TestResult {
    block_on(async {
        for subject in SUBJECTS {
            let setup = Setup::new(Storage::EncryptedTpm, subject).await?;
            // The TPM serves everything now: the second key is a TPM key.
            assert_eq!(setup.svc.import_subject("t", subject).await?, subject.reply);
            assert_eq!(setup.svc.kind_of("t"), Some(custodiod::store::Kind::Tpm));
            let family = Family::of(subject)[0];
            let (mechanism, hash, salt, data) = family.args();
            for _ in 0..3 {
                let (credential, tpm) = join2(
                    setup.sign_as(ID, mechanism, hash, salt, data.clone()),
                    setup.sign_as("t", mechanism, hash, salt, data.clone()),
                )
                .await;
                assert!(
                    credential.is_ok(),
                    "{}: credential: {credential:?}",
                    subject.reply
                );
                assert!(tpm.is_ok(), "{}: TPM: {tpm:?}", subject.reply);
            }
        }
        Ok(())
    })
}

/// Polls both futures from one task until both are done.
async fn join2<A: std::future::Future, B: std::future::Future>(
    a: A,
    b: B,
) -> (A::Output, B::Output) {
    use std::task::Poll;
    let (mut a, mut b) = (Box::pin(a), Box::pin(b));
    let (mut done_a, mut done_b) = (None, None);
    std::future::poll_fn(|cx| {
        if done_a.is_none()
            && let Poll::Ready(v) = a.as_mut().poll(cx)
        {
            done_a = Some(v);
        }
        if done_b.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            done_b = Some(v);
        }
        match (done_a.take(), done_b.take()) {
            (Some(x), Some(y)) => Poll::Ready((x, y)),
            (x, y) => {
                done_a = x;
                done_b = y;
                Poll::Pending
            }
        }
    })
    .await
}
