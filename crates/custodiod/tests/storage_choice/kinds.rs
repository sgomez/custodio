//! The kind per reason, on the success paths.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::{Binding, header};
use custodiod::store::Kind;
use custodiod::tpm::open::{NoTpm, TestTcti};
use zbus::block_on;

use crate::bus::Answer;
use crate::rig::{
    Counting, Rig, SUBJECTS, SpyCreds, Svc, TestResult, lacks_import, lacks_mechanism,
};

/// Imports every subject through `svc`, checks the kind read back from the store and the journal.
async fn expect_kind(svc: &Svc, kind: Kind, binding: Option<Binding>) -> TestResult {
    for (n, subject) in SUBJECTS.iter().enumerate() {
        let id = format!("key{n}");
        assert_eq!(svc.import_subject(&id, *subject).await?, subject.reply);
        let record = svc.store.get(common_uid(), &id)?;
        assert_eq!(record.kind(), kind, "{id}");
        match binding {
            None => {
                let (blob, parent) = record
                    .protected()
                    .blob()
                    .expect("a TPM record holds a blob");
                assert_ne!(parent.len(), 0);
                assert_ne!(blob.public_bytes().len(), 0);
                assert_eq!(record.protected().credential(), None, "{id}");
            }
            Some(want) => {
                assert!(record.protected().blob().is_none(), "{id}");
                let credential = record.protected().credential().expect("a credential");
                assert_eq!(header::inspect(credential).ok(), Some(want), "{id}");
            }
        }
    }
    let entries = svc.entries();
    assert_eq!(entries.len(), SUBJECTS.len());
    assert!(entries.iter().all(|e| e.outcome_name() == "stored"));
    Ok(())
}

fn common_uid() -> u32 {
    crate::common::uid()
}

#[test]
fn ready_gives_tpm() -> TestResult {
    let rig = Rig::new()?;
    let creds = SpyCreds::new(MemoryCreds::host());
    let tpm = Counting::new(TestTcti::new(&rig.tcti()));
    block_on(async {
        let svc = Svc::start(tpm, creds.clone(), Answer::Yes).await?;
        expect_kind(&svc, Kind::Tpm, None).await?;
        assert_eq!(
            creds.encrypts(),
            0,
            "a TPM key is never given to the credential service"
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    rig.assert_nothing_loaded("after the imports")
}

#[test]
fn lacks_gives_encrypted_tpm() -> TestResult {
    let rig = Rig::new()?;
    let (filter, _) = rig.filter(lacks_import())?;
    let creds = SpyCreds::new(MemoryCreds::tpm());
    let tpm = Counting::new(TestTcti::new(&filter.tcti()));
    block_on(async {
        let svc = Svc::start(tpm, creds.clone(), Answer::Yes).await?;
        expect_kind(&svc, Kind::EncryptedTpm, Some(Binding::Tpm)).await?;
        assert_eq!(creds.encrypts(), SUBJECTS.len());
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn absent_gives_encrypted_host() -> TestResult {
    let creds = SpyCreds::new(MemoryCreds::host());
    let tpm = Counting::new(NoTpm);
    block_on(async {
        let svc = Svc::start(tpm, creds.clone(), Answer::Yes).await?;
        expect_kind(&svc, Kind::EncryptedHost, Some(Binding::Host)).await?;
        assert_eq!(creds.encrypts(), SUBJECTS.len());
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn unserved_mechanism_gives_encrypted_tpm() -> TestResult {
    // The TPM lacks the command or scheme of one mechanism of the key type: not TPM, and not a failure.
    for (n, subject) in SUBJECTS.iter().enumerate() {
        let rig = Rig::new()?;
        let (filter, _) = rig.filter(lacks_mechanism(n == 0))?;
        let creds = SpyCreds::new(MemoryCreds::tpm());
        let tpm = Counting::new(TestTcti::new(&filter.tcti()));
        block_on(async {
            let svc = Svc::start(tpm, creds, Answer::Yes).await?;
            assert_eq!(svc.import_subject("k", *subject).await?, subject.reply);
            let record = svc.store.get(common_uid(), "k")?;
            assert_eq!(record.kind(), Kind::EncryptedTpm, "{}", subject.reply);
            assert!(record.protected().credential().is_some());
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}
