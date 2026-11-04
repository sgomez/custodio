//! The order (polkit, decode, choice), the TPM left clean, the plaintext, and the controls that make the rest non-vacuous.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use custodio_it::tpm_filter::cc;
use custodiod::creds::memory::MemoryCreds;
use custodiod::store::Kind;
use custodiod::tpm::open::{NoTpm, TestTcti};
use zbus::block_on;

use crate::bus::Answer;
use crate::common::SENTINEL_PASSWORD;
use crate::rig::{
    Counting, ERR_TPM, Rig, SUBJECTS, SpyCreds, Svc, TestResult, fault, lacks_import, pkcs8_of,
    plaintext_in_store,
};

#[test]
fn tpm_untouched_when_polkit_denies() -> TestResult {
    let rig = Rig::new()?;
    let creds = SpyCreds::new(MemoryCreds::host());
    for subject in SUBJECTS {
        let tpm = Counting::new(TestTcti::new(&rig.tcti()));
        block_on(async {
            let svc = Svc::start(tpm, creds.clone(), Answer::No).await?;
            let got = svc.import_subject("k", subject).await;
            assert_eq!(got, Err(custodio_client::ERROR_POLKIT_DENIED.to_owned()));
            assert_eq!(
                svc.tpm.opens(),
                0,
                "the TPM is not opened before polkit approves"
            );
            svc.assert_empty("denied");
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    assert_eq!(creds.encrypts(), 0);
    Ok(())
}

#[test]
fn tpm_untouched_when_p12_is_wrong() -> TestResult {
    let rig = Rig::new()?;
    let creds = SpyCreds::new(MemoryCreds::host());
    for subject in SUBJECTS {
        let tpm = Counting::new(TestTcti::new(&rig.tcti()));
        block_on(async {
            let svc = Svc::start(tpm, creds.clone(), Answer::Yes).await?;
            let got = svc.import("k", subject.p12, "not the password").await;
            assert_eq!(
                got,
                Err(custodio_client::ERROR_WRONG_PASSWORD_OR_BAD_P12.to_owned())
            );
            assert_eq!(
                svc.tpm.opens(),
                0,
                "the TPM is not opened before the .p12 is decoded"
            );
            svc.assert_empty("wrong password");
            // Control: with the right password the same service does open the TPM.
            svc.import("k", subject.p12, SENTINEL_PASSWORD).await?;
            assert!(svc.tpm.opens() > 0);
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    assert_eq!(creds.encrypts(), 0);
    Ok(())
}

#[test]
fn tpm_is_clean_after_faulted_import() -> TestResult {
    let rig = Rig::new()?;
    // The import is refused after the parent was created and loaded: the commands the TPM saw prove it.
    let (filter, record) = rig.filter(fault(cc::IMPORT, 0x101))?;
    for subject in SUBJECTS {
        let creds = SpyCreds::new(MemoryCreds::host());
        let tpm = Counting::new(TestTcti::new(&filter.tcti()));
        block_on(async {
            let svc = Svc::start(tpm, creds, Answer::Yes).await?;
            let got = svc.import_subject("k", subject).await;
            assert_eq!(got, Err(ERR_TPM.to_owned()));
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        let codes = record.codes();
        let create = codes
            .iter()
            .rposition(|c| *c == cc::CREATE_PRIMARY)
            .unwrap();
        let import = codes.iter().rposition(|c| *c == cc::IMPORT).unwrap();
        assert!(create < import, "something was loaded before the fault");
        rig.assert_nothing_loaded(subject.reply)?;
    }
    // Control: with the flush itself faulted the objects stay, so the check above can see a leak.
    drop(filter);
    let (leaky, _) = rig.filter(fault(cc::FLUSH_CONTEXT, 0x101))?;
    let creds = SpyCreds::new(MemoryCreds::host());
    block_on(async {
        let svc = Svc::start(
            Counting::new(TestTcti::new(&leaky.tcti())),
            creds,
            Answer::Yes,
        )
        .await?;
        assert!(svc.import_subject("k", SUBJECTS[1]).await.is_err());
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    assert_ne!(rig.handles("handles-transient")?.len(), 0);
    rig.tpm.tool_ok("tpm2_flushcontext", ["-t"])?;
    // A successful import leaves nothing either.
    block_on(async {
        let svc = Svc::start(
            Counting::new(TestTcti::new(&rig.tcti())),
            SpyCreds::new(MemoryCreds::host()),
            Answer::Yes,
        )
        .await?;
        for subject in SUBJECTS {
            svc.import_subject(&format!("ok-{}", subject.reply), subject)
                .await?;
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    rig.assert_nothing_loaded("after successful imports")
}

#[test]
fn no_plaintext_in_store_after_any_outcome() -> TestResult {
    // Every outcome: TPM, encrypted TPM-bound, encrypted host-bound (success), and a failure of each family.
    let rig = Rig::new()?;
    let (lacking, _) = rig.filter(lacks_import())?;
    for subject in SUBJECTS {
        let key = pkcs8_of(subject);
        let cases: [(Counting2, MemoryCreds); 3] = [
            (Box::new(TestTcti::new(&rig.tcti())), MemoryCreds::host()),
            (Box::new(TestTcti::new(&lacking.tcti())), MemoryCreds::tpm()),
            (Box::new(NoTpm), MemoryCreds::host()),
        ];
        for (n, (tpm, creds)) in cases.into_iter().enumerate() {
            block_on(async {
                let svc = Svc::start(
                    Counting::new(BoxedTpm(tpm)),
                    SpyCreds::new(creds),
                    Answer::Yes,
                )
                .await?;
                svc.import_subject("k", subject).await?;
                assert!(
                    !plaintext_in_store(&svc, &key),
                    "{} case {n}",
                    subject.reply
                );
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
    }
    Ok(())
}

type Counting2 = Box<dyn custodiod::tpm::TpmAccess>;

struct BoxedTpm(Counting2);

impl custodiod::tpm::TpmAccess for BoxedTpm {
    fn open(&self) -> Result<Box<dyn custodiod::tpm::Session>, custodiod::tpm::OpenError> {
        self.0.open()
    }
}

#[test]
fn controls() -> TestResult {
    // (a) A TPM that lacks and a TPM that fails give different results with the same credentials.
    let rig = Rig::new()?;
    let (lacking, _) = rig.filter(lacks_import())?;
    block_on(async {
        let svc = Svc::start(
            Counting::new(TestTcti::new(&lacking.tcti())),
            SpyCreds::new(MemoryCreds::tpm()),
            Answer::Yes,
        )
        .await?;
        svc.import_subject("k", SUBJECTS[1]).await?;
        assert_eq!(svc.kind_of("k"), Some(Kind::EncryptedTpm));
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    drop(lacking);
    let (broken, _) = rig.filter(fault(cc::GET_CAPABILITY, 0x101))?;
    block_on(async {
        let svc = Svc::start(
            Counting::new(TestTcti::new(&broken.tcti())),
            SpyCreds::new(MemoryCreds::tpm()),
            Answer::Yes,
        )
        .await?;
        assert_eq!(
            svc.import_subject("k", SUBJECTS[1]).await,
            Err(ERR_TPM.to_owned())
        );
        assert_eq!(svc.kind_of("k"), None);
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    // (b) A record planted in the store is seen by the emptiness helper, and so is a plaintext key.
    block_on(async {
        let svc = Svc::start(
            Counting::new(NoTpm),
            SpyCreds::new(MemoryCreds::host()),
            Answer::Yes,
        )
        .await?;
        svc.import_subject("planted", SUBJECTS[0]).await?;
        assert!(catch_unwind(AssertUnwindSafe(|| svc.assert_empty("planted"))).is_err());
        let file = svc.files().remove(0);
        let key = pkcs8_of(SUBJECTS[0]);
        assert!(!plaintext_in_store(&svc, &key));
        std::fs::write(&file, &key)?;
        assert!(plaintext_in_store(&svc, &key));
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}
