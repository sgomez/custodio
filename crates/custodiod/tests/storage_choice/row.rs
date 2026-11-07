//! One failing row: inject, import, check the error, the empty store, the journal and the plaintext; heal, import again.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::Arc;

use custodiod::tpm::TpmAccess;
use zbus::block_on;

use crate::bus::Answer;
use crate::rig::{
    Counting, SUBJECTS, SpyCreds, Subject, Svc, TestResult, pkcs8_of, plaintext_in_store,
};

/// What a row expects of the failed import.
pub struct Row {
    /// The error name of the reply.
    pub err: &'static str,
    /// How many times the credential service may have been asked to encrypt.
    pub encrypts: usize,
}

/// Runs `row` for both key types. `make` builds the (failing) TPM and the credentials for a subject; `heal` repairs
/// them through the service's doubles.
pub fn run<T: TpmAccess + 'static>(
    row: &Row,
    make: &dyn Fn(Subject) -> (T, Arc<SpyCreds>),
    heal: &dyn Fn(&Svc),
) -> TestResult {
    for subject in SUBJECTS {
        let (tpm, creds) = make(subject);
        block_on(async {
            let svc = Svc::start(Counting::new(tpm), creds, Answer::Yes).await?;
            let got = svc.import_subject("k", subject).await;
            let who = subject.reply;
            assert_eq!(got, Err(row.err.to_owned()), "{who}");
            assert_eq!(svc.creds.encrypts(), row.encrypts, "{who}: encrypt calls");
            svc.assert_empty(who);
            svc.assert_one_entry("storage_failure", subject.audit, who);
            assert!(!plaintext_in_store(&svc, &pkcs8_of(subject)), "{who}");
            // Nothing was half-stored: the same id imports once the parts work.
            heal(&svc);
            assert_eq!(
                svc.import_subject("k", subject).await?,
                subject.reply,
                "{who}"
            );
            assert_eq!(svc.store.list(crate::common::uid())?, ["k"], "{who}");
            assert!(!plaintext_in_store(&svc, &pkcs8_of(subject)), "{who}");
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}
