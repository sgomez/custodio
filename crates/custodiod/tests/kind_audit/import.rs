//! The import entry: the kind of a stored key, the cause of each failure, and the entries that stay as they were.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::any::Any;
use std::sync::Arc;

use custodio_it::tpm_filter::cc;
use custodiod::audit::{ImportCause, OperationEntry};
use custodiod::creds::CredsError;
use custodiod::creds::memory::MemoryCreds;
use custodiod::tpm::open::{NoTpm, Production, TestTcti};
use zbus::block_on;

use crate::bus::Answer;
use crate::common::{PASSWORD, SENTINEL_PASSWORD, uid};
use crate::kit::{STORAGES, Storage};
use crate::rig::{
    Counting, ERR_CREDS, ERR_TPM, Rig, SUBJECTS, SpyCreds, Subject, Svc, TestResult, fault,
    lacks_import, pkcs8_of,
};
use crate::secrets::{Secrets, assert_operation_clean};

/// The fields every import entry has had since F113, in order.
const OLD_FIELDS: [&str; 10] = [
    "MESSAGE",
    "MESSAGE_ID",
    "PRIORITY",
    "SYSLOG_IDENTIFIER",
    "CUSTODIO_UID",
    "CUSTODIO_PID",
    "CUSTODIO_KEY_ID",
    "CUSTODIO_OPERATION",
    "CUSTODIO_OUTCOME",
    "CUSTODIO_APP_ID_STATE",
];

pub fn value(e: &OperationEntry, name: &str) -> Option<String> {
    e.fields()
        .into_iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v)
}

/// The secrets of an import of `subject` through `svc`: the stored record's bytes are added when there is one.
fn secrets(svc: &Svc, subject: Subject) -> Secrets {
    let record = svc
        .files()
        .iter()
        .map(|f| std::fs::read(f).unwrap())
        .collect();
    Secrets::new(subject.p12, pkcs8_of(subject), record)
}

/// `ImportP12` as the raw reply: the key type and the kind.
async fn import_reply(svc: &Svc, id: &str, subject: Subject) -> Result<(String, String), String> {
    let reply = svc
        .call_method("ImportP12", &(id, subject.p12.to_vec(), SENTINEL_PASSWORD))
        .await?;
    reply.body().deserialize().map_err(|e| e.to_string())
}

fn storage_name(s: Storage) -> &'static str {
    match s {
        Storage::Tpm => "tpm",
        Storage::EncryptedTpm => "encrypted-tpm",
        Storage::EncryptedHost => "encrypted-host",
    }
}

/// A stored import: one `import` entry, `stored`, the kind of the record and of the reply, no cause.
#[test]
fn import_names_kind() -> TestResult {
    for storage in STORAGES {
        for subject in SUBJECTS {
            let who = format!("{storage:?} {}", subject.reply);
            block_on(async {
                let kind = crate::rig::KindSvc::start(storage.kind()).await?;
                let svc = &kind.svc;
                let (key_type, reply_kind) = import_reply(svc, "k", subject).await?;
                assert_eq!(key_type, subject.reply, "{who}");
                let entries = svc.entries();
                assert_eq!(entries.len(), 1, "{who}");
                let e = &entries[0];
                assert_eq!(e.outcome_name(), "stored", "{who}");
                assert_eq!(e.storage_kind(), Some(storage.kind()), "{who}");
                assert_eq!(e.cause(), None, "{who}");
                let record = svc.store.get(uid(), "k")?.kind();
                assert_eq!(record, storage.kind(), "{who}");
                // The literal wire string, the record, the reply and the field are one value.
                let wire = storage_name(storage);
                assert_eq!(reply_kind, wire, "{who}");
                assert_eq!(record.wire(), wire, "{who}");
                assert_eq!(value(e, "CUSTODIO_STORAGE_KIND").as_deref(), Some(wire));
                assert_eq!(value(e, "CUSTODIO_CAUSE"), None, "{who}");
                assert_eq!(
                    value(e, "CUSTODIO_KEY_TYPE").as_deref(),
                    Some(subject.audit.name())
                );
                assert_eq!(value(e, "CUSTODIO_OUTCOME").as_deref(), Some("stored"));
                assert_eq!(value(e, "PRIORITY").as_deref(), Some("6"));
                assert_operation_clean(e, &secrets(svc, subject), &who);
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
    }
    Ok(())
}

/// Builds the TPM and the credentials of a failure; what must outlive the service is pushed on the vector.
type Make = fn(Subject, &mut Vec<Box<dyn Any>>) -> (Arc<Counting>, Arc<SpyCreds>);

/// A failure of the choice or of the storage, as the TPM and the credentials that produce it.
struct Failure {
    name: &'static str,
    /// The cause the entry carries.
    cause: ImportCause,
    /// The error name of the reply (F117's).
    err: &'static str,
    make: Make,
}

fn device_unopenable(_: Subject, keep: &mut Vec<Box<dyn Any>>) -> (Arc<Counting>, Arc<SpyCreds>) {
    // A directory where the node should be: the device is there and cannot be opened.
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("dev/tpmrm0")).unwrap();
    let tpm = Counting::new(Production::under(root.path()));
    keep.push(Box::new(root));
    (tpm, SpyCreds::new(MemoryCreds::host()))
}

fn tpm_error_in_query(_: Subject, keep: &mut Vec<Box<dyn Any>>) -> (Arc<Counting>, Arc<SpyCreds>) {
    let rig = Rig::new().unwrap();
    let (filter, _) = rig.filter(fault(cc::GET_CAPABILITY, 0x101)).unwrap();
    let tpm = Counting::new(TestTcti::new(&filter.tcti()));
    keep.push(Box::new((rig, filter)));
    (tpm, SpyCreds::new(MemoryCreds::host()))
}

fn owner_hierarchy_unusable(
    _: Subject,
    keep: &mut Vec<Box<dyn Any>>,
) -> (Arc<Counting>, Arc<SpyCreds>) {
    let rig = Rig::new().unwrap();
    rig.tpm
        .tool_ok("tpm2_changeauth", ["-c", "o", "owner-secret"])
        .unwrap();
    let tpm = Counting::new(TestTcti::new(&rig.tcti()));
    keep.push(Box::new(rig));
    (tpm, SpyCreds::new(MemoryCreds::host()))
}

fn faulted_import(
    code: u32,
    creds: MemoryCreds,
) -> (Arc<Counting>, Arc<SpyCreds>, Vec<Box<dyn Any>>) {
    let rig = Rig::new().unwrap();
    let (filter, _) = rig.filter(fault(cc::IMPORT, code)).unwrap();
    let tpm = Counting::new(TestTcti::new(&filter.tcti()));
    (tpm, SpyCreds::new(creds), vec![Box::new((rig, filter))])
}

fn tpm_error_during_import(
    _: Subject,
    keep: &mut Vec<Box<dyn Any>>,
) -> (Arc<Counting>, Arc<SpyCreds>) {
    let (tpm, creds, held) = faulted_import(0x101, MemoryCreds::host());
    keep.extend(held);
    (tpm, creds)
}

fn import_refused_lack_like(
    _: Subject,
    keep: &mut Vec<Box<dyn Any>>,
) -> (Arc<Counting>, Arc<SpyCreds>) {
    let (tpm, creds, held) = faulted_import(0x143, MemoryCreds::tpm());
    keep.extend(held);
    (tpm, creds)
}

fn creds_down_no_tpm(_: Subject, _: &mut Vec<Box<dyn Any>>) -> (Arc<Counting>, Arc<SpyCreds>) {
    let creds = SpyCreds::new(MemoryCreds::host());
    creds.fail_with(Some(CredsError::Unavailable));
    (Counting::new(NoTpm), creds)
}

fn creds_down_lacking_tpm(
    _: Subject,
    keep: &mut Vec<Box<dyn Any>>,
) -> (Arc<Counting>, Arc<SpyCreds>) {
    let rig = Rig::new().unwrap();
    let (filter, _) = rig.filter(lacks_import()).unwrap();
    let creds = SpyCreds::new(MemoryCreds::tpm());
    creds.fail_with(Some(CredsError::Unavailable));
    let tpm = Counting::new(TestTcti::new(&filter.tcti()));
    keep.push(Box::new((rig, filter)));
    (tpm, creds)
}

fn creds_cannot_encrypt(_: Subject, _: &mut Vec<Box<dyn Any>>) -> (Arc<Counting>, Arc<SpyCreds>) {
    let creds = SpyCreds::new(MemoryCreds::host());
    creds.fail_with(Some(CredsError::BadRequest));
    (Counting::new(NoTpm), creds)
}

fn binding_disagrees_with_tpm_kind(
    _: Subject,
    keep: &mut Vec<Box<dyn Any>>,
) -> (Arc<Counting>, Arc<SpyCreds>) {
    // The TPM lacks something, so the kind is encrypted TPM-bound; the credential names the host.
    let rig = Rig::new().unwrap();
    let (filter, _) = rig.filter(lacks_import()).unwrap();
    let tpm = Counting::new(TestTcti::new(&filter.tcti()));
    keep.push(Box::new((rig, filter)));
    (tpm, SpyCreds::new(MemoryCreds::host()))
}

fn binding_disagrees_with_host_kind(
    _: Subject,
    _: &mut Vec<Box<dyn Any>>,
) -> (Arc<Counting>, Arc<SpyCreds>) {
    // No TPM, so the kind is encrypted host-bound; the credential names a TPM.
    (Counting::new(NoTpm), SpyCreds::new(MemoryCreds::tpm()))
}

/// Every failure `storage_choice` injects, with the cause each must carry: a literal table, not the code's own rule.
const FAILURES: [Failure; 10] = [
    Failure {
        name: "device unopenable",
        cause: ImportCause::TpmDevice,
        err: ERR_TPM,
        make: device_unopenable,
    },
    Failure {
        name: "TPM error in the query",
        cause: ImportCause::TpmError,
        err: ERR_TPM,
        make: tpm_error_in_query,
    },
    Failure {
        name: "owner hierarchy unusable",
        cause: ImportCause::TpmOwner,
        err: ERR_TPM,
        make: owner_hierarchy_unusable,
    },
    Failure {
        name: "TPM error during the import",
        cause: ImportCause::TpmError,
        err: ERR_TPM,
        make: tpm_error_during_import,
    },
    Failure {
        name: "import refused with a lack-like code",
        cause: ImportCause::TpmError,
        err: ERR_TPM,
        make: import_refused_lack_like,
    },
    Failure {
        name: "credentials down, no TPM",
        cause: ImportCause::CredentialsUnavailable,
        err: ERR_CREDS,
        make: creds_down_no_tpm,
    },
    Failure {
        name: "credentials down, lacking TPM",
        cause: ImportCause::CredentialsUnavailable,
        err: ERR_CREDS,
        make: creds_down_lacking_tpm,
    },
    Failure {
        name: "credentials cannot encrypt",
        cause: ImportCause::CredentialsRefused,
        err: ERR_CREDS,
        make: creds_cannot_encrypt,
    },
    Failure {
        name: "binding disagrees with the TPM kind",
        cause: ImportCause::BindingMismatch,
        err: ERR_CREDS,
        make: binding_disagrees_with_tpm_kind,
    },
    Failure {
        name: "binding disagrees with the host kind",
        cause: ImportCause::BindingMismatch,
        err: ERR_CREDS,
        make: binding_disagrees_with_host_kind,
    },
];

/// Each failure leaves one `import` entry with `storage_failure`, its cause, the key type, and no kind.
#[test]
fn import_failure_causes() -> TestResult {
    for failure in &FAILURES {
        for subject in SUBJECTS {
            let who = format!("{} {}", failure.name, subject.reply);
            let mut keep = Vec::new();
            let (tpm, creds) = (failure.make)(subject, &mut keep);
            block_on(async {
                let svc = Svc::start(tpm, creds, Answer::Yes).await?;
                assert_eq!(
                    svc.import_subject("k", subject).await,
                    Err(failure.err.to_owned()),
                    "{who}"
                );
                svc.assert_empty(&who);
                let entries = svc.entries();
                assert_eq!(entries.len(), 1, "{who}");
                let e = &entries[0];
                assert_eq!(e.outcome_name(), "storage_failure", "{who}");
                assert_eq!(e.priority(), 3, "{who}");
                assert_eq!(e.key_type(), Some(subject.audit), "{who}");
                assert_eq!(e.cause(), Some(failure.cause), "{who}");
                assert_eq!(e.storage_kind(), None, "{who}");
                assert_eq!(
                    value(e, "CUSTODIO_CAUSE").as_deref(),
                    Some(failure.cause.name()),
                    "{who}"
                );
                assert_eq!(value(e, "CUSTODIO_STORAGE_KIND"), None, "{who}");
                assert_operation_clean(e, &secrets(&svc, subject), &who);
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
    }
    // The table tells apart every cause the injections can produce, and a constant cause would fail it.
    let used: std::collections::BTreeSet<_> = FAILURES.iter().map(|f| f.cause.name()).collect();
    assert_eq!(
        used.into_iter().collect::<Vec<_>>(),
        [
            "binding_mismatch",
            "credentials_refused",
            "credentials_unavailable",
            "tpm_device",
            "tpm_error",
            "tpm_owner"
        ]
    );
    Ok(())
}

/// A request that fails before the choice: name, polkit's answer, file, password, outcome and priority.
type Row<'a> = (&'a str, Answer, &'a [u8], &'a str, &'a str, &'a str);

/// A failure before the choice has no cause and no kind, and the fields it had.
#[test]
fn other_import_entries_unchanged() -> TestResult {
    block_on(async {
        for subject in SUBJECTS {
            let who = subject.reply;
            let ed25519 = include_bytes!("../fixtures/ed25519.p12");
            let rows: [Row; 4] = [
                (
                    "denied",
                    Answer::No,
                    subject.p12,
                    SENTINEL_PASSWORD,
                    "denied",
                    "5",
                ),
                (
                    "authorization unavailable",
                    Answer::Fail,
                    subject.p12,
                    SENTINEL_PASSWORD,
                    "authorization_unavailable",
                    "4",
                ),
                (
                    "wrong password",
                    Answer::Yes,
                    subject.p12,
                    "not-the-password",
                    "wrong_password",
                    "4",
                ),
                (
                    "unsupported key",
                    Answer::Yes,
                    ed25519,
                    PASSWORD,
                    "unsupported_key",
                    "4",
                ),
            ];
            for (name, answer, p12, password, outcome, priority) in rows {
                let svc = Svc::start(
                    Counting::new(NoTpm),
                    SpyCreds::new(MemoryCreds::host()),
                    answer,
                )
                .await?;
                let got = svc
                    .call_method("ImportP12", &("k", p12.to_vec(), password))
                    .await;
                assert!(got.is_err(), "{who}: {name}");
                svc.assert_empty(who);
                let entries = svc.entries();
                assert_eq!(entries.len(), 1, "{who}: {name}");
                let e = &entries[0];
                assert_eq!(e.outcome_name(), outcome, "{who}: {name}");
                assert_eq!((e.storage_kind(), e.cause()), (None, None), "{who}: {name}");
                let names: Vec<_> = e.fields().into_iter().map(|(n, _)| n).collect();
                assert_eq!(names, OLD_FIELDS, "{who}: {name}");
                assert_eq!(value(e, "PRIORITY").as_deref(), Some(priority), "{who}");
                assert_operation_clean(e, &secrets(&svc, subject), name);
            }
        }
        Ok(())
    })
}

/// Control for the rows: the key-type field of a failed import is still there, so the checks above do not hold
/// by an entry with nothing in it.
#[test]
fn failed_entry_keeps_its_old_fields() -> TestResult {
    block_on(async {
        let subject = SUBJECTS[0];
        let creds = SpyCreds::new(MemoryCreds::host());
        creds.fail_with(Some(CredsError::Unavailable));
        let svc = Svc::start(Counting::new(NoTpm), creds, Answer::Yes).await?;
        svc.import_subject("k", subject).await.unwrap_err();
        let e = &svc.entries()[0];
        let names: Vec<_> = e.fields().into_iter().map(|(n, _)| n).collect();
        let mut want = OLD_FIELDS[..9].to_vec();
        want.extend([
            "CUSTODIO_KEY_TYPE",
            "CUSTODIO_CAUSE",
            "CUSTODIO_APP_ID_STATE",
        ]);
        assert_eq!(names, want);
        Ok(())
    })
}

/// The entry of each failure in [`FAILURES`] for `subject`, and of an import of each kind.
pub fn entries_for_queries(subject: Subject) -> Vec<OperationEntry> {
    let mut out = Vec::new();
    for failure in &FAILURES {
        let mut keep = Vec::new();
        let (tpm, creds) = (failure.make)(subject, &mut keep);
        block_on(async {
            let svc = Svc::start(tpm, creds, Answer::Yes).await.unwrap();
            svc.import_subject("k", subject).await.unwrap_err();
            out.extend(svc.entries());
        });
    }
    for storage in STORAGES {
        block_on(async {
            let kind = crate::rig::KindSvc::start(storage.kind()).await.unwrap();
            import_reply(&kind.svc, "k", subject).await.unwrap();
            out.extend(kind.svc.entries());
        });
    }
    out
}
