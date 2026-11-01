//! The operation field and the entries of import, delete and replace certificate.
use super::*;
use std::collections::BTreeSet;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

const C: Caller = Caller { uid: 10, pid: 20 };

fn key() -> Result<KeyId, InvalidKeyId> {
    KeyId::new("k9")
}

fn get(f: &[(&'static str, String)], name: &str) -> Option<String> {
    f.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone())
}

fn literal<'a>(f: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    f.iter().map(|(n, v)| (*n, v.as_str())).collect()
}

#[test]
fn signing_fields_are_the_old_list_plus_the_operation() -> TestResult {
    let table = [
        (Outcome::Signed, "signature made", "6", "signed"),
        (
            Outcome::SigningFailed,
            "signing failed after approval",
            "3",
            "signing_failed",
        ),
        (Outcome::Denied, "signature denied", "5", "denied"),
        (
            Outcome::AuthorizationUnavailable,
            "authorization unavailable, no signature",
            "4",
            "authorization_unavailable",
        ),
    ];
    for (o, phrase, prio, name) in table {
        let with = Entry::new(o, C, key()?, Some(AuditMechanism::Ecdsa)).fields();
        let message = format!("{phrase}: uid 10 pid 20 key k9");
        assert_eq!(
            literal(&with),
            [
                ("MESSAGE", message.as_str()),
                ("MESSAGE_ID", "29c3d30e6c4242406c6db3f120d36401"),
                ("PRIORITY", prio),
                ("SYSLOG_IDENTIFIER", "custodiod"),
                ("CUSTODIO_UID", "10"),
                ("CUSTODIO_PID", "20"),
                ("CUSTODIO_KEY_ID", "k9"),
                ("CUSTODIO_OPERATION", "sign"),
                ("CUSTODIO_OUTCOME", name),
                ("CUSTODIO_MECHANISM", "ecdsa"),
            ]
        );
        let without = Entry::without_caller(key()?, None).fields();
        assert_eq!(get(&without, "CUSTODIO_OPERATION").as_deref(), Some("sign"));
    }
    Ok(())
}

#[test]
fn operation_names_are_the_four_documented_ones() {
    let all = |o: Operation| match o {
        Operation::Sign | Operation::Import | Operation::Delete | Operation::ReplaceCertificate => {
            Operation::all()
        }
    };
    let names: Vec<_> = all(Operation::Sign).iter().map(|o| o.name()).collect();
    assert_eq!(names, ["sign", "import", "delete", "replace_certificate"]);
}

#[test]
fn ids_are_32_lower_hex_and_distinct() {
    let ids: BTreeSet<_> = Operation::all().iter().map(|o| o.message_id()).collect();
    assert_eq!(ids.len(), 4);
    for id in &ids {
        assert!(id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }
    assert_eq!(Operation::Sign.message_id(), MESSAGE_ID);
    assert_eq!(
        Operation::Import.message_id(),
        "4c7163ce45d0b9faf8e7c38d098bdb22"
    );
    assert_eq!(
        Operation::Delete.message_id(),
        "13d1a981ea8f64fc1a6f390bee7fd66c"
    );
    assert_eq!(
        Operation::ReplaceCertificate.message_id(),
        "336e0b53720a735afb179ebc7f779ed6"
    );
}

/// (operation, outcome, priority, message phrase) as literals.
type Row = (&'static str, &'static str, &'static str, &'static str);

fn check(e: &OperationEntry, id: &str, row: Row) {
    let (op, outcome, prio, phrase) = row;
    let f = e.fields();
    let message = format!("{phrase}: uid 10 pid 20 key k9");
    assert_eq!(
        literal(&f).into_iter().take(9).collect::<Vec<_>>(),
        vec![
            ("MESSAGE", message.as_str()),
            ("MESSAGE_ID", id),
            ("PRIORITY", prio),
            ("SYSLOG_IDENTIFIER", "custodiod"),
            ("CUSTODIO_UID", "10"),
            ("CUSTODIO_PID", "20"),
            ("CUSTODIO_KEY_ID", "k9"),
            ("CUSTODIO_OPERATION", op),
            ("CUSTODIO_OUTCOME", outcome),
        ]
    );
    assert_eq!(e.message(), message);
    assert_eq!(e.operation().name(), op);
    assert_eq!(e.outcome_name(), outcome);
    assert_eq!(e.priority().to_string(), prio);
}

#[test]
fn import_outcomes() -> TestResult {
    let rows: [(ImportOutcome, &str, &str, &str); 6] = [
        (ImportOutcome::Stored, "stored", "6", "key imported"),
        (ImportOutcome::Denied, "denied", "5", "import denied"),
        (
            ImportOutcome::AuthorizationUnavailable,
            "authorization_unavailable",
            "4",
            "import authorization unavailable, nothing stored",
        ),
        (
            ImportOutcome::WrongPassword,
            "wrong_password",
            "4",
            "import failed, wrong password",
        ),
        (
            ImportOutcome::UnsupportedKey,
            "unsupported_key",
            "4",
            "import failed, unsupported key",
        ),
        (
            ImportOutcome::StorageFailure,
            "storage_failure",
            "3",
            "import failed after approval, key not stored",
        ),
    ];
    let all = ImportOutcome::all();
    assert_eq!(all.len(), rows.len());
    for (o, name, prio, phrase) in rows {
        assert!(all.contains(&o));
        let e = OperationEntry::import(o, Some(C), key()?, None);
        check(
            &e,
            "4c7163ce45d0b9faf8e7c38d098bdb22",
            ("import", name, prio, phrase),
        );
        assert_eq!(e.fields().len(), 9, "no key type unless known");
        let typed = OperationEntry::import(o, Some(C), key()?, Some(AuditKeyType::EcdsaP256));
        assert_eq!(
            get(&typed.fields(), "CUSTODIO_KEY_TYPE").as_deref(),
            Some("ecdsa_p256")
        );
        assert_eq!(typed.key_type(), Some(AuditKeyType::EcdsaP256));
    }
    assert_eq!(AuditKeyType::Rsa2048.name(), "rsa_2048");
    assert_eq!(AuditKeyType::all().len(), 2);
    Ok(())
}

#[test]
fn delete_outcomes() -> TestResult {
    let rows: [(DeleteOutcome, &str, &str, &str); 4] = [
        (DeleteOutcome::Deleted, "deleted", "6", "key deleted"),
        (DeleteOutcome::Denied, "denied", "5", "delete denied"),
        (
            DeleteOutcome::AuthorizationUnavailable,
            "authorization_unavailable",
            "4",
            "delete authorization unavailable, nothing deleted",
        ),
        (
            DeleteOutcome::StorageFailure,
            "storage_failure",
            "3",
            "delete failed after approval, key not removed",
        ),
    ];
    assert_eq!(DeleteOutcome::all().len(), rows.len());
    for (o, name, prio, phrase) in rows {
        assert!(DeleteOutcome::all().contains(&o));
        let e = OperationEntry::delete(o, Some(C), key()?);
        check(
            &e,
            "13d1a981ea8f64fc1a6f390bee7fd66c",
            ("delete", name, prio, phrase),
        );
        assert_eq!(e.fields().len(), 9);
        assert_eq!(e.key_type(), None);
    }
    Ok(())
}

#[test]
fn replace_certificate_outcomes() -> TestResult {
    let rows: [(ReplaceOutcome, &str, &str, &str); 5] = [
        (
            ReplaceOutcome::Replaced,
            "replaced",
            "6",
            "certificate replaced",
        ),
        (
            ReplaceOutcome::Denied,
            "denied",
            "5",
            "certificate replacement denied",
        ),
        (
            ReplaceOutcome::AuthorizationUnavailable,
            "authorization_unavailable",
            "4",
            "certificate replacement authorization unavailable, nothing changed",
        ),
        (
            ReplaceOutcome::CertificateMismatch,
            "certificate_mismatch",
            "4",
            "certificate replacement refused, certificate does not match the key",
        ),
        (
            ReplaceOutcome::StorageFailure,
            "storage_failure",
            "3",
            "certificate replacement failed after approval, nothing changed",
        ),
    ];
    assert_eq!(ReplaceOutcome::all().len(), rows.len());
    for (o, name, prio, phrase) in rows {
        assert!(ReplaceOutcome::all().contains(&o));
        let e = OperationEntry::replace_certificate(o, Some(C), key()?);
        check(
            &e,
            "336e0b53720a735afb179ebc7f779ed6",
            ("replace_certificate", name, prio, phrase),
        );
        assert_eq!(e.fields().len(), 9);
    }
    Ok(())
}

#[test]
fn no_caller_writes_no_uid_or_pid() -> TestResult {
    let e = OperationEntry::delete(DeleteOutcome::AuthorizationUnavailable, None, key()?);
    assert_eq!(e.caller(), None);
    assert_eq!(e.key_id().as_str(), "k9");
    let f = e.fields();
    assert!(get(&f, "CUSTODIO_UID").is_none() && get(&f, "CUSTODIO_PID").is_none());
    assert_eq!(
        e.message(),
        "delete authorization unavailable, nothing deleted: uid unknown pid unknown key k9"
    );
    Ok(())
}

#[test]
fn operation_entries_reach_the_sinks() -> TestResult {
    let e = OperationEntry::delete(DeleteOutcome::Deleted, Some(C), key()?);
    let sink = MemorySink::default();
    sink.record_operation(&e)?;
    assert_eq!(sink.operation_entries(), vec![e.clone()]);
    assert_eq!(sink.entries(), Vec::new());
    assert!(FailingSink.record_operation(&e).is_err());
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("j.sock");
    let socket = std::os::unix::net::UnixDatagram::bind(&path)?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    JournalSink::new(&path).record_operation(&e)?;
    let mut buf = vec![0u8; 4096];
    let n = socket.recv(&mut buf)?;
    let text = String::from_utf8(buf.get(..n).ok_or("short")?.to_vec())?;
    assert!(text.contains("\nCUSTODIO_OPERATION=delete\n"));
    assert!(text.contains("\nMESSAGE_ID=13d1a981ea8f64fc1a6f390bee7fd66c\n"));
    Ok(())
}

#[test]
fn debug_prints_only_typed_fields() -> TestResult {
    let e = OperationEntry::import(
        ImportOutcome::Stored,
        Some(C),
        key()?,
        Some(AuditKeyType::Rsa2048),
    );
    let d = format!("{e:?}");
    assert!(d.contains("Stored") && d.contains("k9") && d.contains("Rsa2048"));
    Ok(())
}

#[test]
fn the_caller_is_returned_as_given() -> TestResult {
    let e = OperationEntry::delete(DeleteOutcome::Deleted, Some(C), key()?);
    assert_eq!(e.caller(), Some(C));
    Ok(())
}
