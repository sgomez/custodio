//! The app-id fields of the entries, built from the case alone.

use std::error::Error;

use super::{
    APP_ID_FIELD, APP_ID_STATE_FIELD, AuditMechanism, Caller, DeleteOutcome, Entry, ImportOutcome,
    KeyId, OperationEntry, Outcome, ReplaceOutcome, app_id_state,
};
use crate::app_id::{AppIdOutcome, validate};

type TestResult = Result<(), Box<dyn Error>>;

const CALLER: Caller = Caller { uid: 1, pid: 2 };

fn cases() -> Result<[(AppIdOutcome, &'static str); 3], Box<dyn Error>> {
    let id = validate(b"org.example.App").ok_or("id")?;
    Ok([
        (AppIdOutcome::Read(id), "read"),
        (AppIdOutcome::None, "none"),
        (AppIdOutcome::Undetermined, "undetermined"),
    ])
}

type Fields = Vec<(&'static str, String)>;

fn all(app_id: &AppIdOutcome) -> Result<Vec<(Fields, String)>, Box<dyn Error>> {
    let key = || KeyId::new("k");
    let sign = Entry::new(Outcome::Signed, CALLER, key()?, Some(AuditMechanism::Ecdsa))
        .with_app_id(app_id.clone());
    let without = Entry::without_caller(key()?, None).with_app_id(app_id.clone());
    let ops = [
        OperationEntry::import(ImportOutcome::Stored, Some(CALLER), key()?, None),
        OperationEntry::delete(DeleteOutcome::Deleted, None, key()?),
        OperationEntry::replace_certificate(ReplaceOutcome::Replaced, Some(CALLER), key()?),
    ];
    let mut out = vec![
        (sign.fields(), sign.message()),
        (without.fields(), without.message()),
    ];
    for e in ops {
        let e = e.with_app_id(app_id.clone());
        out.push((e.fields(), e.message()));
    }
    Ok(out)
}

#[test]
fn wire_value_of_each_case() -> TestResult {
    for (case, state) in cases()? {
        assert_eq!(app_id_state(&case), state);
        for (fields, message) in all(&case)? {
            let get = |n: &str| {
                fields
                    .iter()
                    .find(|(f, _)| *f == n)
                    .map(|(_, v)| v.as_str())
            };
            assert_eq!(get(APP_ID_STATE_FIELD), Some(state));
            let want = match &case {
                AppIdOutcome::Read(id) => Some(id.as_str()),
                _ => None,
            };
            assert_eq!(get(APP_ID_FIELD), want);
            // Exactly one of each field, and the message is the same with every case.
            assert_eq!(
                fields
                    .iter()
                    .filter(|(n, _)| n.starts_with("CUSTODIO_APP_ID"))
                    .count(),
                1 + usize::from(want.is_some())
            );
            assert!(!message.contains("example"), "{message}");
        }
    }
    Ok(())
}

#[test]
fn an_entry_without_a_case_is_undetermined() -> TestResult {
    let e = Entry::new(Outcome::Signed, CALLER, KeyId::new("k")?, None);
    assert_eq!(e.app_id(), &AppIdOutcome::Undetermined);
    let o = OperationEntry::delete(DeleteOutcome::Denied, None, KeyId::new("k")?);
    assert_eq!(o.app_id(), &AppIdOutcome::Undetermined);
    Ok(())
}

#[test]
fn the_messages_do_not_change() -> TestResult {
    let e = Entry::new(Outcome::Signed, CALLER, KeyId::new("k")?, None);
    let (read, _) = cases()?.into_iter().next().ok_or("case")?;
    assert_eq!(e.clone().with_app_id(read).message(), e.message());
    assert_eq!(e.message(), "signature made: uid 1 pid 2 key k");
    Ok(())
}
