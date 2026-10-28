use super::*;

fn map(uid: Option<OwnedVariant>, pid: Option<OwnedVariant>) -> HashMap<String, OwnedVariant> {
    let mut m = HashMap::new();
    if let Some(v) = uid {
        m.insert("UnixUserID".to_owned(), v);
    }
    if let Some(v) = pid {
        m.insert("ProcessID".to_owned(), v);
    }
    m
}

fn num(v: u32) -> OwnedVariant {
    OwnedVariant::from(v)
}

#[test]
fn caller_from_both_fields() {
    let got = caller_from(&map(Some(num(1_234_567)), Some(num(7_654_321))));
    assert_eq!(
        got,
        Ok(Caller {
            uid: 1_234_567,
            pid: 7_654_321
        })
    );
}

#[test]
fn caller_from_missing_pid() {
    assert_eq!(
        caller_from(&map(Some(num(1_234_567)), None)),
        Err(CredentialsError::Missing)
    );
}

#[test]
fn caller_from_missing_uid() {
    assert_eq!(
        caller_from(&map(None, Some(num(7_654_321)))),
        Err(CredentialsError::Missing)
    );
}

#[test]
fn caller_from_wrong_types() {
    let text = Some(OwnedVariant::from(true));
    assert_eq!(
        caller_from(&map(text.clone(), Some(num(7_654_321)))),
        Err(CredentialsError::Missing)
    );
    assert_eq!(
        caller_from(&map(Some(num(1_234_567)), text)),
        Err(CredentialsError::Missing)
    );
}

#[test]
fn caller_from_empty_map() {
    assert_eq!(caller_from(&HashMap::new()), Err(CredentialsError::Missing));
}

#[test]
fn errors_display() {
    assert_eq!(
        CredentialsError::Missing.to_string(),
        "bus credentials incomplete"
    );
    assert_eq!(
        CredentialsError::Bus.to_string(),
        "bus credentials unavailable"
    );
}
