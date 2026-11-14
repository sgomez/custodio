use super::*;
use std::os::fd::AsFd;

#[test]
fn request_uses_system_bus_name_subject_and_interaction() -> Result<(), AuthError> {
    let ((kind, details), action, extra, flags, cancel) = request(":1.42", ACTION_ID)?;
    assert_eq!(kind, "system-bus-name");
    assert_eq!(details.len(), 1);
    assert_eq!(details.get("name"), Some(&Variant::from(":1.42")));
    assert_eq!(action, "com.rfirma.custodio.sign");
    assert!(extra.is_empty());
    assert_eq!(flags, 1);
    assert_eq!(cancel, "");
    Ok(())
}

#[test]
fn request_carries_the_given_action() -> Result<(), AuthError> {
    let (_, action, _, flags, _) = request(":1.42", IMPORT_ACTION_ID)?;
    assert_eq!(action, "com.rfirma.custodio.import-certificate");
    assert_eq!(flags, 1);
    Ok(())
}

#[test]
fn non_unique_senders_are_rejected() {
    for bad in [
        "",
        "com.rfirma.Custodio1",
        "org.freedesktop.DBus",
        "1.42",
        ":",
    ] {
        assert!(
            matches!(request(bad, ACTION_ID), Err(AuthError::BadSender)),
            "{bad}"
        );
    }
}

#[test]
fn auth_errors_display() {
    assert_eq!(
        AuthError::BadSender.to_string(),
        "sender is not a unique bus name"
    );
    assert_eq!(AuthError::Denied.to_string(), "not authorized");
    assert_eq!(
        AuthError::Unavailable("why".into()).to_string(),
        "polkit unavailable: why"
    );
}

#[test]
fn process_subject_carries_the_uid_as_int32_the_way_polkit_reads_it() -> std::io::Result<()> {
    let file = std::fs::File::open("/dev/null")?;
    let ((kind, details), action, _, flags, _) = process_request(file.as_fd(), 1001_i32, ACTION_ID);
    assert_eq!(kind, "unix-process");
    // polkit reads `uid` as an int32; any other type is ignored and ends in "'pidfd' specified withtout 'uid'"
    assert_eq!(details.get("uid"), Some(&Variant::from(1001_i32)));
    assert!(details.contains_key("pidfd"));
    assert_eq!(action, ACTION_ID);
    assert_eq!(flags, 1);
    Ok(())
}
