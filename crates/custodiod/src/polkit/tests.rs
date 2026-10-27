use super::*;

#[test]
fn request_uses_system_bus_name_subject_and_interaction() -> Result<(), AuthError> {
    let ((kind, details), action, extra, flags, cancel) = request(":1.42")?;
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
fn non_unique_senders_are_rejected() {
    for bad in [
        "",
        "com.rfirma.Custodio1",
        "org.freedesktop.DBus",
        "1.42",
        ":",
    ] {
        assert!(matches!(request(bad), Err(AuthError::BadSender)), "{bad}");
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
