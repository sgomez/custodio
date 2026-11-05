use zbus::names::OwnedErrorName;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn method_error(name: &str, text: Option<&str>) -> Result<zbus::Error, Box<dyn std::error::Error>> {
    let message = zbus::Message::method_call("/x", "M").build(&())?;
    let name = OwnedErrorName::try_from(name)?;
    Ok(zbus::Error::MethodError(
        name,
        text.map(str::to_owned),
        message,
    ))
}

#[test]
fn the_reply_error_name_picks_the_failure() -> TestResult {
    for name in [
        "com.rfirma.Custodio1.Error.InvalidArgs",
        "com.rfirma.Custodio1.Error.PolkitDenied",
        "com.rfirma.Custodio1.Error.FromTheFuture",
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "org.freedesktop.DBus.Error.AccessDenied",
    ] {
        let want = ServiceFailure::from_name(name);
        assert_eq!(
            failure_of(&method_error(name, Some("SERVICE FREE TEXT"))?),
            want
        );
        assert_eq!(failure_of(&method_error(name, None)?), want);
    }
    Ok(())
}

#[test]
fn transport_errors_say_so() {
    assert_eq!(
        failure_of(&zbus::Error::Unsupported),
        ServiceFailure::Transport
    );
    for absent in [
        zbus::fdo::Error::ServiceUnknown("x".into()),
        zbus::fdo::Error::NameHasNoOwner("x".into()),
    ] {
        assert_eq!(
            failure_of(&zbus::Error::FDO(Box::new(absent))),
            ServiceFailure::ServiceAbsent
        );
    }
    let other = zbus::Error::FDO(Box::new(zbus::fdo::Error::AccessDenied("x".into())));
    assert_eq!(failure_of(&other), ServiceFailure::Transport);
}

#[test]
fn a_list_element_keeps_each_field_in_its_place() {
    let entry = key_entry((
        "id1".into(),
        "rsa2048".into(),
        "encrypted-tpm".into(),
        vec![1, 2, 3],
    ));
    assert_eq!(entry.id, "id1");
    assert_eq!(entry.key_type, "rsa2048");
    assert_eq!(entry.kind, Kind::EncryptedTpm);
    assert_eq!(entry.certificate, vec![1, 2, 3]);
}
