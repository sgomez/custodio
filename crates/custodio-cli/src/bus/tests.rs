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
fn every_name_has_its_message() -> TestResult {
    let table = [
        (
            ERROR_INVALID_ARGS,
            "the service rejected the request: the key id, the file or the password is not acceptable",
        ),
        (
            ERROR_KEY_ID_TAKEN,
            "a key with this id already exists; choose another with --id",
        ),
        (
            ERROR_WRONG_PASSWORD_OR_BAD_P12,
            "wrong password, or the file is not a usable .p12 (it must hold one private key and its certificate)",
        ),
        (
            ERROR_UNSUPPORTED_KEY_TYPE,
            "unsupported key type; only RSA 2048 and ECDSA P-256 are accepted",
        ),
        (
            ERROR_CERTIFICATE_MISMATCH,
            "no certificate in the .p12 file matches its private key",
        ),
        (
            ERROR_INTERNAL,
            "the service could not store the key (see its log)",
        ),
        (
            ERROR_AUDIT_UNAVAILABLE,
            "the service cannot write its audit log (see its log)",
        ),
        (
            ERROR_NO_SUCH_KEY,
            "the service reports that no such key exists",
        ),
        (ERROR_POLKIT_DENIED, "not authorized"),
        (
            ERROR_AUTHORIZATION_UNAVAILABLE,
            "the service cannot ask for authorization (see its log)",
        ),
        (
            "com.rfirma.Custodio1.Error.FromTheFuture",
            "the service answered with an unknown error (com.rfirma.Custodio1.Error.FromTheFuture)",
        ),
    ];
    for (name, want) in table {
        assert_eq!(message_for_name(name), want, "{name}");
        // Whatever text the service sent, it is not shown.
        let got = error_message(&method_error(name, Some("SERVICE FREE TEXT"))?);
        assert_eq!(got, want, "{name}");
        assert_eq!(error_message(&method_error(name, None)?), want, "{name}");
    }
    Ok(())
}

#[test]
fn transport_errors_say_so() {
    assert_eq!(
        error_message(&zbus::Error::Unsupported),
        format!("cannot talk to the service: {}", zbus::Error::Unsupported)
    );
    let fdo = zbus::Error::FDO(Box::new(zbus::fdo::Error::ServiceUnknown("x".into())));
    assert!(error_message(&fdo).starts_with("cannot talk to the service: "));
}
