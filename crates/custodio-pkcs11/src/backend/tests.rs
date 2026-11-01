use custodio_client::{
    ERROR_AUDIT_UNAVAILABLE, ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_CERTIFICATE_MISMATCH,
    ERROR_INTERNAL, ERROR_INVALID_ARGS, ERROR_KEY_ID_TAKEN, ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED,
    ERROR_UNSUPPORTED_KEY_TYPE, ERROR_WRONG_PASSWORD_OR_BAD_P12,
};
use zbus::names::OwnedErrorName;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn method_error(name: &str) -> Result<zbus::Error, Box<dyn std::error::Error>> {
    let message = zbus::Message::method_call("/x", "M").build(&())?;
    let name = OwnedErrorName::try_from(name)?;
    Ok(zbus::Error::MethodError(name, Some("text".into()), message))
}

/// Each service failure and the `BackendError` it has always ended as: the module turns `Denied`
/// into `CKR_FUNCTION_FAILED`, `Invalid` into `CKR_DATA_INVALID` and `Unavailable` into
/// `CKR_DEVICE_ERROR` (pinned by `composed_failure_ends_the_operation`).
#[test]
fn every_service_name_maps_to_the_error_it_always_did() -> TestResult {
    use BackendError::{Denied, Invalid, Unavailable};
    let table = [
        (ERROR_POLKIT_DENIED, Denied),
        (ERROR_AUTHORIZATION_UNAVAILABLE, Denied),
        (ERROR_INVALID_ARGS, Invalid),
        (ERROR_NO_SUCH_KEY, Unavailable),
        (ERROR_AUDIT_UNAVAILABLE, Unavailable),
        (ERROR_INTERNAL, Unavailable),
        (ERROR_KEY_ID_TAKEN, Unavailable),
        (ERROR_WRONG_PASSWORD_OR_BAD_P12, Unavailable),
        (ERROR_UNSUPPORTED_KEY_TYPE, Unavailable),
        (ERROR_CERTIFICATE_MISMATCH, Unavailable),
        // Names this version does not know.
        ("com.rfirma.Custodio1.Error.FromTheFuture", Unavailable),
        ("org.freedesktop.DBus.Error.Failed", Unavailable),
        ("org.freedesktop.DBus.Error.ServiceUnknown", Unavailable),
        // The bus itself, or an older service, with the generic names.
        ("org.freedesktop.DBus.Error.AccessDenied", Denied),
        ("org.freedesktop.DBus.Error.InvalidArgs", Invalid),
    ];
    for (name, want) in table {
        assert_eq!(map_error(&method_error(name)?), want, "{name}");
    }
    Ok(())
}

#[test]
fn other_errors_are_unavailable() {
    assert_eq!(
        map_error(&zbus::Error::Unsupported),
        BackendError::Unavailable
    );
    let fdo = |e| map_error(&zbus::Error::FDO(Box::new(e)));
    assert_eq!(
        fdo(zbus::fdo::Error::AccessDenied("x".into())),
        BackendError::Denied
    );
    assert_eq!(
        fdo(zbus::fdo::Error::InvalidArgs("x".into())),
        BackendError::Invalid
    );
    assert_eq!(
        fdo(zbus::fdo::Error::Failed("x".into())),
        BackendError::Unavailable
    );
}
