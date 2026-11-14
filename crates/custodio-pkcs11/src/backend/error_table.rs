use custodio_client::{
    ERROR_AUDIT_UNAVAILABLE, ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_CERTIFICATE_MISMATCH,
    ERROR_INTERNAL, ERROR_INVALID_ARGS, ERROR_KEY_ID_TAKEN, ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED,
    ERROR_UNSUPPORTED_KEY_TYPE, ERROR_WRONG_PASSWORD_OR_BAD_P12,
};

use super::BackendError;

/// The service failures and the `BackendError` each ends as, for `ListKeys` and for `Sign` alike
/// (both go through `map_error`): the ten names of the client crate, names this version does not
/// know, the generic bus names.
#[must_use]
pub fn error_table() -> Vec<(&'static str, BackendError)> {
    use BackendError::{Denied, Invalid, Unavailable};
    vec![
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
    ]
}
