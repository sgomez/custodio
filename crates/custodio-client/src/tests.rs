use super::*;

#[test]
fn names_are_the_documented_literals() {
    assert_eq!(BUS_NAME, "com.rfirma.Custodio1");
    let want = [
        (ERROR_INVALID_ARGS, "InvalidArgs"),
        (ERROR_NO_SUCH_KEY, "NoSuchKey"),
        (ERROR_KEY_ID_TAKEN, "KeyIdTaken"),
        (ERROR_POLKIT_DENIED, "PolkitDenied"),
        (ERROR_AUTHORIZATION_UNAVAILABLE, "AuthorizationUnavailable"),
        (ERROR_WRONG_PASSWORD_OR_BAD_P12, "WrongPasswordOrBadP12"),
        (ERROR_UNSUPPORTED_KEY_TYPE, "UnsupportedKeyType"),
        (ERROR_CERTIFICATE_MISMATCH, "CertificateMismatch"),
        (ERROR_AUDIT_UNAVAILABLE, "AuditUnavailable"),
        (ERROR_TPM_FAILED, "TpmFailed"),
        (ERROR_CREDENTIALS_UNAVAILABLE, "CredentialsUnavailable"),
        (ERROR_KEY_LOST, "KeyLost"),
        (ERROR_TEMPORARILY_UNAVAILABLE, "TemporarilyUnavailable"),
        (ERROR_INTERNAL, "Internal"),
    ];
    for (name, last) in want {
        assert_eq!(name, format!("com.rfirma.Custodio1.Error.{last}"));
    }
}
