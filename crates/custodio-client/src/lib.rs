//! What the clients (`custodio-cli`, `custodio-pkcs11`) and the service (`custodiod`) agree on.
//!
//! The bus name, the object path, the documented bounds and the D-Bus error names live here, so
//! the clients never link the service.
#![forbid(unsafe_code)]

/// Well-known bus name of the service.
pub const BUS_NAME: &str = "com.rfirma.Custodio1";
/// Object path of the service.
pub const OBJECT_PATH: &str = "/com/rfirma/Custodio1";
/// Largest `.p12` accepted. Real files are a few kilobytes.
pub const MAX_P12_LEN: usize = 1024 * 1024;
/// Largest DER certificate `ReplaceCertificate` accepts. Real certificates are one to a few kilobytes.
pub const MAX_CERT_LEN: usize = 16 * 1024;

/// The call was malformed: bad key id, mechanism, hash, salt length, data size or password size,
/// or a data length the mechanism cannot take.
pub const ERROR_INVALID_ARGS: &str = "com.rfirma.Custodio1.Error.InvalidArgs";
/// No key has the given id.
pub const ERROR_NO_SUCH_KEY: &str = "com.rfirma.Custodio1.Error.NoSuchKey";
/// A key with the given id is already stored.
pub const ERROR_KEY_ID_TAKEN: &str = "com.rfirma.Custodio1.Error.KeyIdTaken";
/// polkit refused the signature.
pub const ERROR_POLKIT_DENIED: &str = "com.rfirma.Custodio1.Error.PolkitDenied";
/// The caller could not be identified or polkit could not be asked, so nothing was signed.
pub const ERROR_AUTHORIZATION_UNAVAILABLE: &str =
    "com.rfirma.Custodio1.Error.AuthorizationUnavailable";
/// The `.p12` could not be opened: wrong password, corrupt file, or a file that holds no private
/// key, more than one, or a key without a certificate.
pub const ERROR_WRONG_PASSWORD_OR_BAD_P12: &str =
    "com.rfirma.Custodio1.Error.WrongPasswordOrBadP12";
/// The key is neither RSA 2048 nor ECDSA P-256.
pub const ERROR_UNSUPPORTED_KEY_TYPE: &str = "com.rfirma.Custodio1.Error.UnsupportedKeyType";
/// No certificate in the `.p12` carries the public key of the private key.
pub const ERROR_CERTIFICATE_MISMATCH: &str = "com.rfirma.Custodio1.Error.CertificateMismatch";
/// The audit entry could not be recorded, so the call was refused.
pub const ERROR_AUDIT_UNAVAILABLE: &str = "com.rfirma.Custodio1.Error.AuditUnavailable";
/// The TPM failed or cannot be used for an import: the key was not stored, and no weaker storage was tried.
pub const ERROR_TPM_FAILED: &str = "com.rfirma.Custodio1.Error.TpmFailed";
/// The credential service is unavailable or refused an import: the key was not stored.
pub const ERROR_CREDENTIALS_UNAVAILABLE: &str = "com.rfirma.Custodio1.Error.CredentialsUnavailable";
/// The key store, a stored key or the signing operation failed.
pub const ERROR_INTERNAL: &str = "com.rfirma.Custodio1.Error.Internal";

#[cfg(test)]
mod tests;
