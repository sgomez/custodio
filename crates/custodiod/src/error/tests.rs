use std::collections::HashSet;

use zbus::DBusError;

use super::*;

#[test]
fn every_variant_has_its_name() {
    let want = [
        (ServiceError::InvalidArgs, "InvalidArgs"),
        (ServiceError::NoSuchKey, "NoSuchKey"),
        (ServiceError::KeyIdTaken, "KeyIdTaken"),
        (ServiceError::PolkitDenied, "PolkitDenied"),
        (
            ServiceError::AuthorizationUnavailable,
            "AuthorizationUnavailable",
        ),
        (ServiceError::WrongPasswordOrBadP12, "WrongPasswordOrBadP12"),
        (ServiceError::UnsupportedKeyType, "UnsupportedKeyType"),
        (ServiceError::CertificateMismatch, "CertificateMismatch"),
        (ServiceError::AuditUnavailable, "AuditUnavailable"),
        (ServiceError::Internal, "Internal"),
    ];
    assert_eq!(want.len(), ServiceError::ALL.len());
    for (variant, last) in want {
        assert_eq!(
            variant.error_name(),
            format!("com.rfirma.Custodio1.Error.{last}")
        );
        assert!(ServiceError::ALL.contains(&variant));
    }
}

#[test]
fn names_are_distinct_valid_and_in_the_project_namespace() {
    let names: HashSet<&str> = ServiceError::ALL.iter().map(|e| e.error_name()).collect();
    assert_eq!(names.len(), ServiceError::ALL.len());
    let messages: HashSet<&str> = ServiceError::ALL.iter().map(|e| e.message()).collect();
    assert_eq!(messages.len(), ServiceError::ALL.len());
    for e in ServiceError::ALL {
        assert!(e.error_name().starts_with("com.rfirma.Custodio1."), "{e:?}");
        assert!(
            !e.error_name().starts_with("org.freedesktop.DBus.Error."),
            "{e:?}"
        );
        assert!(ErrorName::try_from(e.error_name()).is_ok(), "{e:?}");
        assert_eq!(DBusError::name(&e).as_str(), e.error_name());
        assert_eq!(DBusError::description(&e), Some(e.message()));
        assert_eq!(e.to_string(), e.message());
    }
}

#[test]
fn messages_are_fixed_and_leak_nothing() {
    for e in ServiceError::ALL {
        let m = e.message();
        assert_ne!(m, "");
        assert!(!m.contains('/'), "{m}");
        assert!(!m.contains("sentinel"), "{m}");
    }
}

#[test]
fn request_errors_are_invalid_args() {
    for e in [
        RequestError::BadId,
        RequestError::BadMechanism,
        RequestError::BadHash,
        RequestError::BadSaltLength,
        RequestError::DataTooLarge,
        RequestError::PasswordTooLarge,
    ] {
        assert_eq!(ServiceError::from(&e), ServiceError::InvalidArgs, "{e:?}");
    }
}

fn io() -> std::io::Error {
    std::io::Error::other("sentinel")
}

#[test]
fn store_errors_map() {
    use std::path::PathBuf;
    let p = || PathBuf::from("/sentinel");
    let table = [
        (StoreError::InvalidId, ServiceError::InvalidArgs),
        (StoreError::AlreadyExists, ServiceError::KeyIdTaken),
        (StoreError::NotFound, ServiceError::NoSuchKey),
        (StoreError::BadPermissions(p()), ServiceError::Internal),
        (StoreError::BadFileType(p()), ServiceError::Internal),
        (StoreError::BadOwner(p()), ServiceError::Internal),
        (StoreError::TooLarge, ServiceError::Internal),
        (StoreError::SyncFailed(io()), ServiceError::Internal),
        (StoreError::Io(io()), ServiceError::Internal),
    ];
    for (e, want) in table {
        assert_eq!(ServiceError::from(&e), want, "{e:?}");
    }
}

#[test]
fn import_errors_map() {
    let table = [
        (ImportError::TooLarge, ServiceError::InvalidArgs),
        (
            ImportError::Parse("sentinel".into()),
            ServiceError::WrongPasswordOrBadP12,
        ),
        (
            ImportError::NoPrivateKey,
            ServiceError::WrongPasswordOrBadP12,
        ),
        (
            ImportError::MultipleKeys,
            ServiceError::WrongPasswordOrBadP12,
        ),
        (
            ImportError::NoCertificate,
            ServiceError::WrongPasswordOrBadP12,
        ),
        (
            ImportError::CertificateMismatch,
            ServiceError::CertificateMismatch,
        ),
        (
            ImportError::UnsupportedKey("sentinel".into()),
            ServiceError::UnsupportedKeyType,
        ),
        (
            ImportError::Store(StoreError::AlreadyExists),
            ServiceError::KeyIdTaken,
        ),
        (
            ImportError::Store(StoreError::Io(io())),
            ServiceError::Internal,
        ),
    ];
    for (e, want) in table {
        assert_eq!(ServiceError::from(&e), want, "{e:?}");
    }
}

#[test]
fn sign_and_auth_errors_map() {
    let table = [
        (SignError::BadData, ServiceError::InvalidArgs),
        (SignError::MechanismMismatch, ServiceError::InvalidArgs),
        (SignError::BadKey, ServiceError::Internal),
        (SignError::Failed, ServiceError::Internal),
    ];
    for (e, want) in table {
        assert_eq!(ServiceError::from(&e), want, "{e:?}");
    }
    assert_eq!(
        ServiceError::from(&AuthError::Denied),
        ServiceError::PolkitDenied
    );
    assert_eq!(
        ServiceError::from(&AuthError::BadSender),
        ServiceError::AuthorizationUnavailable
    );
    assert_eq!(
        ServiceError::from(&AuthError::Unavailable("sentinel".into())),
        ServiceError::AuthorizationUnavailable
    );
}
