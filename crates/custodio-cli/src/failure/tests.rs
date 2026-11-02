use super::*;

const NAMES: [(&str, &str); 10] = [
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
];

fn all_failures() -> Vec<ServiceFailure> {
    let mut all: Vec<_> = NAMES
        .iter()
        .map(|(n, _)| ServiceFailure::from_name(n))
        .collect();
    all.push(ServiceFailure::from_name(
        "org.freedesktop.DBus.Error.ServiceUnknown",
    ));
    all.push(ServiceFailure::from_name(
        "org.freedesktop.DBus.Error.AccessDenied",
    ));
    all.push(ServiceFailure::from_name(
        "com.rfirma.Custodio1.Error.FromTheFuture",
    ));
    all.push(ServiceFailure::from_name(""));
    all
}

#[test]
fn every_documented_name_has_its_own_fixed_message() {
    for (name, want) in NAMES {
        let failure = ServiceFailure::from_name(name);
        assert!(!matches!(failure, ServiceFailure::Unknown(_)), "{name}");
        assert_eq!(failure.message(), want, "{name}");
        assert_eq!(failure.to_string(), want, "{name}");
    }
}

#[test]
fn undocumented_names_are_shown_as_unknown_with_the_name() {
    assert_eq!(
        ServiceFailure::from_name("com.rfirma.Custodio1.Error.FromTheFuture").message(),
        "the service answered with an unknown error (com.rfirma.Custodio1.Error.FromTheFuture)"
    );
    assert!(matches!(
        ServiceFailure::from_name(""),
        ServiceFailure::Unknown(_)
    ));
}

#[test]
fn bus_daemon_names_are_transport_or_absent_never_unknown() {
    for name in [
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "org.freedesktop.DBus.Error.NameHasNoOwner",
    ] {
        assert_eq!(
            ServiceFailure::from_name(name),
            ServiceFailure::ServiceAbsent
        );
    }
    for name in [
        "org.freedesktop.DBus.Error.AccessDenied",
        "org.freedesktop.DBus.Error.NoReply",
        "org.freedesktop.DBus.Error.Whatever",
    ] {
        assert_eq!(
            ServiceFailure::from_name(name),
            ServiceFailure::Transport,
            "{name}"
        );
    }
}

#[test]
fn no_two_failures_share_a_message() {
    let all = [
        ServiceFailure::InvalidArgs,
        ServiceFailure::NoSuchKey,
        ServiceFailure::KeyIdTaken,
        ServiceFailure::PolkitDenied,
        ServiceFailure::AuthorizationUnavailable,
        ServiceFailure::WrongPasswordOrBadP12,
        ServiceFailure::UnsupportedKeyType,
        ServiceFailure::CertificateMismatch,
        ServiceFailure::AuditUnavailable,
        ServiceFailure::Internal,
        ServiceFailure::ServiceAbsent,
        ServiceFailure::Transport,
        ServiceFailure::Unknown("x.y".into()),
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a.message(), b.message(), "{a:?} / {b:?}");
        }
    }
}

#[test]
fn messages_hold_nothing_but_their_fixed_text() {
    for f in all_failures() {
        let text = format!("{f} {f:?}");
        assert!(!text.contains("SERVICE FREE TEXT"), "{text}");
    }
}
