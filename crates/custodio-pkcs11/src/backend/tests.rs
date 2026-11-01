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

/// What the fake service lists: `(id, key type, certificate)`.
fn listed() -> Vec<(String, String, Vec<u8>)> {
    vec![
        ("a".into(), "rsa2048".into(), vec![1, 2, 3]),
        ("b".into(), "ecdsa-p256".into(), vec![4, 5]),
    ]
}

struct FakeService;

#[zbus::interface(name = "com.rfirma.Custodio1")]
impl FakeService {
    // The `interface` macro needs a method with `&self`.
    #[allow(clippy::unused_self)]
    fn list_keys(&self) -> Vec<(String, String, Vec<u8>)> {
        listed()
    }
}

const CHILD_VAR: &str = "CUSTODIO_TEST_BACKEND_CHILD";

/// The child half of `dbus_backend_lists_the_certificates_of_list_keys`: the backend reads the bus
/// address from `DBUS_SYSTEM_BUS_ADDRESS`, which cannot be set safely in a running test process.
#[test]
fn backend_child() -> TestResult {
    if std::env::var_os(CHILD_VAR).is_none() {
        return Ok(());
    }
    let got = DbusBackend
        .list_certificates()
        .map_err(|e| format!("{e:?}"))?;
    let want: Vec<_> = listed().into_iter().map(|(id, _, c)| (id, c)).collect();
    assert_eq!(got, want);
    println!("backend-child-checked");
    Ok(())
}

#[test]
fn dbus_backend_lists_the_certificates_of_list_keys() -> TestResult {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    struct Daemon(std::process::Child);
    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut address = String::new();
    BufReader::new(child.stdout.take().ok_or("no stdout")?).read_line(&mut address)?;
    let _daemon = Daemon(child);
    let address = address.trim().to_owned();
    let service = block_on(
        zbus::connection::Builder::address(address.as_str())
            .serve_at(OBJECT_PATH, FakeService)
            .name(BUS_NAME)
            .build(),
    )?;
    let out = Command::new(std::env::current_exe()?)
        .args(["--exact", "backend::tests::backend_child", "--nocapture"])
        .env(CHILD_VAR, "1")
        .env("DBUS_SYSTEM_BUS_ADDRESS", &address)
        .output()?;
    drop(service);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The child really ran the check.
    assert!(stdout.contains("backend-child-checked"), "{stdout}");
    Ok(())
}
