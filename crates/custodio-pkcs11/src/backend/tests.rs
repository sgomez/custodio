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
/// The service failures and the `BackendError` each ends as, for `ListKeys` and for `Sign` alike
/// (both go through `map_error`): the ten names of the client crate, names this version does not
/// know, the generic bus names.
fn error_table() -> Vec<(&'static str, BackendError)> {
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

/// Each service failure and the `BackendError` it has always ended as: the module turns `Denied`
/// into `CKR_FUNCTION_FAILED`, `Invalid` into `CKR_DATA_INVALID` and `Unavailable` into
/// `CKR_DEVICE_ERROR` (pinned by `composed_failure_ends_the_operation`).
#[test]
fn every_service_name_maps_to_the_error_it_always_did() -> TestResult {
    // All ten documented names are in the table.
    assert_eq!(
        error_table()
            .iter()
            .filter(|(n, _)| n.starts_with("com.rfirma.Custodio1.Error.") && !n.contains("Future"))
            .count(),
        10
    );
    for (name, want) in error_table() {
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

/// With `fail`, `ListKeys` and `Sign` answer with the next name of `error_table()` (each method
/// has its own position), so one child can walk the table.
#[derive(Default)]
struct FakeService {
    fail: bool,
    lists: std::sync::atomic::AtomicUsize,
    signs: std::sync::atomic::AtomicUsize,
}

/// An error reply with a given name.
struct Named(OwnedErrorName);

impl zbus::DBusError for Named {
    fn create_reply(&self, header: &zbus::message::Header<'_>) -> zbus::Result<zbus::Message> {
        zbus::Message::error(header, self.0.clone()).build(&"text")
    }

    fn name(&self) -> zbus::names::ErrorName<'_> {
        self.0.inner().clone()
    }

    fn description(&self) -> Option<&str> {
        Some("text")
    }
}

impl FakeService {
    fn next_error(counter: &std::sync::atomic::AtomicUsize) -> Named {
        let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let table = error_table();
        let name = table[n % table.len()].0;
        Named(OwnedErrorName::try_from(name).unwrap_or_else(|_| {
            OwnedErrorName::from(zbus::names::ErrorName::from_static_str_unchecked(
                "org.freedesktop.DBus.Error.Failed",
            ))
        }))
    }
}

#[zbus::interface(name = "com.rfirma.Custodio1")]
impl FakeService {
    fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>, Named> {
        if self.fail {
            return Err(Self::next_error(&self.lists));
        }
        Ok(listed())
    }

    // The `interface` macro needs owned argument types to deserialize the D-Bus message.
    #[allow(clippy::needless_pass_by_value)]
    fn sign(
        &self,
        id: String,
        mechanism: u32,
        hash: u32,
        salt_len: u32,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Named> {
        let _ = (id, mechanism, hash, salt_len, data);
        if self.fail {
            return Err(Self::next_error(&self.signs));
        }
        Ok(vec![9])
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

/// The child half of `both_calls_map_every_name_through_the_real_backend`: the same table
/// position for `ListKeys` and for `Sign`, asserting what the `Backend` caller gets.
#[test]
fn backend_errors_child() {
    if std::env::var_os(CHILD_VAR).is_none() {
        return;
    }
    let params = SignParams {
        mechanism: 1,
        hash: 0,
        salt_len: 0,
    };
    for (name, want) in error_table() {
        assert_eq!(
            DbusBackend.list_certificates(),
            Err(want),
            "ListKeys {name}"
        );
        assert_eq!(
            DbusBackend.sign("a", params, b"x"),
            Err(want),
            "Sign {name}"
        );
    }
    println!("backend-errors-checked");
}

struct Daemon(std::process::Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Serves `service` on a private bus and runs the test `child` (this binary) against it; returns
/// the child's stdout.
fn run_against(service: FakeService, child: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let mut daemon = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut address = String::new();
    BufReader::new(daemon.stdout.take().ok_or("no stdout")?).read_line(&mut address)?;
    let _daemon = Daemon(daemon);
    let address = address.trim().to_owned();
    let served = block_on(
        zbus::connection::Builder::address(address.as_str())
            .serve_at(OBJECT_PATH, service)
            .name(BUS_NAME)
            .build(),
    )?;
    let out = Command::new(std::env::current_exe()?)
        .args(["--exact", child, "--nocapture"])
        .env(CHILD_VAR, "1")
        .env("DBUS_SYSTEM_BUS_ADDRESS", &address)
        .output()?;
    drop(served);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(stdout)
}

#[test]
fn dbus_backend_lists_the_certificates_of_list_keys() -> TestResult {
    let stdout = run_against(FakeService::default(), "backend::tests::backend_child")?;
    // The child really ran the check.
    assert!(stdout.contains("backend-child-checked"), "{stdout}");
    Ok(())
}

/// A service answering every name of the table from `ListKeys` and from `Sign`: the real `Backend`
/// gives the same `BackendError` for both calls, the one `error_table` names.
#[test]
fn both_calls_map_every_name_through_the_real_backend() -> TestResult {
    let service = FakeService {
        fail: true,
        ..FakeService::default()
    };
    let stdout = run_against(service, "backend::tests::backend_errors_child")?;
    assert!(stdout.contains("backend-errors-checked"), "{stdout}");
    Ok(())
}
