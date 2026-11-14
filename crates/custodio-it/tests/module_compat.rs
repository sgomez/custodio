//! The calls this release's module makes are pinned (F178): destination, path, interface, member, the signature of
//! the arguments and the signature of the reply it accepts. A stale copy of the module keeps working only while these
//! stay; a future incompatible change must give an old copy no slots, never a wrong signature (`docs/api.md`,
//! "Compatibility rule").
//!
//! Arrangement: the module runs as a child (this binary re-executed, `unshare -Ur` so the test directory is root-owned
//! for the module's check) against a recording double on the snap socket: a peer-to-peer server that notes the first
//! message and answers with a body the test chooses; on the bus the same double owns the service's name on a private
//! `dbus-daemon`. `a_current_service_answers_the_pinned_calls` runs the real service on both transports (the snap
//! socket service of `snap_rig`, and the `Custodio` object on a private bus) and compares what it introspects and
//! answers with the same pin, so the pin and the service cannot drift apart.

use std::error::Error;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

use custodio_client::{BUS_NAME, OBJECT_PATH};
use custodio_pkcs11::backend::{Backend, BackendError, DbusBackend, SignParams};
use zbus::connection::{AuthMechanism, Builder};
use zbus::{Guid, MessageStream, block_on};

#[path = "module_compat/live.rs"]
mod live;
#[allow(
    dead_code,
    reason = "the rig is shared with snap_transport.rs, which uses other parts"
)]
mod snap_rig;

type TestResult = Result<(), Box<dyn Error>>;

const MODE_VAR: &str = "MODULE_COMPAT_CHILD";

/// One call of the module: the destination (`None` on the socket, which has no bus), path, interface, member, the
/// signature of the arguments and the signature of the reply the module accepts.
type Pin = (
    Option<&'static str>,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

/// Written once from the module's behaviour; changing it is a deliberate edit.
const PINNED: [Pin; 2] = [
    (
        None,
        "/com/rfirma/Custodio1",
        "com.rfirma.Custodio1",
        "ListKeys",
        "",
        "a(sssay)",
    ),
    (
        None,
        "/com/rfirma/Custodio1",
        "com.rfirma.Custodio1",
        "Sign",
        "suuuay",
        "ay",
    ),
];

/// The error names the module maps: (name, result).
const ERRORS: [(&str, &str); 4] = [
    ("com.rfirma.Custodio1.Error.PolkitDenied", "Denied"),
    ("com.rfirma.Custodio1.Error.InvalidArgs", "Invalid"),
    ("com.rfirma.Custodio1.Error.NoSuchKey", "Unavailable"),
    // A name this release does not know.
    ("com.rfirma.Custodio1.Error.FromTheFuture", "Unavailable"),
];

#[derive(Clone)]
enum Answer {
    Keys(Vec<(String, String, String, Vec<u8>)>),
    Bytes(Vec<u8>),
    Text(String),
    Error(&'static str),
}

/// Serves one connection on the socket, notes the first message, answers it, and returns what it saw.
fn double(listener: UnixListener, answer: Answer) -> mpsc::Receiver<Pin2> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let _ = block_on(async {
            let conn = Builder::unix_stream(stream)
                .server(Guid::generate())
                .p2p()
                .auth_mechanism(AuthMechanism::Anonymous)
                .build()
                .await?;
            record_and_answer(conn, answer, tx).await?;
            Ok::<(), Box<dyn Error>>(())
        });
    });
    rx
}

/// The same double on a private bus, owning the service's name; returns once the name is owned.
fn bus_double(address: &str, answer: Answer) -> Result<mpsc::Receiver<Pin2>, Box<dyn Error>> {
    let (tx, rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let address = address.to_owned();
    thread::spawn(move || {
        let _ = block_on(async {
            let conn = Builder::address(address.as_str())
                .name(BUS_NAME)
                .build()
                .await?;
            let _ = ready_tx.send(());
            record_and_answer(conn, answer, tx).await?;
            Ok::<(), Box<dyn Error>>(())
        });
    });
    ready_rx.recv_timeout(std::time::Duration::from_secs(20))?;
    Ok(rx)
}

async fn record_and_answer(
    conn: zbus::Connection,
    answer: Answer,
    tx: mpsc::Sender<Pin2>,
) -> Result<(), Box<dyn Error>> {
    let mut messages = MessageStream::from(&conn);
    let msg = futures_next(&mut messages).await.ok_or("no message")??;
    let header = msg.header();
    let seen = (
        header.destination().map(ToString::to_string),
        header.path().map(ToString::to_string).unwrap_or_default(),
        header
            .interface()
            .map(ToString::to_string)
            .unwrap_or_default(),
        header.member().map(ToString::to_string).unwrap_or_default(),
        {
            // zbus shows the arguments of a call as one struct; on the wire they are the bare list.
            let sig = msg.body().signature().to_string();
            sig.strip_prefix('(')
                .and_then(|s| s.strip_suffix(')'))
                .map_or(sig.clone(), str::to_owned)
        },
    );
    let _ = tx.send(seen);
    match answer {
        Answer::Keys(k) => drop(conn.reply(&header, &k).await?),
        Answer::Bytes(b) => drop(conn.reply(&header, &b).await?),
        Answer::Text(t) => drop(conn.reply(&header, &t).await?),
        Answer::Error(name) => {
            let error = zbus::Message::error(&header, name).build(&"x")?;
            conn.send(&error).await?;
        }
    }
    // Keep the connection until the module hangs up.
    let _ = futures_next(&mut messages).await;
    Ok(())
}

type Pin2 = (Option<String>, String, String, String, String);

async fn futures_next(s: &mut MessageStream) -> Option<zbus::Result<zbus::Message>> {
    use zbus::export::futures_core::Stream;
    std::future::poll_fn(|cx| std::pin::Pin::new(&mut *s).poll_next(cx)).await
}

#[test]
fn module_child() {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return;
    };
    let params = SignParams {
        mechanism: 0x1041,
        hash: 0,
        salt_len: 0,
    };
    match mode.as_str() {
        "list" => println!(
            "RESULT {:?}",
            DbusBackend.list_certificates().map(|k| k.len())
        ),
        "sign" => println!(
            "RESULT {:?}",
            DbusBackend.sign("ec", params, &[7; 32]).map(|s| s.len())
        ),
        _ => println!("RESULT unknown"),
    }
}

/// Runs the module child for `mode` against `answer`; returns the call the double saw and the module's result.
fn run(mode: &str, answer: Answer) -> Result<(Pin2, String), Box<dyn Error>> {
    let base = tempfile::tempdir()?;
    let dir = base.path().join("snap.firefox");
    std::fs::create_dir(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let rx = double(UnixListener::bind(dir.join("custodio.sock"))?, answer);
    let out = Command::new("unshare")
        .arg("-Ur")
        .arg(std::env::current_exe()?)
        .args(["--exact", "module_child", "--nocapture", "--test-threads=1"])
        .env(MODE_VAR, mode)
        .env("SNAP_INSTANCE_NAME", "firefox")
        .env("CUSTODIO_TEST_SOCKET_BASE_DIR", base.path())
        .output()?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seen = rx.recv()?;
    let result = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.split_once("RESULT ").map(|(_, r)| r.to_owned()))
        .ok_or("no result line")?;
    Ok((seen, result))
}

struct Daemon(std::process::Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Like `run`, on a private bus: the module child has no `SNAP_INSTANCE_NAME`, so it uses the bus.
fn run_on_bus(mode: &str, answer: Answer) -> Result<(Pin2, String), Box<dyn Error>> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let mut daemon = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut address = String::new();
    BufReader::new(daemon.stdout.take().ok_or("no stdout")?).read_line(&mut address)?;
    let _daemon = Daemon(daemon);
    let address = address.trim().to_owned();
    let rx = bus_double(&address, answer)?;
    let out = Command::new(std::env::current_exe()?)
        .args(["--exact", "module_child", "--nocapture", "--test-threads=1"])
        .env(MODE_VAR, mode)
        .env_remove("SNAP_INSTANCE_NAME")
        .env("DBUS_SYSTEM_BUS_ADDRESS", &address)
        .output()?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seen = rx.recv()?;
    let result = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.split_once("RESULT ").map(|(_, r)| r.to_owned()))
        .ok_or("no result line")?;
    Ok((seen, result))
}

fn good(member: &str) -> Answer {
    if member == "ListKeys" {
        Answer::Keys(vec![("ec".into(), "ec".into(), "host".into(), vec![1])])
    } else {
        Answer::Bytes(vec![1, 2, 3])
    }
}

#[test]
fn the_modules_calls_are_pinned() -> TestResult {
    for (pin, mode) in PINNED.iter().zip(["list", "sign"]) {
        let (seen, result) = run(mode, good(pin.3))?;
        assert_eq!(
            seen,
            (
                pin.0.map(str::to_owned),
                pin.1.into(),
                pin.2.into(),
                pin.3.into(),
                pin.4.into()
            ),
            "{mode}"
        );
        assert!(
            result.starts_with("Ok("),
            "{mode}: the pinned reply signature {} is accepted: {result}",
            pin.5
        );
    }
    // The constants the pin stands for are the client crate's.
    assert_eq!((PINNED[0].1, PINNED[0].2), (OBJECT_PATH, BUS_NAME));
    Ok(())
}

/// On the bus the call is the same, with the service's name as destination.
#[test]
fn the_modules_calls_are_pinned_on_the_bus() -> TestResult {
    for (pin, mode) in PINNED.iter().zip(["list", "sign"]) {
        let (seen, result) = run_on_bus(mode, good(pin.3))?;
        assert_eq!(
            seen,
            (
                Some("com.rfirma.Custodio1".to_owned()),
                pin.1.into(),
                pin.2.into(),
                pin.3.into(),
                pin.4.into()
            ),
            "{mode}"
        );
        assert!(result.starts_with("Ok("), "{mode}: {result}");
    }
    assert_eq!(BUS_NAME, "com.rfirma.Custodio1");
    Ok(())
}

#[test]
fn a_changed_reply_signature_gives_no_slots_on_the_bus_too() -> TestResult {
    assert_eq!(
        run_on_bus("list", Answer::Text("x".into()))?.1,
        "Err(Unavailable)"
    );
    assert_eq!(
        run_on_bus("sign", Answer::Text("x".into()))?.1,
        "Err(Unavailable)"
    );
    Ok(())
}

/// The table of the unit tests (`backend/tests.rs` uses the same one) through the socket, for `Sign` and `ListKeys`.
#[test]
fn errors_map_the_same_on_both_transports() -> TestResult {
    for (name, want) in custodio_pkcs11::backend::error_table::error_table() {
        let name: &'static str = Box::leak(name.to_owned().into_boxed_str());
        let want = format!("Err({want:?})");
        for mode in ["list", "sign"] {
            assert_eq!(
                run(mode, Answer::Error(name))?.1,
                want,
                "socket {mode} {name}"
            );
        }
        assert_eq!(
            run_on_bus("sign", Answer::Error(name))?.1,
            want,
            "bus {name}"
        );
    }
    Ok(())
}

/// What the double records of a call a client sends to it over the socket (no module involved).
fn record_call(
    member: &str,
    send: impl FnOnce(&zbus::Connection, Option<&str>),
) -> Result<Pin2, Box<dyn Error>> {
    let base = tempfile::tempdir()?;
    let rx = double(UnixListener::bind(base.path().join("s"))?, good(member));
    let stream = std::os::unix::net::UnixStream::connect(base.path().join("s"))?;
    let client = block_on(
        Builder::unix_stream(stream)
            .p2p()
            .auth_mechanism(AuthMechanism::Anonymous)
            .build(),
    )?;
    send(&client, None);
    Ok(rx.recv()?)
}

fn as_pin(pin: &Pin) -> Pin2 {
    (
        pin.0.map(str::to_owned),
        pin.1.into(),
        pin.2.into(),
        pin.3.into(),
        pin.4.into(),
    )
}

/// The negative control of the pin: a client that sends `Sign` with a changed argument list (one `u32` fewer, then
/// the arguments in another order) leaves a record that is not the pinned one, while the right list leaves exactly it.
#[test]
fn the_pin_notices_a_different_call() -> TestResult {
    let data: &[u8] = &[7; 32];
    let right = record_call("Sign", |c, d| {
        let _ = block_on(c.call_method(
            d,
            OBJECT_PATH,
            Some(BUS_NAME),
            "Sign",
            &("ec", 0x1041u32, 0u32, 0u32, data),
        ));
    })?;
    assert_eq!(right.3, "Sign");
    assert_eq!(right.4, PINNED[1].4, "the helper sends the pinned call");
    let fewer = record_call("Sign", |c, d| {
        let _ = block_on(c.call_method(
            d,
            OBJECT_PATH,
            Some(BUS_NAME),
            "Sign",
            &("ec", 0x1041u32, 0u32, data),
        ));
    })?;
    assert_ne!(fewer.4, PINNED[1].4, "{fewer:?}");
    let swapped = record_call("Sign", |c, d| {
        let _ = block_on(c.call_method(
            d,
            OBJECT_PATH,
            Some(BUS_NAME),
            "Sign",
            &(0x1041u32, "ec", 0u32, 0u32, data),
        ));
    })?;
    assert_ne!(swapped.4, PINNED[1].4, "{swapped:?}");
    let other_member = record_call("ListKeys", |c, d| {
        let _ = block_on(c.call_method(d, OBJECT_PATH, Some(BUS_NAME), "ListKeys", &()));
    })?;
    assert_ne!(other_member, as_pin(&PINNED[1]));
    Ok(())
}

#[test]
fn a_changed_reply_signature_gives_no_slots_and_no_signature() -> TestResult {
    let (_, listed) = run("list", Answer::Text("not keys".into()))?;
    assert_eq!(listed, "Err(Unavailable)");
    let (_, signed) = run("sign", Answer::Text("not bytes".into()))?;
    assert_eq!(signed, "Err(Unavailable)");
    let (_, signed) = run("sign", Answer::Keys(vec![]))?;
    assert_eq!(signed, "Err(Unavailable)");
    Ok(())
}

#[test]
fn the_error_names_the_module_maps_are_pinned() -> TestResult {
    for (name, want) in ERRORS {
        let (_, result) = run("sign", Answer::Error(name))?;
        assert_eq!(result, format!("Err({want})"), "{name}");
    }
    Ok(())
}

#[test]
fn error_names_are_those_of_the_client_crate() {
    // Every pinned name that is not meant to be unknown is a name of the client crate; the unknown one is not.
    for (name, _) in ERRORS {
        let unknown = name.ends_with("FromTheFuture");
        assert_eq!(
            custodio_client::ERROR_NAMES.contains(&name),
            !unknown,
            "{name}"
        );
    }
}

const _: Option<BackendError> = None;
