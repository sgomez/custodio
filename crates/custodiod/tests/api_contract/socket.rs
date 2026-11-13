//! The socket section of `docs/api.md` against a live socket peer (F177).

use std::collections::BTreeSet;
use std::error::Error;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use custodiod::snap_socket::limits::{
    HANDSHAKE_TIMEOUT, IDLE_TIMEOUT, MAX_CONNECTIONS, MAX_MESSAGE_LEN, REFUSAL_LINES_PER_WINDOW,
    REFUSAL_WINDOW,
};
use custodiod::snap_socket::peer::{Peer, Source};
use custodiod::snap_socket::{Outcome, Service, serve};
use custodiod::store::KeyStore;
use zbus::block_on;
use zbus::connection::{AuthMechanism, Builder};

use super::{INTERFACE, OBJECT_PATH, edited, manifest};

/// The methods the document's socket section names, and its `name: value` bounds.
fn doc_socket(text: &str) -> (BTreeSet<String>, Vec<(String, String)>) {
    let mut methods = BTreeSet::new();
    let mut bounds = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("- socket ") else {
            continue;
        };
        let ticks: Vec<&str> = line.split('`').skip(1).step_by(2).collect();
        if let Some(name) = rest.strip_prefix("method ") {
            methods.extend(name.split('`').nth(1).map(str::to_owned));
        } else if let Some((name, _)) = rest.split_once(':') {
            bounds.extend(ticks.first().map(|v| (name.to_owned(), (*v).to_owned())));
        }
    }
    (methods, bounds)
}

fn live_methods() -> Result<BTreeSet<String>, Box<dyn Error>> {
    let tmp = tempfile::tempdir()?;
    let store = Arc::new(KeyStore::open(tmp.path().join("keys"))?);
    let path = tmp.path().join("s.sock");
    let service =
        Service::new(store, Arc::new(|_| {})).with_source(Source::Injected(Arc::new(|_| Peer {
            uid: Some(4001),
            pid: Some(1),
            pidfd: std::fs::File::open("/dev/null").ok().map(Into::into),
            label: Some(b"snap.firefox.firefox (enforce)".to_vec()),
        })));
    let outcome = serve(
        "snap-firefox",
        UnixListener::bind(&path)?,
        std::path::Path::new("/usr"),
        &mut Vec::new(),
        &service,
    );
    assert!(matches!(outcome, Outcome::Serving));
    let stream = UnixStream::connect(&path)?;
    let xml: String = block_on(async {
        let connection = Builder::unix_stream(stream)
            .p2p()
            .auth_mechanism(AuthMechanism::Anonymous)
            .build()
            .await?;
        let reply = connection
            .call_method(
                None::<&str>,
                OBJECT_PATH,
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await?;
        Ok::<String, Box<dyn Error>>(reply.body().deserialize()?)
    })?;
    let (_, after) = xml
        .split_once(&format!("<interface name=\"{INTERFACE}\">"))
        .ok_or("no Custodio interface")?;
    let (section, _) = after.split_once("</interface>").ok_or("unterminated")?;
    Ok(section
        .lines()
        .filter_map(|l| l.trim().strip_prefix("<method name=\""))
        .filter_map(|l| l.split('"').next().map(str::to_owned))
        .collect())
}

#[test]
fn the_socket_serves_exactly_the_two_methods() -> Result<(), Box<dyn Error>> {
    let text = std::fs::read_to_string(manifest("../../docs/api.md"))?;
    let live = live_methods()?;
    assert_eq!(live, ["ListKeys", "Sign"].map(str::to_owned).into());
    let (documented, bounds) = doc_socket(&text);
    assert_eq!(documented, live);
    // Edited copies fail: a write method added, or `Sign` removed.
    let extra = edited(
        &text,
        "- socket method `Sign`",
        "- socket method `Sign`\n- socket method `DeleteKey`",
    );
    assert_ne!(doc_socket(&extra).0, live);
    let removed = edited(&text, "- socket method `Sign`", "- gone");
    assert_ne!(doc_socket(&removed).0, live);
    // Each documented value is the shipped constant.
    let want = [
        ("connections", MAX_CONNECTIONS.to_string()),
        ("message size", MAX_MESSAGE_LEN.to_string()),
        ("handshake time", HANDSHAKE_TIMEOUT.as_secs().to_string()),
        ("idle time", IDLE_TIMEOUT.as_secs().to_string()),
        ("refusal log", REFUSAL_LINES_PER_WINDOW.to_string()),
    ];
    for (name, value) in want {
        let found = bounds
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone());
        assert_eq!(found, Some(value), "documented socket {name}");
    }
    assert_eq!(REFUSAL_WINDOW.as_secs(), 60);
    assert!(text.contains(&format!("per `{}` seconds", REFUSAL_WINDOW.as_secs())));
    Ok(())
}
